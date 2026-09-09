"""Run the scorer inside a torn-down, network-isolated container (stage 3).

The host does three things and no more: it builds the image, it hands a
container the repository and a patch, and it collects what comes back. It
never applies a patch, never starts the patched app, and never fires an attack
payload. All of that happens behind the container boundary.

## Isolation

Containers are created with --network none. That is the strongest of the two
modes the pilot supports and the default here, because the scorer needs
loopback and nothing else: the patched app binds 127.0.0.1 and checks B and C
talk to it there.

The flag is only the request. What the artifact records is the measurement
harness/isolation.py takes from inside the container, and if that measurement
finds egress the run is refused. See WHY-ISOLATION in the held-out notes.

## Teardown

One container per patch, created fresh, removed with force when the run ends
however it ends. Nothing is bind mounted, so the container cannot write to the
repository even by accident, and the repository it reads is a copy that dies
with it. The seeded database, the patched file, the app process and the whole
writable layer go with it. Nothing survives into the next patch.

## Provenance

Two halves, recorded separately because they are observed by different
parties. The container reports what it measured about itself. The host reports
what only it can know: the image digest, the flags it actually passed, the
runtime version. Neither half is asked to vouch for the other.
"""

import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time

from harness import corpus

ROOT = corpus.ROOT

IMAGE = "assay-pilot-001/scorer:1"
CONTAINER_ROOT = "/assay"
CONTAINER_OUT = "/out"

# Isolation the host asks docker for. network-none is loopback only: the
# container has no interface other than lo, so there is nothing to route out
# of. internal is the weaker mode, kept because a future finding may need two
# containers to talk to each other.
INTERNAL_NETWORK = "assay-isolated"

MODE_FLAGS = {
    "network-none": ["--network", "none"],
    "internal": ["--network", INTERNAL_NETWORK],
}

# Never copied into the container. The virtualenv is the host's and the wrong
# architecture; the git directory is large and irrelevant to scoring.
COPY_EXCLUDE = {".venv", ".git", "__pycache__", ".DS_Store"}


class DockerUnavailable(Exception):
    """No usable container runtime. The caller reports INSUFFICIENT EVIDENCE.

    Stage 3 scoring has no host fallback on purpose. Running the patched app
    and the attack set outside a container would produce a result whose
    isolation we could not describe honestly, and an unrunnable check is a
    better outcome than an overstated one.
    """


def docker(*args, **kw):
    return subprocess.run(["docker"] + list(args),
                          stdout=kw.get("stdout", subprocess.PIPE),
                          stderr=kw.get("stderr", subprocess.PIPE),
                          check=False)


def require_docker():
    try:
        out = docker("version", "--format", "{{.Server.Version}}")
    except FileNotFoundError:
        raise DockerUnavailable("docker command not found on PATH")
    if out.returncode != 0:
        raise DockerUnavailable(
            "docker is installed but no daemon answered: %s"
            % out.stderr.decode(errors="replace").strip())
    return out.stdout.decode().strip()


def ensure_internal_network(name=INTERNAL_NETWORK):
    """Create the internal network if it is not there, and verify it is internal.

    Only used by the internal mode. A docker network created with --internal
    has no gateway, so a container on it can talk to other containers on the
    same network and cannot reach anything else. If a network of this name
    already exists but is NOT internal, that is refused rather than used: a
    routed network with the expected name is the exact shape that would make a
    run claim isolation it does not have.
    """
    out = docker("network", "inspect", name, "--format", "{{.Internal}}")
    if out.returncode == 0:
        if out.stdout.decode().strip() != "true":
            raise DockerUnavailable(
                "network %s exists but is not internal. Refusing to score in "
                "it: it would look isolated and route." % name)
        return name
    created = docker("network", "create", "--internal", name)
    if created.returncode != 0:
        raise DockerUnavailable("could not create internal network %s: %s"
                                % (name, created.stderr.decode(
                                    errors="replace").strip()))
    return name


def image_exists(image=IMAGE):
    return docker("image", "inspect", image).returncode == 0


def build_image(image=IMAGE, quiet=False):
    """Build the scoring image. This is the one step that needs the network.

    Worth being plain about, because it is the obvious objection: the image is
    built with egress so pip can fetch the pinned dependencies, and every
    scoring run then happens with no egress at all. Build time and run time
    are different moments with different guarantees, and the artifact only
    ever claims the run time one.
    """
    cmd = ["build", "-f", os.path.join("container", "Dockerfile"),
           "-t", image, "."]
    proc = subprocess.run(["docker"] + cmd, cwd=ROOT,
                          stdout=None if not quiet else subprocess.DEVNULL,
                          stderr=None if not quiet else subprocess.DEVNULL)
    if proc.returncode != 0:
        raise DockerUnavailable("image build failed for %s" % image)
    return image_identity(image)


def image_identity(image=IMAGE):
    """The image id actually used, recorded so a run can be tied to a build.

    Ask only for the id. An inspect format that reaches for an optional field
    fails the whole template when the field is absent, and the failure is
    silent: the command exits non zero, stdout is empty, and the provenance
    quietly records an empty image id instead of refusing. That happened, and
    it is the same class of fault as the rest of this stage, a check that
    looks like it passed because it never ran.
    """
    out = docker("image", "inspect", image, "--format", "{{.Id}}")
    if out.returncode != 0:
        raise DockerUnavailable(
            "could not inspect image %s: %s"
            % (image, out.stderr.decode(errors="replace").strip()))
    image_id = out.stdout.decode().strip()
    if not image_id:
        raise DockerUnavailable("image %s reported an empty id" % image)
    return {"image": image, "image_id": image_id}


def _repo_tar(path, root=ROOT):
    """Tar the repository for copying in. Excludes the host virtualenv.

    Held-out material is included: checks B and C cannot run without the
    attack set, the benign set and the baseline. It goes into a container with
    no egress and is destroyed with it.
    """
    with tarfile.open(path, "w") as tar:
        for name in sorted(os.listdir(root)):
            if name in COPY_EXCLUDE:
                continue
            tar.add(os.path.join(root, name), arcname="./" + name,
                    filter=lambda ti: None if os.path.basename(ti.name)
                    in COPY_EXCLUDE else ti)


def score_in_container(tool, finding_id="finding-01", patch=None,
                       patched_file=None, run_date=None, mode="network-none",
                       image=IMAGE, keep_output=None):
    """Score one patch in a fresh container. Returns (outcome, provenance, out_dir).

    Exactly one of patch (a unified diff) or patched_file (an already patched
    app file) must be given. patch is the shape stage 3 is specified around;
    patched_file exists because the committed stage 1 evidence was produced
    from one, and the parity gate has to feed the scorer the same input to
    compare like with like.

    out_dir holds everything the container wrote. The caller owns it.
    """
    if (patch is None) == (patched_file is None):
        raise ValueError("give exactly one of patch or patched_file")
    if mode not in MODE_FLAGS:
        raise ValueError("unknown isolation mode %r" % mode)

    server_version = require_docker()
    if not image_exists(image):
        build_image(image)
    if mode == "internal":
        ensure_internal_network()

    out_dir = keep_output or tempfile.mkdtemp(prefix="assay_container_out_")
    name = "assay-score-%s-%s-%d" % (finding_id, tool, int(time.time() * 1000))

    argv = ["--tool", tool, "--finding", finding_id, "--out", CONTAINER_OUT,
            "--requested-mode", mode]
    if run_date:
        argv += ["--run-date", run_date]
    if patch:
        argv += ["--patch", os.path.join(CONTAINER_ROOT,
                                         os.path.relpath(patch, ROOT))]
    else:
        argv += ["--patched-file", os.path.join(
            CONTAINER_ROOT, os.path.relpath(patched_file, ROOT))]

    created = docker("create", "--name", name, *MODE_FLAGS[mode],
                     # No bind mounts anywhere. The container gets a copy of
                     # the repository, not the repository.
                     "--workdir", CONTAINER_ROOT, image, *argv)
    if created.returncode != 0:
        raise DockerUnavailable("docker create failed: %s"
                                % created.stderr.decode(errors="replace").strip())

    try:
        # What docker actually configured, read back rather than assumed.
        inspected = json.loads(docker(
            "inspect", name, "--format", "{{json .HostConfig}}").stdout.decode())
        network_mode = inspected.get("NetworkMode")
        binds = inspected.get("Binds") or []

        tar_path = os.path.join(tempfile.mkdtemp(prefix="assay_tar_"), "repo.tar")
        _repo_tar(tar_path)
        with open(tar_path, "rb") as f:
            cp = subprocess.run(["docker", "cp", "-", "%s:%s" % (name, CONTAINER_ROOT)],
                                stdin=f, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        shutil.rmtree(os.path.dirname(tar_path), ignore_errors=True)
        if cp.returncode != 0:
            raise DockerUnavailable("docker cp into container failed: %s"
                                    % cp.stderr.decode(errors="replace").strip())

        started = time.time()
        run = docker("start", "--attach", name)
        elapsed = time.time() - started
        logs = (run.stdout.decode(errors="replace")
                + run.stderr.decode(errors="replace"))

        collect = docker("cp", "%s:%s/." % (name, CONTAINER_OUT), out_dir)
        if collect.returncode != 0:
            raise DockerUnavailable("docker cp out of container failed: %s"
                                    % collect.stderr.decode(errors="replace").strip())
    finally:
        docker("rm", "--force", name)

    outcome = _read_json(os.path.join(out_dir, "_outcome.json")) or {
        "verdict": "INSUFFICIENT EVIDENCE",
        "reason": "container produced no outcome file",
        "detail": logs[-4000:],
    }
    container_side = _read_json(os.path.join(out_dir, "_container.json")) or {}

    provenance = {
        "schema": "assay-pilot-001/provenance",
        "schema_version": 1,
        "stage": 3,
        "finding": finding_id,
        "tool": tool,
        # When this container run happened. Deliberately not the same field as
        # the date inside the evidence artifact, which records when the scan
        # being reproduced was taken. Collapsing the two would let a re-run
        # quietly restate itself as the original.
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "run_date_in_evidence": run_date,
        "execution": {
            "mode": "container",
            "runtime": "docker",
            "server_version": server_version,
            "image": image,
            "image_id": image_identity(image)["image_id"],
            "requested_isolation": mode,
            "network_mode_configured": network_mode,
            "bind_mounts": binds,
            "no_bind_mounts": not binds,
            "teardown": "container removed with docker rm --force",
            "wall_seconds": round(elapsed, 2),
        },
        "container_observed": container_side,
        "exit_code": run.returncode,
    }
    return outcome, provenance, out_dir


def _read_json(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)
