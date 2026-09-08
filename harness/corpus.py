"""Corpus manifest loading for Assay Pilot 001.

The corpus holds up to fifteen findings (protocol section 1). Everything that
used to be a constant in manual_score.py, the app file, the port, the
endpoint, the attack success oracle, the held-out paths, now lives in a
manifest as one entry per finding. This module reads the manifest, validates
it, and hands the scorer a Finding object.

## The manifest is split in two, and the split line is check A

  corpus/manifest.json              public, tracked
      Identity, location and shape: id, status, shape, protocol rows, CWE, the
      file and line of the sink, and the plumbing check A needs to point the
      pinned scanner at the right module. Pointers to held-out material by
      path only, never contents.

  heldout/corpus/experimenter.json  git-ignored
      The known correct fix for every finding, the endpoint wiring that checks
      B and C drive, and the attack success oracle.

The rule: the public manifest carries what check A needs. The experimenter
manifest carries what checks B and C need. That line is not arbitrary. It is
the same line the README already draws for a public clone of this repository,
which can run check A and cannot run checks B and C.

The known correct fix is held out because for the harder findings, the second
order and multi-hop shapes, the correct fix IS the answer. A public tracked
file naming it puts that answer into every future training run and quietly
turns a real failure into a fake pass. Same reasoning as the attack sets.
See heldout/finding-01/WHY-ISOLATION.md.

## Missing held-out material is a verdict, not a crash

A public clone has no heldout/ directory at all. HeldOutMissing carries the
list of files that were not found so the caller can emit INSUFFICIENT
EVIDENCE with the reason recorded in the artifact, rather than a traceback.
"""

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH = os.path.join(ROOT, "corpus", "manifest.json")

SCHEMA_VERSION = 1

# Fields every entry must carry, whatever its status.
_COMMON_FIELDS = ("id", "status", "shape", "shape_key", "cwe")

# Fields a public entry must carry before the harness will score it.
_BUILT_FIELDS = ("app", "sink", "heldout", "reported_payload_file",
                 "results_dir")

# Fields the experimenter manifest must carry for a built finding.
_EXPERIMENTER_FIELDS = ("reference_fix", "endpoint", "oracle")


class ManifestError(Exception):
    """The manifest is malformed, or the finding asked for is not scorable."""


class HeldOutMissing(Exception):
    """Held-out material this finding needs is not present on disk.

    Raised, not swallowed. The caller turns this into an INSUFFICIENT EVIDENCE
    verdict with the missing paths recorded in the evidence artifact.
    """

    def __init__(self, finding_id, missing):
        self.finding_id = finding_id
        self.missing = list(missing)
        Exception.__init__(self, "%s: held-out material not found: %s" % (
            finding_id, ", ".join(self.missing)))


class Finding(object):
    """One corpus finding, resolved against the repository root.

    Properties that read the public manifest always work. Properties that read
    the experimenter manifest raise HeldOutMissing when it is not on disk.
    """

    def __init__(self, entry, defaults, root=ROOT, experimenter_path=None):
        self.root = root
        self.entry = entry
        self.defaults = defaults
        self.id = entry["id"]
        self.status = entry["status"]
        self.shape = entry["shape"]
        self.shape_key = entry["shape_key"]
        self.cwe = entry["cwe"]
        self._experimenter_path = experimenter_path
        self._experimenter = None

    # ---- the experimenter half -------------------------------------------

    @property
    def experimenter_path(self):
        return os.path.join(self.root, self._experimenter_path)

    def _load_experimenter(self):
        if self._experimenter is not None:
            return self._experimenter
        path = self.experimenter_path
        if not os.path.exists(path):
            raise HeldOutMissing(self.id, [os.path.relpath(path, self.root)])
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        entry = data.get("findings", {}).get(self.id)
        if entry is None:
            raise HeldOutMissing(self.id, [
                "%s#findings.%s" % (os.path.relpath(path, self.root), self.id)])
        for field in _EXPERIMENTER_FIELDS:
            if field not in entry:
                raise ManifestError("experimenter manifest entry %s missing %r"
                                    % (self.id, field))
        self._experimenter = entry
        return entry

    @property
    def reference_fix(self):
        """The known correct fix, written by us. Held out."""
        return self._load_experimenter()["reference_fix"]

    @property
    def endpoint(self):
        return self._load_experimenter()["endpoint"]

    @property
    def oracle(self):
        return self._load_experimenter()["oracle"]

    @property
    def reference_port(self):
        return self._load_experimenter().get("reference_port", 5101)

    @property
    def reference_app(self):
        return self.path(self.reference_fix["reference_app"])

    @property
    def baseline_provenance(self):
        return self._load_experimenter()["baseline_provenance"]

    # ---- paths -----------------------------------------------------------

    def path(self, relative):
        return os.path.join(self.root, relative)

    @property
    def app_file(self):
        """The original, unpatched app file for this finding."""
        return self.path(self.entry["app"]["file"])

    @property
    def scan_target(self):
        """What Semgrep is pointed at for check A.

        Each finding owns one module, so a scan of that module isolates this
        finding from the other fourteen flaws in the same application. Finding
        1's module is the whole app today because it is the only one built.
        """
        return self.path(self.entry["app"]["scan_target"])

    @property
    def scan_target_relative(self):
        """Scan target as written in the manifest, relative to the repo root.

        Semgrep records the target path in the SARIF exactly as it was given
        on the command line, so scanning from the repository root with the
        relative path is what makes the SARIF reproducible on any machine.
        """
        return self.entry["app"]["scan_target"]

    @property
    def support_files(self):
        return [self.path(p) for p in self.entry["app"].get("support_files", [])]

    @property
    def seed_script(self):
        return self.entry["app"].get("seed_script")

    @property
    def rule_file(self):
        return self.path(self.entry.get("scanner_rule")
                         or self.defaults["scanner_rule"])

    @property
    def rule_file_relative(self):
        return self.entry.get("scanner_rule") or self.defaults["scanner_rule"]

    @property
    def python_bin(self):
        return self.path(self.defaults["python"])

    @property
    def semgrep_bin(self):
        return self.path(self.defaults["semgrep"])

    @property
    def results_dir(self):
        return self.entry["results_dir"]

    @property
    def reported_payload_file(self):
        return self.path(self.entry["reported_payload_file"])

    @property
    def sarif_path(self):
        return self.path(os.path.join("scanner", self.id + ".sarif"))

    @property
    def capture_record_path(self):
        return self.path(os.path.join("scanner", self.id + ".capture.json"))

    # ---- network shape ---------------------------------------------------

    @property
    def host(self):
        return self.entry["app"]["host"]

    @property
    def port(self):
        return self.entry["app"]["port"]

    def base_url(self, port=None):
        return "http://%s:%d" % (self.host, port or self.port)

    def health_url(self, port=None):
        return self.base_url(port) + self.entry["app"]["health_path"]

    def endpoint_url(self, port=None):
        return self.base_url(port) + self.endpoint["path"]

    @property
    def endpoint_param(self):
        return self.endpoint["param"]

    # ---- held-out material ----------------------------------------------

    def heldout_path(self, key):
        return self.path(self.entry["heldout"][key])

    def missing_heldout(self, keys=("attacks", "benign", "baseline")):
        """Return the held-out files this finding needs but does not have.

        The experimenter manifest is always required, because without it there
        is no endpoint to fire at and no oracle to judge the response.
        """
        missing = []
        if not os.path.exists(self.experimenter_path):
            missing.append(os.path.relpath(self.experimenter_path, self.root))
        for key in keys:
            p = self.heldout_path(key)
            if not os.path.exists(p):
                missing.append(os.path.relpath(p, self.root))
        return missing

    def require_heldout(self, keys=("attacks", "benign", "baseline")):
        missing = self.missing_heldout(keys)
        if missing:
            raise HeldOutMissing(self.id, missing)

    def load_attacks(self):
        """Every attack in the held-out set, reported payload included."""
        with open(self.heldout_path("attacks"), encoding="utf-8") as f:
            return json.load(f)["attacks"]

    def held_out_attacks(self):
        """Check B fires these: every attack except the reported payload.

        The reported payload is excluded because the fixer was shown it. It is
        the one hint a real developer gets from a bug report, so blocking it
        proves nothing.
        """
        return [a for a in self.load_attacks() if not a.get("reported")]

    def load_benign(self):
        with open(self.heldout_path("benign"), encoding="utf-8") as f:
            return json.load(f)["benign"]

    def load_baseline(self):
        with open(self.heldout_path("baseline"), encoding="utf-8") as f:
            return json.load(f)["baseline"]

    def heldout_results_dir(self, output_root=None):
        rel = os.path.join(self.entry["heldout"]["dir"], "results")
        return os.path.join(output_root or self.root, rel)


def load_manifest(path=MANIFEST_PATH):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ManifestError("manifest schema_version is %r, this harness "
                            "understands %r" % (data.get("schema_version"),
                                                SCHEMA_VERSION))
    if "experimenter_manifest" not in data:
        raise ManifestError("manifest does not name its experimenter half")
    seen = set()
    for entry in data["findings"]:
        for field in _COMMON_FIELDS:
            if field not in entry:
                raise ManifestError("manifest entry missing %r: %r"
                                    % (field, entry.get("id", entry)))
        if entry["id"] in seen:
            raise ManifestError("duplicate finding id %r" % entry["id"])
        seen.add(entry["id"])
        if entry["status"] not in ("built", "planned"):
            raise ManifestError("finding %s has unknown status %r"
                                % (entry["id"], entry["status"]))
        if entry["status"] == "built":
            for field in _BUILT_FIELDS:
                if field not in entry:
                    raise ManifestError("built finding %s missing %r"
                                        % (entry["id"], field))
        # The answer key must not creep back into the public manifest.
        for field in _EXPERIMENTER_FIELDS:
            if field in entry:
                raise ManifestError(
                    "finding %s carries %r in the public manifest. That field "
                    "is experimenter material and belongs in %s"
                    % (entry["id"], field, data["experimenter_manifest"]))
    return data


def list_findings(path=MANIFEST_PATH, root=ROOT):
    data = load_manifest(path)
    return [Finding(e, data["defaults"], root, data["experimenter_manifest"])
            for e in data["findings"]]


def get_finding(finding_id, path=MANIFEST_PATH, root=ROOT):
    """Look up one finding. Refuses to return a placeholder entry."""
    data = load_manifest(path)
    for entry in data["findings"]:
        if entry["id"] == finding_id:
            if entry["status"] != "built":
                raise ManifestError(
                    "finding %s is a structural placeholder (status %r) and "
                    "cannot be scored yet" % (finding_id, entry["status"]))
            return Finding(entry, data["defaults"], root,
                           data["experimenter_manifest"])
    known = ", ".join(e["id"] for e in data["findings"])
    raise ManifestError("no finding %r in the manifest. known: %s"
                        % (finding_id, known))
