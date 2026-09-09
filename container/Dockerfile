# Assay Pilot 001 - the scoring container (protocol section 8, stage 3).
#
# Everything the scorer does to a patch happens in here: the pinned scanner
# run for check A, the patched app process that checks B and C fire at, and
# the seeded database they read. The host runs no patched code at all.
#
# The base image is pinned by digest, not by tag. A tag moves. A digest does
# not, and a hostile reader reproducing this months from now gets the same
# interpreter and the same libc we used.
FROM python@sha256:a02e9c5406c416c504d6c9a1a306ff4080c3173f1008d192f953bd20382a2d5c

# SEMGREP_ENABLE_VERSION_CHECK and SEMGREP_SEND_METRICS matter twice over.
# They keep the scan reproducible, and they stop semgrep waiting on a network
# call that can never complete inside a container with no egress. Without
# them every scan pays a DNS timeout it does not need.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    SEMGREP_SEND_METRICS=off

# The harness reads its interpreter and scanner paths out of the manifest
# defaults, which say .venv/bin/python and .venv/bin/semgrep relative to the
# repository root. Building a real virtualenv at that exact path means the
# container satisfies the existing manifest with no manifest change and no
# special case in the scoring core. The scorer cannot tell it is in a
# container, which is the point: identical code, identical artifacts.
# git is here for one job: applying the patch diff to a clean checkout in
# check A. The scorer is handed a diff, not a patched file, so something has
# to apply it, and git apply reports a refusal cleanly instead of guessing.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /assay
COPY requirements.lock.txt /tmp/requirements.lock.txt
RUN python -m venv /assay/.venv \
    && /assay/.venv/bin/pip install --no-cache-dir -r /tmp/requirements.lock.txt \
    && rm /tmp/requirements.lock.txt

# Fail the build rather than the run if the pinned scanner did not land.
RUN /assay/.venv/bin/semgrep --version

# The repository itself is not baked in. It is copied into a fresh container
# at run time and dies with that container, so no patch can leave anything
# behind for the next one.
ENTRYPOINT ["/assay/.venv/bin/python", "container/run_score.py"]
