"""Apply a patch diff to a clean checkout (stage 3, check A).

The scorer is given a diff and a finding id, not a pre-patched file. That
matters for more than tidiness: a diff is what a tool actually emits, and
applying it is the first place a patch can fail. Protocol section 3 already
says a patch that will not apply is INSUFFICIENT EVIDENCE rather than a fail,
because we learned nothing about the vulnerability.

Clean checkout means exactly that. Every scored patch starts from a fresh copy
of the unpatched corpus file, made here, used once, and deleted with the
container. No patch ever sees what the previous patch did.

PatchFailed carries git's own stderr. When a diff refuses to apply we want the
reason in the artifact, not a bare boolean.
"""

import os
import shutil
import subprocess
import tempfile


class PatchFailed(Exception):
    """The diff did not apply to a clean checkout of the corpus file.

    Callers turn this into INSUFFICIENT EVIDENCE with detail recorded, never
    into NOT VERIFIED. A patch that cannot be applied has not been tested.
    """

    def __init__(self, diff_path, detail):
        self.diff_path = diff_path
        self.detail = detail
        Exception.__init__(self, "%s did not apply: %s" % (diff_path, detail))


def apply_to_clean_checkout(finding, diff_path, workdir=None):
    """Apply diff_path to a clean copy of the finding's app file.

    Returns the path to the patched file. The caller owns the returned
    directory tree and is responsible for removing it.

    The checkout is laid out with the app file at the same repository relative
    path the diff names (app/corpus_app.py), because a diff produced by git
    carries a/ and b/ prefixes and expects to be applied from a root.
    """
    root = workdir or tempfile.mkdtemp(prefix="assay_checkout_")
    rel = os.path.relpath(finding.app_file, finding.root)
    dest = os.path.join(root, rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy(finding.app_file, dest)

    proc = subprocess.run(["git", "apply", "-p1", "--verbose", diff_path],
                          cwd=root, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    if proc.returncode != 0:
        detail = proc.stderr.decode(errors="replace").strip()
        raise PatchFailed(diff_path, detail or "git apply exited %d"
                          % proc.returncode)
    return dest
