"""The findings by tools matrix (stage 4).

Stage 3 scores one patch. Stage 4 is the grid: every finding in the corpus
against every tool that supplied a patch for it.

The harness does not call the fixers. Patches arrive as diff files that the
experimenter puts on disk, one per cell:

    patches/<finding-id>/<tool>.patch

That is deliberate and it is what makes the numbers defensible. A harness that
invoked the tools itself would be making choices about prompt, temperature,
retries and timeouts, and every one of those choices would end up inside the
result. Protocol section 2 fixes the prompt and requires it to be identical
across tools; keeping generation outside the harness is how that stays true.

## Four cell states, and why "not supplied" is not a failure

  scored        the patch ran and produced VERIFIED or NOT VERIFIED
  insufficient  the patch ran and produced INSUFFICIENT EVIDENCE
  not-run       a diff is on disk but the scorer has not run it yet
  not-supplied  no diff on disk for this cell
  not-built     the finding is a structural placeholder, nothing to score

Only the first two belong in any rate. A tool that was never given a patch for
finding 7 has not failed finding 7, and quietly folding those cells into a
denominator would understate every tool that was tested on fewer findings. The
report prints the cell counts next to the rates so the denominator is always
visible.

That distinction is also why coverage is reported at all. A verified-fix rate
over three cells and the same rate over sixty are not the same claim.
"""

import json
import os

from harness import corpus

ROOT = corpus.ROOT

PATCH_SUFFIX = ".patch"
PATCHED_FILE_SUFFIX = ".py"

SCORED = "scored"
INSUFFICIENT = "insufficient"
NOT_RUN = "not-run"
NOT_SUPPLIED = "not-supplied"
NOT_BUILT = "not-built"


class Cell(object):
    """One finding scored against one tool."""

    def __init__(self, finding_id, tool, patch=None, patched_file=None,
                 built=True):
        self.finding_id = finding_id
        self.tool = tool
        self.patch = patch
        self.patched_file = patched_file
        self.built = built
        self.evidence = None
        self.insufficient = None

    @property
    def supplied(self):
        return bool(self.patch or self.patched_file)

    @property
    def state(self):
        if not self.built:
            return NOT_BUILT
        if self.evidence is not None:
            return SCORED
        if self.insufficient is not None:
            return INSUFFICIENT
        if not self.supplied:
            return NOT_SUPPLIED
        # A diff is on disk but the scorer has not run it. Distinct from
        # not-supplied, and counted in neither the rates nor the insufficient
        # rate: nothing has been attempted, so there is nothing to report
        # except that it is outstanding.
        return NOT_RUN

    @property
    def verdict(self):
        if self.evidence is not None:
            return self.evidence["verdict"]
        if self.insufficient is not None:
            return "INSUFFICIENT EVIDENCE"
        return None

    @property
    def failure_class(self):
        return self.evidence["failure_class"] if self.evidence else None

    @property
    def alert_closed(self):
        """Check A only. None when the cell produced no verdict."""
        if self.evidence is None:
            return None
        return bool(self.evidence["checks"]["A_alert_closed"]["pass"])

    def __repr__(self):
        return "<Cell %s/%s %s>" % (self.finding_id, self.tool, self.state)


def evidence_path(finding, tool, root=ROOT):
    return os.path.join(root, finding.results_dir, tool + ".json")


def insufficient_path(finding, tool, root=ROOT):
    """Where a run that produced no verdict is recorded.

    A separate filename on purpose. INSUFFICIENT EVIDENCE is a result the
    protocol requires us to report, and a file named .insufficient.json cannot
    be mistaken by a reader, or by a later script, for a verdict.
    """
    return os.path.join(root, finding.results_dir, tool + ".insufficient.json")


def provenance_path(finding, tool, root=ROOT):
    return os.path.join(root, finding.results_dir, tool + ".provenance.json")


def discover_tools(findings, root=ROOT):
    """Every tool name that has supplied at least one patch anywhere."""
    tools = set()
    for finding in findings:
        d = os.path.join(root, finding.entry.get("patches_dir",
                                                 os.path.join("patches",
                                                              finding.id)))
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if name.startswith("_"):
                continue
            stem, ext = os.path.splitext(name)
            if ext in (PATCH_SUFFIX, PATCHED_FILE_SUFFIX):
                tools.add(stem)
    return sorted(tools)


def build(root=ROOT, findings=None, tools=None, results_root=None):
    """Build the full matrix. Returns (findings, tools, {(finding,tool): Cell}).

    results_root is where already-recorded results are read from. It is
    separate from root so a dry run can write and read its results somewhere
    other than the repository while still discovering the corpus and the
    patches from the repository itself.
    """
    all_findings = corpus.list_findings(root=root)
    if findings:
        wanted = set(findings)
        all_findings = [f for f in all_findings if f.id in wanted]
    built = [f for f in all_findings if f.status == "built"]

    all_tools = tools or discover_tools(built, root)

    cells = {}
    for finding in all_findings:
        patches_dir = os.path.join(root, finding.entry.get(
            "patches_dir", os.path.join("patches", finding.id)))
        for tool in all_tools:
            if finding.status != "built":
                cells[(finding.id, tool)] = Cell(finding.id, tool, built=False)
                continue
            patch = os.path.join(patches_dir, tool + PATCH_SUFFIX)
            pfile = os.path.join(patches_dir, tool + PATCHED_FILE_SUFFIX)
            cell = Cell(finding.id, tool,
                        patch=patch if os.path.exists(patch) else None,
                        patched_file=pfile if os.path.exists(pfile) else None)
            _load_existing(cell, finding, results_root or root)
            cells[(finding.id, tool)] = cell
    return all_findings, all_tools, cells


def _load_existing(cell, finding, root):
    """Attach whatever result is already on disk for this cell."""
    ev = evidence_path(finding, cell.tool, root)
    ie = insufficient_path(finding, cell.tool, root)
    if os.path.exists(ev):
        with open(ev, encoding="utf-8") as f:
            cell.evidence = json.load(f)
    elif os.path.exists(ie):
        with open(ie, encoding="utf-8") as f:
            cell.insufficient = json.load(f)
