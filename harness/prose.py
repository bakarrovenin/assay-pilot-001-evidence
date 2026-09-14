"""Explanatory prose in a vulnerable module is a leak, and this is the test.

The corpus leaked its answer three times, each through a different carrier:

  1. the public manifest carried reference_fix, endpoint and oracle for
     finding-01 (note 6; carries_answer_key in the history guard)
  2. the finding-01 module as first drafted carried comments announcing the
     flaw, stripped by the experimenter before the first commit (unrecorded;
     every committed version is clean under this test)
  3. findings 04, 08 and 13 were built with a module docstring that named the
     shape, the sink, the attack that works and the fix that works, and an
     inline comment at the sink saying "this is the flaw" (note 12)

The third one walked past both leak guards, and both were correct by their own
definition: they search for payloads, oracle prose, fix code and held-out
paths. A docstring saying "the only fixes that work are ... bind it as a
parameter" is none of those. So this file is the missing definition. A
vulnerable module, and any support file handed to a fixer with it, must read
as ordinary application code. Its comments and docstrings may describe what
the code does for its users. They may not describe the flaw, the shape, the
sink, the attack, the scanner, the experiment or the fix.

That is decided by vocabulary, which is blunt on purpose. A term list catches
"this is the numeric-context flaw" and it would also catch a comment that said
"safe to call twice". The second is a false positive and the cost of one is
that the experimenter rewords a comment. The cost of a false negative was
eight scored cells against a corpus that named its own fix. The list errs
toward the first.

Both guards use this: tools/check_no_leak.py on the working tree, and
tools/check_history_no_leak.py on every blob a push would send.
"""

import io
import re
import tokenize

# One regex per term, word-bounded where a bare substring would match ordinary
# code words (prefix, unbound, refix). Grouped by what the term gives away.
TERMS = [
    # the flaw and the attack
    ("flaw", r"\bflaws?\b"),
    ("vulnerab", r"\bvulnerab"),
    ("inject", r"\binject"),
    ("attack", r"\battack"),
    ("exploit", r"\bexploit"),
    ("payload", r"\bpayload"),
    ("malicious", r"\bmalicious\b"),
    ("hole", r"\bholes?\b"),
    ("taint", r"\btaint"),
    ("sink", r"\bsinks?\b"),
    ("second order", r"\bsecond[- ]order\b"),
    ("trusted/untrusted", r"\b(un)?trusted\b"),
    ("safe/unsafe", r"\b(un)?safe(ly)?\b"),
    ("secure/insecure", r"\b(in)?secur"),
    # the mechanism, named
    ("interpolat", r"\binterpolat"),
    ("concatenat", r"\bconcatenat"),
    ("f-string", r"\bf-string"),
    ("quote", r"\bquot(e|es|ed|ing)\b"),
    ("escape", r"\bescap"),
    ("sanitis", r"\bsaniti[sz]"),
    # the fix, named
    ("fix", r"\bfix(es|ed|ing)?\b"),
    ("bind/bound", r"\b(bind(s|ing)?|bound)\b"),
    ("parameteris", r"\bparameteri[sz]"),
    ("bound parameter", r"\bparameter(s)?\b"),
    ("allow-list", r"\b(allow|deny|block|white|black)[- ]?list"),
    ("validate", r"\bvalidat"),
    ("identifier", r"\bidentifiers?\b"),
    # the experiment
    ("scanner", r"\bscanner\b"),
    ("semgrep", r"\bsemgrep\b"),
    ("codeql", r"\bcodeql\b"),
    ("cwe", r"\bcwe\b"),
    ("owasp", r"\bowasp\b"),
    ("portswigger", r"\bportswigger\b"),
    ("finding", r"\bfindings?\b"),
    ("shape", r"\bshapes?\b"),
    ("protocol", r"\bprotocol\b"),
    ("manifest", r"\bmanifest\b"),
    ("provenance", r"\bprovenance\b"),
    ("held out", r"\bheld[- ]out\b"),
    ("fixer", r"\bfixers?\b"),
    ("patch", r"\bpatch"),
]

COMPILED = [(label, re.compile(pattern, re.IGNORECASE)) for label, pattern in TERMS]


def prose_segments(source):
    """Every comment and every string that stands alone as a statement.

    Standalone strings are docstrings and bare string expressions, which is
    where module and function prose lives. String literals used as values
    (SQL text, JSON keys, error messages) are code, not prose, and are left
    alone: the query itself necessarily contains the words the guard would
    otherwise object to.

    Returns (line, kind, text) triples. If the source does not tokenize, the
    whole file is returned as one segment so a broken module is searched
    rather than silently passed.
    """
    segments = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, SyntaxError):
        return [(1, "unparseable", source)]

    # A string token is prose when it is the only thing on its logical line:
    # the previous significant token is a NEWLINE, INDENT, DEDENT or the start
    # of the file, and the next is a NEWLINE.
    starts_statement = {tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
                        tokenize.NL, tokenize.COMMENT}
    prev_type = tokenize.NEWLINE
    for i, tok in enumerate(tokens):
        if tok.type == tokenize.COMMENT:
            segments.append((tok.start[0], "comment", tok.string.lstrip("#")))
        elif tok.type == tokenize.STRING and prev_type in starts_statement:
            nxt = tokens[i + 1].type if i + 1 < len(tokens) else tokenize.NEWLINE
            if nxt in (tokenize.NEWLINE, tokenize.NL, tokenize.ENDMARKER):
                segments.append((tok.start[0], "docstring", tok.string))
        if tok.type not in (tokenize.NL, tokenize.COMMENT):
            prev_type = tok.type
    return segments


def violations(source):
    """Every (line, kind, term, excerpt) where module prose names the flaw."""
    found = []
    for line, kind, text in prose_segments(source):
        for label, rx in COMPILED:
            m = rx.search(text)
            if m:
                # One excerpt per segment per term, the line it sits on.
                offset = text[:m.start()].count("\n")
                excerpt = text.split("\n")[offset].strip()
                found.append((line + offset, kind, label, excerpt[:90]))
    return found


def handed_to_fixer(finding):
    """The module paths a fixer receives for this finding, from the manifest."""
    entry = finding.entry.get("app", {})
    paths = [entry.get("file")]
    paths += list(entry.get("support_files") or [])
    return [p for p in paths if p]
