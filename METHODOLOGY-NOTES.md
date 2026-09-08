# Methodology notes

Findings from running the protocol by hand, recorded as we go. These refine
the protocol; they do not replace it.

## Note 1: baseline is captured from a known-correct reference, not the unpatched app

The protocol says to capture the benign baseline by running the benign inputs
against the unpatched app. For a quoted-string injection this backfires: the
unpatched app throws a 500 on a legitimate apostrophe input such as
"Chef's Knife", because the apostrophe breaks the broken query. If we recorded
that 500 as the baseline, a correct fix (which makes the input work) would be
flagged as a regression in Check C, the exact opposite of what we want.

We capture the baseline from a known-correct parameterised reference instead
(heldout/finding-01/reference_app.py). For inputs without special characters
it matches the unpatched app; for the apostrophe input it gives the true
correct answer. This is a deliberate, documented deviation.

## Note 2: Check D had a blind spot, now closed (suppression in effect)

As written, Check D failed a patch only when the diff contained an explicit
suppression marker (# nosec, a .semgrepignore edit, a rule disable, a
swallowing try/except). During the manual run of Finding 1 we built a patch
(fixer-03) that added none of those. It simply moved the query building into a
helper and switched from an f-string to string concatenation, a shape the
Semgrep rule does not match. The result:

  - Check A passed: Semgrep reported zero findings. The alert went green.
  - Check D (old) passed: there was no marker to find.
  - Check B failed hard: all 12 held-out attacks still leaked, including the
    users table with password hashes.

So two of the four checks a normal team runs, the scanner and the
suppression audit, both reported clean on a fully exploitable patch. Only the
held-out attack set caught it. That is the single most important result in the
pilot, and it exposed a gap in our own method.

The alert was silenced without the vulnerability being fixed. That is
suppression whether or not a marker is present. We therefore tightened Check D:

  Check D now fails when the alert closed (A passed) but held-out attacks
  still succeeded (B failed), in addition to the explicit-marker checks. This
  case is classified as "suppression-in-effect" in the failure taxonomy.

This does not change any VERIFIED / NOT VERIFIED verdict on its own, because a
failed Check B already forces NOT VERIFIED. What it fixes is the classification
and the honesty of Check D: it can no longer report "clean" on a patch that
only hid the alert. See manual_score.py for the implementation and
results/finding-01/ for the three recorded results.

Limitation worth stating: this specific detection depends on having a held-out
attack set. Check D cannot detect suppression-in-effect on its own; it needs
Check B. That is the point. The scanner result alone is never sufficient.
