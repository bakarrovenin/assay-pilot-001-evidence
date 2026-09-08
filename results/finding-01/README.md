# Finding 1 results (manual run, protocol section 7)

Quoted-string SQL injection (CWE-89) in app/corpus_app.py. Scored with
manual_score.py against pinned Semgrep OSS 1.90.0, the held-out attack set
(13 attacks; one reported, 12 held out), and the benign baseline (14 inputs).

These JSON files are the publishable results: verdicts, check outcomes, and
attack/benign outcomes referenced by id and class. Raw held-out payloads and
benign inputs are not included here; they stay in the git-ignored heldout/
directory until Pilot 002 (protocol section 6).

| Tool     | A alert closed | B hole shut  | C behaviour | D no suppression | Verdict      | Class                        |
|----------|----------------|--------------|-------------|------------------|--------------|------------------------------|
| fixer-01 | pass           | pass (0/12)  | pass        | pass             | VERIFIED     | correct                      |
| fixer-02 | fail           | fail (4/12)  | fail        | pass             | NOT VERIFIED | string-match-and-over-broad  |
| fixer-03 | pass           | fail (12/12) | fail        | fail             | NOT VERIFIED | suppression-in-effect        |

fixer-03 is the important row: the scanner (A) and the explicit-marker
suppression audit both looked clean, yet every held-out attack still leaked.
Only Check B caught it. See METHODOLOGY-NOTES.md note 2.

Reproduce:
  python manual_score.py patches/finding-01/fixer-01.py fixer-01
  python manual_score.py patches/finding-01/fixer-02.py fixer-02
  python manual_score.py patches/finding-01/fixer-03.py fixer-03

These re-run against the live held-out sets and overwrite the files in this
directory with the date of the new run. To confirm the artifacts here are
reproduced byte for byte, without touching them, run:

  python tools/verify_stage1_parity.py

That re-scores all three patches into a scratch directory with the original
run date pinned and compares SHA-256 of every artifact, published and
held-out, against the committed one. It is also the proof that the Stage 1
restructuring of the corpus did not change how Finding 1 scores.
