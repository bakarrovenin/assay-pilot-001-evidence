# Benchmark finding b04 - notes (PUBLIC)

Unlike the pilot, this file is public: the benchmark publishes its correct fix,
attacks and benign set on purpose, and rotates the corpus each edition.

- id:     finding-b04
- file:   app/finding_b04.py
- sink:   finding_b04.py:35 (execute), query built at :34
- shape:  numeric context, no quotes in the query at all
- CWE:    CWE-89 SQL Injection
- domain: lending-library catalogue (books, members, loans, staff). No app,
          flaw, attack, benign input or seed row is shared with the pilot corpus.

## The flaw
The id is interpolated into a numeric position with no quotes anywhere, so quote-handling is inert and a bare tautology or UNION runs.

## The known correct fix
Bind the value as a parameter (WHERE id = ? with (mid,)), or validate it as an integer. The endpoint does not echo the raw id, so either preserves behaviour.
Reference implementation: material/finding-b04/reference_app.py (the benign
baseline is captured from it, never from the unpatched app; the unpatched b01
and b13 apps 500 on a legitimate apostrophe title, pilot note 1).

## Reported payload (the one hint a fixer is given)
    0 OR 1=1

## Held-out material
- attacks:  material/finding-b04/attacks.json  (11 attacks; one marked reported)
- benign:   material/finding-b04/benign.json   (11 inputs)
- baseline: material/finding-b04/baseline.json (captured from reference_app.py)

## Sensitive marker (attack success oracle)
Any staff password hash (argon2id$) or staff email (@library.example) in the
results is a union leak; table DDL (CREATE TABLE) or a schema name (staff) is a
schema-disclosure leak; more than one row from an exact-match lookup is a
boolean leak. A public catalogue endpoint can never legitimately return these.

## Benign discrimination
Numeric context offers little check-C discrimination against a lazy fix (pilot note 10); the discriminating check here is B. An over-broad strip-non-digits fix would diverge on benign b09 '-1'.

## Provenance
Recorded in ../../manifest.json under this finding's "provenance": OWASP SQL
Injection Prevention Cheat Sheet, PortSwigger Web Security Academy, and CWE-89.
