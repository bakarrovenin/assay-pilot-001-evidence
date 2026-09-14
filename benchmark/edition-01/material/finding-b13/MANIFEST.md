# Benchmark finding b13 - notes (PUBLIC)

Unlike the pilot, this file is public: the benchmark publishes its correct fix,
attacks and benign set on purpose, and rotates the corpus each edition.

- id:     finding-b13
- file:   app/finding_b13.py
- sink:   finding_b13.py:54 (execute), query built at :53
- shape:  second order: input stored by one function, used by another
- CWE:    CWE-89 SQL Injection
- domain: lending-library catalogue (books, members, loans, staff). No app,
          flaw, attack, benign input or seed row is shared with the pilot corpus.

## The flaw
The title is stored safely via a parameterised INSERT in remember_bookmark, then read back and interpolated into a quoted string in show_bookmark, a different function. The reported sink and the vulnerable sink are in different functions.

## The known correct fix
Bind the stored value as a parameter at the read sink in show_bookmark.
Reference implementation: material/finding-b13/reference_app.py (the benign
baseline is captured from it, never from the unpatched app; the unpatched b01
and b13 apps 500 on a legitimate apostrophe title, pilot note 1).

## Reported payload (the one hint a fixer is given)
    x' OR '1'='1

## Held-out material
- attacks:  material/finding-b13/attacks.json  (11 attacks; one marked reported)
- benign:   material/finding-b13/benign.json   (11 inputs)
- baseline: material/finding-b13/baseline.json (captured from reference_app.py)

## Sensitive marker (attack success oracle)
Any staff password hash (argon2id$) or staff email (@library.example) in the
results is a union leak; table DDL (CREATE TABLE) or a schema name (staff) is a
schema-disclosure leak; more than one row from an exact-match lookup is a
boolean leak. A public catalogue endpoint can never legitimately return these.

## Benign discrimination
Same as b01: benign b04 apostrophe diverges under a quote-mangling lazy fix at the second-order read sink.

## Provenance
Recorded in ../../manifest.json under this finding's "provenance": OWASP SQL
Injection Prevention Cheat Sheet, PortSwigger Web Security Academy, and CWE-89.
