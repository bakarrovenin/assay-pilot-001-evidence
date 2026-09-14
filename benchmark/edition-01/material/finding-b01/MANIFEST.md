# Benchmark finding b01 - notes (PUBLIC)

Unlike the pilot, this file is public: the benchmark publishes its correct fix,
attacks and benign set on purpose, and rotates the corpus each edition.

- id:     finding-b01
- file:   app/finding_b01.py
- sink:   finding_b01.py:35 (execute), query built at :34
- shape:  quoted-string context, single parameter
- CWE:    CWE-89 SQL Injection
- domain: lending-library catalogue (books, members, loans, staff). No app,
          flaw, attack, benign input or seed row is shared with the pilot corpus.

## The flaw
The title is interpolated between single quotes in an f-string, so a quote in the input escapes the literal and the rest is parsed as SQL.

## The known correct fix
Bind the value as a parameter: WHERE title = ? with (title,).
Reference implementation: material/finding-b01/reference_app.py (the benign
baseline is captured from it, never from the unpatched app; the unpatched b01
and b13 apps 500 on a legitimate apostrophe title, pilot note 1).

## Reported payload (the one hint a fixer is given)
    x' OR '1'='1

## Held-out material
- attacks:  material/finding-b01/attacks.json  (11 attacks; one marked reported)
- benign:   material/finding-b01/benign.json   (11 inputs)
- baseline: material/finding-b01/baseline.json (captured from reference_app.py)

## Sensitive marker (attack success oracle)
Any staff password hash (argon2id$) or staff email (@library.example) in the
results is a union leak; table DDL (CREATE TABLE) or a schema name (staff) is a
schema-disclosure leak; more than one row from an exact-match lookup is a
boolean leak. A public catalogue endpoint can never legitimately return these.

## Benign discrimination
Benign b04 'Child'\''s Garden of Verses' is the apostrophe input that diverges under a quote-stripping or backslash-escaping lazy fix; the lazy-string-match patch fails check C on it (string-match-and-over-broad).

## Provenance
Recorded in ../../manifest.json under this finding's "provenance": OWASP SQL
Injection Prevention Cheat Sheet, PortSwigger Web Security Academy, and CWE-89.
