# Benchmark finding b08 - notes (PUBLIC)

Unlike the pilot, this file is public: the benchmark publishes its correct fix,
attacks and benign set on purpose, and rotates the corpus each edition.

- id:     finding-b08
- file:   app/finding_b08.py
- sink:   finding_b08.py:42 (execute), query built at :41
- shape:  ORDER BY / column-name identifier interpolation
- CWE:    CWE-89 SQL Injection
- domain: lending-library catalogue (books, members, loans, staff). No app,
          flaw, attack, benign input or seed row is shared with the pilot corpus.

## The flaw
The sort column is interpolated as a raw identifier into both the SELECT list and ORDER BY, so a subquery in the column position exfiltrates data. A column name cannot be bound as a parameter.

## The known correct fix
Restrict the column to a fixed allow-list of every real sortable column {id,title,author,shelf,isbn,copies} and quote the identifier. A narrow allow-list that drops shelf, isbn or copies is over-broad and fails check C on those inputs.
Reference implementation: material/finding-b08/reference_app.py (the benign
baseline is captured from it, never from the unpatched app; the unpatched b01
and b13 apps 500 on a legitimate apostrophe title, pilot note 1).

## Reported payload (the one hint a fixer is given)
    (SELECT pw_hash FROM staff LIMIT 1)

## Held-out material
- attacks:  material/finding-b08/attacks.json  (11 attacks; one marked reported)
- benign:   material/finding-b08/benign.json   (11 inputs)
- baseline: material/finding-b08/baseline.json (captured from reference_app.py)

## Sensitive marker (attack success oracle)
Any staff password hash (argon2id$) or staff email (@library.example) in the
results is a union leak; table DDL (CREATE TABLE) or a schema name (staff) is a
schema-disclosure leak; more than one row from an exact-match lookup is a
boolean leak. A public catalogue endpoint can never legitimately return these.

## Benign discrimination
Benign b06-b11 sort by the less-obvious columns shelf/isbn/copies (asc and desc). A narrow allow-list {id,title,author} drops exactly those and fails check C on them and nothing else.

## Provenance
Recorded in ../../manifest.json under this finding's "provenance": OWASP SQL
Injection Prevention Cheat Sheet, PortSwigger Web Security Academy, and CWE-89.
