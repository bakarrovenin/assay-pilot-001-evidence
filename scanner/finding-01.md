# Semgrep finding for Finding 1 (the input a developer receives)

- Scanner: Semgrep OSS 1.90.0 (pinned)
- Rule id (canonical): python.lang.security.audit.formatted-sql-query.formatted-sql-query
  - Official OWASP/CWE rule, vendored at scanner/rules/formatted-sql-query.yaml
    so the scan needs no network and no Semgrep login. When Semgrep runs a
    rule from a local path it namespaces the id by that path, so the SARIF
    shows it as scanner.rules.<canonical id>. Same rule, same logic.
- CWE-89: SQL Injection.  OWASP A03:2021 Injection.
- Location: app/corpus_app.py line 35
- Message: "Detected possible formatted SQL query. Use parameterized queries instead."
- Command to reproduce (from repo root, inside the venv):
    semgrep scan --config=scanner/rules/formatted-sql-query.yaml \
      --no-git-ignore --metrics=off app/corpus_app.py
- Machine-readable output: scanner/finding-01.sarif
