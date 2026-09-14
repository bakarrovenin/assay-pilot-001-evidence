"""Known-correct reference for benchmark finding B08. Public.

A column name cannot be a bound parameter, so the sort column is restricted to
a fixed allow-list of every real sortable column and never taken verbatim from
the request. The identifier is also double-quoted.
"""

import os
import sqlite3

from flask import Flask, jsonify, request

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "app", "library.db"))

app = Flask(__name__)

SORTABLE_COLUMNS = {"id", "title", "author", "shelf", "isbn", "copies"}


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/catalog")
def catalog():
    spec = request.args.get("sort", "title")
    descending = spec.startswith("-")
    column = spec[1:] if descending else spec
    direction = "DESC" if descending else "ASC"
    if column not in SORTABLE_COLUMNS:
        return jsonify({"error": "invalid sort column"}), 400
    conn = get_connection()
    cur = conn.cursor()
    query = (
        f'SELECT id, title, "{column}" AS featured FROM books '
        f'ORDER BY "{column}" {direction}'
    )
    rows = cur.execute(query).fetchall()
    conn.close()
    results = [dict(row) for row in rows]
    return jsonify({"sort": spec, "count": len(results), "results": results})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})
