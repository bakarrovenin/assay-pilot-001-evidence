"""Catalogue listing for the lending library, sorted by a chosen column.

Run it with

    python finding_b08.py

and query it at  /catalog?sort=author  or  /catalog?sort=-title  for descending.
"""

import os
import sqlite3

from flask import Flask, jsonify, request

DB_PATH = os.path.join(os.path.dirname(__file__), "library.db")

app = Flask(__name__)


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/catalog")
def catalog():
    """List books, featuring and sorting by a chosen column.

    "sort=author" sorts ascending, "sort=-author" descending.
    e.g. /catalog?sort=-title
    """
    spec = request.args.get("sort", "title")
    descending = spec.startswith("-")
    column = spec[1:] if descending else spec
    direction = "DESC" if descending else "ASC"

    conn = get_connection()
    cur = conn.cursor()

    query = f"SELECT id, title, {column} AS featured FROM books ORDER BY {column} {direction}"
    rows = cur.execute(query).fetchall()
    conn.close()

    results = [dict(row) for row in rows]
    return jsonify({"sort": spec, "count": len(results), "results": results})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        import seed

        seed.build()
    app.run(host="127.0.0.1", port=5208, debug=False)
