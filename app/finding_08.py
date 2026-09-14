"""Catalogue listing with a caller-chosen sort column.

Run it with

    python finding_08.py

and query it at  /catalog?sort=-price
"""

import os
import sqlite3

from flask import Flask, jsonify, request

DB_PATH = os.path.join(os.path.dirname(__file__), "store.db")

app = Flask(__name__)


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/catalog")
def catalog():
    """List products, featuring and sorting by a chosen column.

    "sort=price" sorts ascending, "sort=-price" descending. e.g. /catalog?sort=-price
    """
    spec = request.args.get("sort", "name")
    descending = spec.startswith("-")
    column = spec[1:] if descending else spec
    direction = "DESC" if descending else "ASC"

    conn = get_connection()
    cur = conn.cursor()

    query = f"SELECT id, name, {column} AS featured FROM products ORDER BY {column} {direction}"
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
    app.run(host="127.0.0.1", port=5008, debug=False)
