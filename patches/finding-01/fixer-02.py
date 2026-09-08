"""Product lookup service for the Assay Pilot 001 corpus app.

A tiny Flask application over a small SQLite product catalogue. Run it with

    python corpus_app.py

and query it at  /product?name=Notebook
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


def _sanitize(value):
    # Escape single quotes to neutralize the ' OR '1'='1 payload.
    return value.replace("'", "\\'")


@app.route("/product")
def product_lookup():
    """Look up products by their exact name, e.g. /product?name=Notebook"""
    name = request.args.get("name", "")
    name = _sanitize(name)

    conn = get_connection()
    cur = conn.cursor()

    query = f"SELECT id, name, price, category, sku FROM products WHERE name = '{name}'"
    rows = cur.execute(query).fetchall()
    conn.close()

    results = [dict(row) for row in rows]
    return jsonify({"query_name": name, "count": len(results), "results": results})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        import seed

        seed.build()
    app.run(host="127.0.0.1", port=5001, debug=False)
