"""Product lookup by id for the catalogue service.

Run it with

    python finding_04.py

and query it at  /product_by_id?id=3
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


@app.route("/product_by_id")
def product_by_id():
    """Look up a single product by its numeric id, e.g. /product_by_id?id=3"""
    pid = request.args.get("id", "0")

    conn = get_connection()
    cur = conn.cursor()

    query = f"SELECT id, name, price, category, sku FROM products WHERE id = {pid}"
    rows = cur.execute(query).fetchall()
    conn.close()

    results = [dict(row) for row in rows]
    return jsonify({"query_id": pid, "count": len(results), "results": results})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        import seed

        seed.build()
    app.run(host="127.0.0.1", port=5004, debug=False)
