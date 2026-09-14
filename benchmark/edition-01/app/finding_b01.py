"""Book lookup service for the lending-library catalogue.

Run it with

    python finding_b01.py

and query it at  /book?title=Refactoring
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


@app.route("/book")
def book():
    """Look up a book by its exact title, e.g. /book?title=Refactoring"""
    title = request.args.get("title", "")

    conn = get_connection()
    cur = conn.cursor()

    query = f"SELECT id, title, author, shelf, isbn FROM books WHERE title = '{title}'"
    rows = cur.execute(query).fetchall()
    conn.close()

    results = [dict(row) for row in rows]
    return jsonify({"query_title": title, "count": len(results), "results": results})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        import seed

        seed.build()
    app.run(host="127.0.0.1", port=5201, debug=False)
