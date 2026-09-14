"""Known-correct reference for benchmark finding B01. Public.

Bind the value as a parameter so the query text never varies with input. Reads
the same seeded database the corpus app serves.
"""

import os
import sqlite3

from flask import Flask, jsonify, request

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "app", "library.db"))

app = Flask(__name__)


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/book")
def book():
    title = request.args.get("title", "")
    conn = get_connection()
    cur = conn.cursor()
    query = "SELECT id, title, author, shelf, isbn FROM books WHERE title = ?"
    rows = cur.execute(query, (title,)).fetchall()
    conn.close()
    results = [dict(row) for row in rows]
    return jsonify({"query_title": title, "count": len(results), "results": results})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})
