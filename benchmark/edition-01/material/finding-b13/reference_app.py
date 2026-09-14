"""Known-correct reference for benchmark finding B13. Public.

The second-order read binds the stored value as a parameter, so the taint that
travels through the bookmarks table never reaches the query as code.
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


def ensure_bookmarks_table(cur):
    cur.execute(
        "CREATE TABLE IF NOT EXISTS bookmarks "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL)")


@app.route("/bookmark")
def bookmark():
    title = request.args.get("title", "")
    conn = get_connection()
    cur = conn.cursor()
    ensure_bookmarks_table(cur)
    cur.execute("INSERT INTO bookmarks (title) VALUES (?)", (title,))
    conn.commit()
    row = cur.execute("SELECT title FROM bookmarks ORDER BY id DESC LIMIT 1").fetchone()
    mark = row["title"] if row is not None else ""
    query = "SELECT id, title, author, shelf, isbn FROM books WHERE title = ?"
    rows = cur.execute(query, (mark,)).fetchall()
    conn.close()
    results = [dict(r) for r in rows]
    return jsonify({"query_title": mark, "count": len(results), "results": results})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})
