"""Reading-list service for the lending library.

Run it with

    python finding_b13.py

and bookmark a book at  /bookmark?title=Refactoring , which stores it and shows
the most recently bookmarked book back.
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


def ensure_bookmarks_table(cur):
    """Create the bookmarks table on first use."""
    cur.execute(
        "CREATE TABLE IF NOT EXISTS bookmarks "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL)")


def remember_bookmark(title):
    """Store the chosen bookmark."""
    conn = get_connection()
    cur = conn.cursor()
    ensure_bookmarks_table(cur)
    cur.execute("INSERT INTO bookmarks (title) VALUES (?)", (title,))
    conn.commit()
    conn.close()


def show_bookmark():
    """Read the most recent bookmark back and return its book details."""
    conn = get_connection()
    cur = conn.cursor()

    row = cur.execute(
        "SELECT title FROM bookmarks ORDER BY id DESC LIMIT 1").fetchone()
    mark = row["title"] if row is not None else ""

    query = f"SELECT id, title, author, shelf, isbn FROM books WHERE title = '{mark}'"
    rows = cur.execute(query).fetchall()
    conn.close()

    results = [dict(r) for r in rows]
    return jsonify({"query_title": mark, "count": len(results), "results": results})


@app.route("/bookmark")
def bookmark():
    """Remember a book by title, then show it back.

    e.g. /bookmark?title=Refactoring
    """
    title = request.args.get("title", "")
    remember_bookmark(title)
    return show_bookmark()


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        import seed

        seed.build()
    app.run(host="127.0.0.1", port=5213, debug=False)
