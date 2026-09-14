"""Favourite product service.

Run it with

    python finding_13.py

and set a favourite at  /favourite?name=Notebook , which echoes it back.
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


def ensure_favourites_table(cur):
    """Create the favourites table on first use."""
    cur.execute(
        "CREATE TABLE IF NOT EXISTS favourites "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)")


def remember_favourite(name):
    """Store the chosen favourite."""
    conn = get_connection()
    cur = conn.cursor()
    ensure_favourites_table(cur)
    cur.execute("INSERT INTO favourites (name) VALUES (?)", (name,))
    conn.commit()
    conn.close()


def show_favourite():
    """Read the most recent favourite back and return its product details."""
    conn = get_connection()
    cur = conn.cursor()

    row = cur.execute(
        "SELECT name FROM favourites ORDER BY id DESC LIMIT 1").fetchone()
    fav = row["name"] if row is not None else ""

    query = f"SELECT id, name, price, category, sku FROM products WHERE name = '{fav}'"
    rows = cur.execute(query).fetchall()
    conn.close()

    results = [dict(r) for r in rows]
    return jsonify({"query_name": fav, "count": len(results), "results": results})


@app.route("/favourite")
def set_favourite():
    """Remember a favourite product by name, then show it back.

    e.g. /favourite?name=Notebook
    """
    name = request.args.get("name", "")
    remember_favourite(name)
    return show_favourite()


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        import seed

        seed.build()
    app.run(host="127.0.0.1", port=5013, debug=False)
