"""Known-correct reference for benchmark finding B04. Public.

Bind the value as a parameter. An integer cast with validation is an equally
correct alternative; the endpoint does not echo the raw id, so either correct
fix preserves behaviour.
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


@app.route("/member")
def member():
    mid = request.args.get("id", "0")
    conn = get_connection()
    cur = conn.cursor()
    query = "SELECT id, name, city, joined FROM members WHERE id = ?"
    rows = cur.execute(query, (mid,)).fetchall()
    conn.close()
    results = [dict(row) for row in rows]
    return jsonify({"count": len(results), "results": results})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})
