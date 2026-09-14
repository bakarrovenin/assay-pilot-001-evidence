"""Database seeder for the Assay benchmark, edition 1.

Creates a small, deterministic SQLite database for a lending-library service.
Running this again drops and rebuilds everything, so the data is always
identical. This is public benchmark material and shares nothing with the pilot
corpus: different tables, different rows, different sensitive column.

    python seed.py
"""

import os
import sqlite3
import unicodedata

DB_PATH = os.path.join(os.path.dirname(__file__), "library.db")

# Public catalogue rows. Titles are chosen to include awkward legitimate
# values a benign input set will exercise: an apostrophe, a hyphen, a percent
# sign, a plus, and a non-ASCII character.
BOOKS = [
    # (title, author, shelf, isbn, copies)
    ("Clean Code", "Robert Martin", "A1", "9780132350884", 4),
    ("The Pragmatic Programmer", "Hunt and Thomas", "A2", "9780201616224", 3),
    ("Refactoring", "Martin Fowler", "A3", "9780201485677", 2),
    ("Winnie-the-Pooh", "A. A. Milne", "C7", "9780525444473", 5),
    ("Child's Garden of Verses", "R. L. Stevenson", "C8", "9780192727565", 1),
    ("100% Pure Adrenaline", "Dale Vretch", "D2", "9781000000017", 2),
    ("C++ Primer", "Lippman et al.", "B4", "9780321714114", 3),
    ("Café Society", "Elodie Marchand", "E1", "9781000000024", 2),
    ("The A-Team Companion", "P. Long", "F3", "9781000000031", 1),
    ("Gödel, Escher, Bach", "Douglas Hofstadter", "B1", "9780465026562", 2),
]

MEMBERS = [
    # (name, city, joined)
    ("Ada Lovelace", "London", "2021-03-01"),
    ("Grace Hopper", "New York", "2021-05-14"),
    ("Alan Turing", "Manchester", "2022-01-09"),
    ("Katherine Johnson", "Hampton", "2022-07-22"),
    ("Edsger Dijkstra", "Austin", "2023-02-11"),
]

LOANS = [
    # (member_index, book_index, due)
    (0, 0, "2026-10-01"),
    (1, 3, "2026-09-30"),
    (2, 6, "2026-10-05"),
]

# The sensitive table. A public endpoint must never return a row of this.
STAFF = [
    # (username, pw_hash, role, email)
    ("s.admin", "argon2id$v=19$m=65536,t=3$c3RhZmZzYWx0$Zm9vYmFy", "admin", "s.admin@library.example"),
    ("j.clerk", "argon2id$v=19$m=65536,t=3$Y2xlcmtzYWx0$YmF6cXV4", "clerk", "j.clerk@library.example"),
]


def build():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE books (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            title   TEXT NOT NULL,
            author  TEXT NOT NULL,
            shelf   TEXT NOT NULL,
            isbn    TEXT NOT NULL,
            copies  INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE members (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            name    TEXT NOT NULL,
            city    TEXT NOT NULL,
            joined  TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE loans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id   INTEGER NOT NULL,
            book_id     INTEGER NOT NULL,
            due         TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE staff (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            pw_hash  TEXT NOT NULL,
            role     TEXT NOT NULL,
            email    TEXT NOT NULL
        )
        """
    )

    # Store titles in Unicode NFC so an accented title matches a normally typed
    # lookup rather than depending on the client's normalisation form.
    books = [(unicodedata.normalize("NFC", t), a, s, i, c) for (t, a, s, i, c) in BOOKS]
    cur.executemany(
        "INSERT INTO books (title, author, shelf, isbn, copies) VALUES (?, ?, ?, ?, ?)",
        books,
    )
    cur.executemany(
        "INSERT INTO members (name, city, joined) VALUES (?, ?, ?)", MEMBERS
    )
    cur.executemany(
        "INSERT INTO loans (member_id, book_id, due) VALUES (?, ?, ?)",
        [(m + 1, b + 1, due) for (m, b, due) in LOANS],
    )
    cur.executemany(
        "INSERT INTO staff (username, pw_hash, role, email) VALUES (?, ?, ?, ?)",
        STAFF,
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    build()
