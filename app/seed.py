"""Database seeder for the Assay Pilot 001 corpus app.

Creates a small, deterministic SQLite database. Running this again drops and
rebuilds everything, so the data is always identical.

Tables:
  products - the product catalogue exposed by the /product endpoint
  users    - internal account records (never meant to be publicly readable)

Run:  python seed.py
"""

import os
import sqlite3
import unicodedata

DB_PATH = os.path.join(os.path.dirname(__file__), "store.db")

PRODUCTS = [
    # (name, price, category, sku)
    ("Water Bottle",        12.50, "Kitchen",   "WB-001"),
    ("Ceramic Mug",          9.00, "Kitchen",   "CM-002"),
    ("Notebook",             4.25, "Office",    "NB-003"),
    ("Desk Lamp",           28.99, "Office",    "DL-004"),
    ("Wireless Mouse",      19.95, "Office",    "WM-005"),
    ("Yoga Mat",            24.00, "Fitness",   "YM-006"),
    ("Backpack",            45.00, "Travel",    "BP-007"),
    ("Chef's Knife",        60.00, "Kitchen",   "CK-008"),
    ("100% Cotton Socks",    8.00, "Apparel",   "CS-009"),
    ("T-Shirt",             15.00, "Apparel",   "TS-010"),
    ("Café Blend Coffee", 11.75, "Kitchen", "CB-011"),
    ("Stainless Straw",      3.50, "Kitchen",   "SS-012"),
]

USERS = [
    # (username, password_hash, role, email). Placeholder hashes.
    ("admin",   "hash_admin_9f8e7d",  "admin",  "admin@example.com"),
    ("jbrown",  "hash_jbrown_1a2b3c", "staff",  "jbrown@example.com"),
    ("mgarcia", "hash_mgarcia_4d5e6f","staff",  "mgarcia@example.com"),
]


def build():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE products (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT NOT NULL,
            price    REAL NOT NULL,
            category TEXT NOT NULL,
            sku      TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL,
            email         TEXT NOT NULL
        )
        """
    )
    # Store product names in Unicode NFC (standard composed form) so an
    # accented name matches a normally typed lookup.
    products_nfc = [
        (unicodedata.normalize("NFC", name), price, category, sku)
        for (name, price, category, sku) in PRODUCTS
    ]
    cur.executemany(
        "INSERT INTO products (name, price, category, sku) VALUES (?, ?, ?, ?)",
        products_nfc,
    )
    cur.executemany(
        "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
        USERS,
    )
    conn.commit()
    conn.close()
    print("Seeded", DB_PATH)
    print("products:", len(PRODUCTS), " users:", len(USERS))


if __name__ == "__main__":
    build()
