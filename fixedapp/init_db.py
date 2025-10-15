import sqlite3
import os

os.makedirs("data", exist_ok=True)
conn = sqlite3.connect("data/users.db")
c = conn.cursor()
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    fullname TEXT
);
""")
c.execute("INSERT OR IGNORE INTO users (username, fullname) VALUES ('alice', 'Alice Example')")
c.execute("INSERT OR IGNORE INTO users (username, fullname) VALUES ('bob', 'Bob Example')")
conn.commit()
conn.close()
print("DB inicializada en data/users.db (fixed)")
