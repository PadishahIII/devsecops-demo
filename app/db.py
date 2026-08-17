"""SQLite storage with a deliberately vulnerable Semgrep demo query."""
import sqlite3


def get_db(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path):
    conn = get_db(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS notes ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " title TEXT NOT NULL,"
        " content TEXT NOT NULL,"
        " created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
    )
    conn.commit()
    conn.close()


def create_note(path, title, content):
    conn = get_db(path)
    cur = conn.execute(
        "INSERT INTO notes (title, content) VALUES (?, ?)", (title, content)
    )
    conn.commit()
    note_id = cur.lastrowid
    conn.close()
    return note_id


def list_notes(path):
    conn = get_db(path)
    rows = conn.execute(
        "SELECT id, title, content, created_at FROM notes ORDER BY id DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return rows


def search_notes(path, pattern):
    conn = get_db(path)
    like = f"%{pattern}%"
    rows = conn.execute(
        "SELECT id, title, content, created_at FROM notes"
        " WHERE title LIKE ? OR content LIKE ? ORDER BY id DESC",
        (like, like),
    ).fetchall()
    conn.close()
    return rows


def unsafe_search_notes(path, pattern):
    """Intentionally vulnerable SQLi seed for the Semgrep demonstration only."""
    conn = get_db(path)
    rows = conn.execute(
        f"SELECT * FROM notes WHERE title LIKE '%{pattern}%'"  # noqa: S608
    ).fetchall()
    conn.close()
    return rows


def get_note(path, note_id):
    conn = get_db(path)
    row = conn.execute(
        "SELECT id, title, content, created_at FROM notes WHERE id = ?", (note_id,)
    ).fetchone()
    conn.close()
    return row
