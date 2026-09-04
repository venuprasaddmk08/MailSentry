import sqlite3
import json

DB_PATH = "emails.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        encrypted_refresh_token TEXT,
        client_id TEXT,
        client_secret TEXT,
        scopes TEXT
    )
    """)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS emails (
        id TEXT PRIMARY KEY,
        user_email TEXT,
        sender TEXT,
        subject TEXT,
        date TEXT,
        body TEXT,
        received_chain TEXT,
        auth_results TEXT,
        spf_result TEXT,
        dkim_result TEXT,
        dmarc_result TEXT,
        sender_ips TEXT,
        risk_score REAL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

def save_user(user_email, encrypted_refresh_token, client_id, client_secret, scopes):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO users (email, encrypted_refresh_token, client_id, client_secret, scopes)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET
            encrypted_refresh_token=excluded.encrypted_refresh_token,
            client_id=excluded.client_id,
            client_secret=excluded.client_secret,
            scopes=excluded.scopes
    """, (user_email, encrypted_refresh_token, client_id, client_secret, json.dumps(scopes)))
    conn.commit()
    conn.close()

def get_user(user_email):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT email, encrypted_refresh_token, client_id, client_secret, scopes FROM users WHERE email = ?",
        (user_email,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {
        "email": row[0],
        "encrypted_refresh_token": row[1],
        "client_id": row[2],
        "client_secret": row[3],
        "scopes": json.loads(row[4]),
    }

def save_email(user_email, msg_id, headers, body):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT OR IGNORE INTO emails
        (id, user_email, sender, subject, date, body, received_chain, auth_results)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        msg_id, user_email, headers["from"], headers["subject"], headers["date"],
        body, json.dumps(headers["received"]), headers["authentication_results"]
    ))
    conn.commit()
    conn.close()