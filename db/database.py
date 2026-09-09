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
        content_json TEXT,
        geo_json TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS mailbox_count_cache (
        user_email TEXT PRIMARY KEY,
        exact_count INTEGER,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    existing_cols = [row[1] for row in conn.execute("PRAGMA table_info(emails)").fetchall()]
    if "content_json" not in existing_cols:
        conn.execute("ALTER TABLE emails ADD COLUMN content_json TEXT")
    if "geo_json" not in existing_cols:
        conn.execute("ALTER TABLE emails ADD COLUMN geo_json TEXT")
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

def save_email(user_email, msg_id, headers, body, spf=None, dkim=None, dmarc=None,
               sender_ips=None, risk_score=None, content=None, geo=None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO emails
        (id, user_email, sender, subject, date, body, received_chain, auth_results,
         spf_result, dkim_result, dmarc_result, sender_ips, risk_score, content_json, geo_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            spf_result=excluded.spf_result,
            dkim_result=excluded.dkim_result,
            dmarc_result=excluded.dmarc_result,
            sender_ips=excluded.sender_ips,
            risk_score=excluded.risk_score,
            content_json=excluded.content_json,
            geo_json=excluded.geo_json
    """, (
        msg_id, user_email, headers["from"], headers["subject"], headers["date"],
        body, json.dumps(headers["received"]), headers["authentication_results"],
        spf, dkim, dmarc, json.dumps(sender_ips or []), risk_score,
        json.dumps(content) if content else None,
        json.dumps(geo) if geo else None,
    ))
    conn.commit()
    conn.close()

def get_stats(user_email):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT risk_score FROM emails WHERE user_email = ? AND risk_score IS NOT NULL",
        (user_email,)
    ).fetchall()
    conn.close()

    counts = {"high": 0, "medium": 0, "low": 0}
    for (score,) in rows:
        if score >= 60:
            counts["high"] += 1
        elif score >= 30:
            counts["medium"] += 1
        else:
            counts["low"] += 1
    return counts

def get_scanned_count(user_email):
    conn = sqlite3.connect(DB_PATH)
    count = conn.execute(
        "SELECT COUNT(*) FROM emails WHERE user_email = ? AND risk_score IS NOT NULL",
        (user_email,)
    ).fetchone()[0]
    conn.close()
    return count

def get_emails_by_risk(user_email, risk_level=None, limit=200):
    conn = sqlite3.connect(DB_PATH)
    if risk_level == "high":
        condition = "risk_score >= 60"
    elif risk_level == "medium":
        condition = "risk_score >= 30 AND risk_score < 60"
    elif risk_level == "low":
        condition = "risk_score < 30"
    else:
        condition = "1=1"

    rows = conn.execute(f"""
        SELECT id, sender, subject, date, body, spf_result, dkim_result, dmarc_result,
               sender_ips, risk_score, content_json, geo_json
        FROM emails
        WHERE user_email = ? AND risk_score IS NOT NULL AND {condition}
        ORDER BY risk_score DESC
        LIMIT ?
    """, (user_email, limit)).fetchall()
    conn.close()

    results = []
    for row in rows:
        content = json.loads(row[10]) if row[10] else {}
        geo = json.loads(row[11]) if row[11] else []
        results.append({
            "id": row[0],
            "from": row[1],
            "subject": row[2],
            "date": row[3],
            "body_preview": (row[4] or "")[:200],
            "spf": row[5],
            "dkim": row[6],
            "dmarc": row[7],
            "sender_ips": json.loads(row[8]) if row[8] else [],
            "geo": geo,
            "content": content,
            "risk": {
                "risk_score": row[9],
                "risk_level": "high" if row[9] >= 60 else ("medium" if row[9] >= 30 else "low"),
            },
        })
    return results

def get_scanned_ids(user_email, ids):
    """Returns the subset of `ids` that are already scanned (have a risk_score) for this user."""
    if not ids:
        return set()
    conn = sqlite3.connect(DB_PATH)
    placeholders = ",".join(["?"] * len(ids))
    rows = conn.execute(
        f"""SELECT id FROM emails
            WHERE user_email = ? AND risk_score IS NOT NULL AND id IN ({placeholders})""",
        (user_email, *ids)
    ).fetchall()
    conn.close()
    return {row[0] for row in rows}

def get_emails_by_ids(user_email, ids):
    """
    Returns a dict {id: full_email_dict} for already-scanned emails matching `ids`,
    in the same shape /emails returns per-item (from, subject, body_preview, spf,
    dkim, dmarc, sender_ips, geo, content, risk). Used to skip re-scanning on repeat views.
    """
    if not ids:
        return {}
    conn = sqlite3.connect(DB_PATH)
    placeholders = ",".join(["?"] * len(ids))
    rows = conn.execute(f"""
        SELECT id, sender, subject, date, body, received_chain, auth_results,
               spf_result, dkim_result, dmarc_result, sender_ips, risk_score,
               content_json, geo_json
        FROM emails
        WHERE user_email = ? AND risk_score IS NOT NULL AND id IN ({placeholders})
    """, (user_email, *ids)).fetchall()
    conn.close()

    results = {}
    for row in rows:
        content = json.loads(row[12]) if row[12] else {}
        geo = json.loads(row[13]) if row[13] else []
        score = row[11]
        results[row[0]] = {
            "from": row[1],
            "subject": row[2],
            "date": row[3],
            "body_preview": (row[4] or "")[:200],
            "received": json.loads(row[5]) if row[5] else [],
            "authentication_results": row[6],
            "to": None,
            "spf": row[7],
            "dkim": row[8],
            "dmarc": row[9],
            "sender_ips": json.loads(row[10]) if row[10] else [],
            "geo": geo,
            "content": content,
            "risk": {
                "risk_score": score,
                "risk_level": "high" if score >= 60 else ("medium" if score >= 30 else "low"),
                **({k: v for k, v in content.get("ai", {}).items()} if isinstance(content, dict) and content.get("ai") else {}),
            },
        }
    return results

def get_cached_exact_count(user_email):
    """Returns (count, updated_at) tuple, or None if no cache exists yet."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT exact_count, updated_at FROM mailbox_count_cache WHERE user_email = ?",
        (user_email,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {"count": row[0], "updated_at": row[1]}

def set_cached_exact_count(user_email, count):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO mailbox_count_cache (user_email, exact_count, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_email) DO UPDATE SET
            exact_count=excluded.exact_count,
            updated_at=CURRENT_TIMESTAMP
    """, (user_email, count))
    conn.commit()
    conn.close()