import sqlite3
conn = sqlite3.connect('emails.db')
count = conn.execute("SELECT COUNT(*) FROM emails WHERE user_email = 'venuprasaddvoid@gmail.com'").fetchone()[0]
rows = conn.execute("SELECT id, sender, risk_score, content_json FROM emails WHERE user_email = 'venuprasaddvoid@gmail.com' AND sender LIKE '%microsoft%' OR sender LIKE '%canva%'").fetchall()
print(f"Total count: {count}")
print(f"Microsoft/Canva rows found: {len(rows)}")
for r in rows:
    print(r)
