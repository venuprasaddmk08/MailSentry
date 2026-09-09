# test edit 1
import sqlite3
conn = sqlite3.connect('emails.db')
total = conn.execute("SELECT COUNT(*) FROM emails WHERE user_email = 'venuprasaddvoid@gmail.com'").fetchone()[0]
unique_ids = conn.execute("SELECT COUNT(DISTINCT id) FROM emails WHERE user_email = 'venuprasaddvoid@gmail.com'").fetchone()[0]
print(f"Total rows: {total}, Unique IDs: {unique_ids}")
