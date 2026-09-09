import sqlite3
conn = sqlite3.connect('emails.db')
conn.execute("DELETE FROM emails WHERE user_email = 'venuprasaddvoid@gmail.com'")
conn.commit()
print("Reset done")
