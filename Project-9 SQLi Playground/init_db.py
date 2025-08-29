import sqlite3

DB = 'data.db'

def init():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    ''')

    try:
        c.execute("INSERT INTO users (username, password) VALUES ('alice', 'alicepass')")
        c.execute("INSERT INTO users (username, password) VALUES ('bob', 'bobpass')")
    except Exception:
        pass

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init()
    print('DB initialized (data.db)')
