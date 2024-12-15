import sqlite3

def init_db():
    conn = sqlite3.connect("eventsTrigger.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            trigger_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            trigger_type TEXT NOT NULL,
            schedule_time DATETIME DEFAULT NULL,
            interval INTEGER DEFAULT NULL,
            api_endpoint TEXT DEFAULT NULL,
            api_payload TEXT DEFAULT NULL,
            is_recurring BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active',
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS event_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trigger_id INTEGER,
        triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT,
        api_payload TEXT,
        is_test BOOLEAN,
        FOREIGN KEY(trigger_id) REFERENCES triggers(id)
    )
    ''')
    conn.commit()
    conn.close()


def get_db_connection():
    """Get a database connection."""
    conn = sqlite3.connect('eventsTrigger.db')
    conn.row_factory = sqlite3.Row
    return conn
