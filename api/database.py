import sqlite3
import os
from datetime import datetime

# Use /tmp for Vercel writable storage
DATABASE_PATH = os.environ.get('DATABASE_PATH', '/tmp/database.db')

def get_db():
    """Get database connection"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"Error connecting to database at {DATABASE_PATH}: {e}")
        return None

def init_db():
    """Initialize database with required tables"""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
        
        conn = get_db()
        if not conn:
            return
        
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                user_id INTEGER UNIQUE,
                join_date TEXT,
                last_seen TEXT,
                subscription_expiry TEXT,
                file_limit INTEGER DEFAULT 5,
                banned INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0
            )
        ''')
        
        # User files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT,
                file_path TEXT,
                file_type TEXT,
                upload_date TEXT,
                size INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT,
                message TEXT,
                timestamp TEXT,
                source TEXT
            )
        ''')
        
        # Create admin user if not exists
        cursor.execute('''
            INSERT OR IGNORE INTO users 
            (username, user_id, join_date, file_limit, is_admin)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', 1, datetime.now().isoformat(), 999, 1))
        
        conn.commit()
        conn.close()
        print(f"Database initialized at {DATABASE_PATH}")
    except Exception as e:
        print(f"Error initializing database: {e}")

def get_stats():
    """Get system statistics"""
    try:
        conn = get_db()
        if not conn:
            return {'total_users': 0, 'active_users': 0, 'total_files': 0}
        
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) as count FROM users')
        total_users = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM users WHERE banned = 0')
        active_users = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM user_files')
        total_files = cursor.fetchone()['count']
        
        conn.close()
        
        return {
            'total_users': total_users,
            'active_users': active_users,
            'total_files': total_files
        }
    except Exception as e:
        print(f"Error getting stats: {e}")
        return {'total_users': 0, 'active_users': 0, 'total_files': 0}

# ... rest of the database functions remain ...
