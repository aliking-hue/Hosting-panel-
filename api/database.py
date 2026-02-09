import sqlite3
import os
from datetime import datetime

DATABASE_PATH = 'data/bot_data.db'

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with required tables"""
    os.makedirs('data', exist_ok=True)
    
    conn = get_db()
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

def get_stats():
    """Get system statistics"""
    conn = get_db()
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

def get_users():
    """Get all users"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.*, 
               COUNT(uf.id) as file_count,
               (SELECT COUNT(*) FROM user_files uf2 
                WHERE uf2.user_id = u.id AND uf2.file_type = 'py') as py_files,
               (SELECT COUNT(*) FROM user_files uf2 
                WHERE uf2.user_id = u.id AND uf2.file_type = 'js') as js_files
        FROM users u
        LEFT JOIN user_files uf ON u.id = uf.user_id
        GROUP BY u.id
        ORDER BY u.join_date DESC
    ''')
    
    users = []
    for row in cursor.fetchall():
        user = dict(row)
        # Calculate subscription status
        if user['subscription_expiry']:
            expiry = datetime.fromisoformat(user['subscription_expiry'])
            user['subscription_active'] = expiry > datetime.now()
            user['days_left'] = (expiry - datetime.now()).days if expiry > datetime.now() else 0
        else:
            user['subscription_active'] = False
            user['days_left'] = 0
        
        users.append(user)
    
    conn.close()
    return users

def get_user_files(user_id):
    """Get files for a specific user"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM user_files 
        WHERE user_id = ? 
        ORDER BY upload_date DESC
    ''', (user_id,))
    
    files = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return files

def log_event(level, message, source='web'):
    """Add log entry"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (level, message, timestamp, source)
        VALUES (?, ?, ?, ?)
    ''', (level, message, datetime.now().isoformat(), source))
    conn.commit()
    conn.close()
