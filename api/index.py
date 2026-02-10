from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import os
import sqlite3
import psutil
from datetime import datetime
from werkzeug.utils import secure_filename
import json
from functools import wraps
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask with absolute paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
TEMPLATE_DIR = os.path.join(PROJECT_ROOT, 'templates')
STATIC_DIR = os.path.join(PROJECT_ROOT, 'static')

# Use /tmp for writable storage on Vercel
UPLOADS_DIR = '/tmp/uploads'
DATABASE_PATH = '/tmp/database.db'

# Create directories if they don't exist
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)

# Initialize Flask app
app = Flask(__name__, 
           template_folder=TEMPLATE_DIR,
           static_folder=STATIC_DIR)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
app.config['UPLOAD_FOLDER'] = UPLOADS_DIR

logger.info(f"Template folder: {TEMPLATE_DIR}")
logger.info(f"Static folder: {STATIC_DIR}")
logger.info(f"Database path: {DATABASE_PATH}")
logger.info(f"Uploads folder: {UPLOADS_DIR}")

# Database initialization
def init_db():
    """Initialize the SQLite database"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                telegram_id INTEGER UNIQUE,
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
                filename TEXT NOT NULL,
                file_path TEXT,
                file_type TEXT,
                upload_date TEXT,
                size INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Add admin user if not exists
        cursor.execute('''
            INSERT OR IGNORE INTO users 
            (username, telegram_id, join_date, file_limit, is_admin)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', 1, datetime.now().isoformat(), 999, 1))
        
        # Add some sample users for demo
        cursor.execute('''
            INSERT OR IGNORE INTO users 
            (username, telegram_id, join_date, file_limit, is_admin, subscription_expiry)
            VALUES 
            ('john_doe', 12345678, '2024-01-15', 10, 0, '2024-12-31'),
            ('jane_smith', 87654321, '2024-02-20', 5, 0, NULL),
            ('premium_user', 11223344, '2024-03-10', 50, 0, '2024-12-31')
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")

# Initialize database on startup
init_db()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
@login_required
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Simple hardcoded credentials
        if username == 'admin' and password == os.environ.get('ADMIN_PASSWORD', 'admin123'):
            session['logged_in'] = True
            session['username'] = username
            logger.info(f"Admin logged in: {username}")
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    return redirect(url_for('login'))

# API Endpoints
@app.route('/api/system-stats')
@login_required
def system_stats():
    """Get system statistics"""
    try:
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        return jsonify({
            'success': True,
            'cpu_usage': cpu_usage,
            'memory_usage': memory.percent,
            'memory_total': memory.total // (1024 * 1024),  # MB
            'memory_used': memory.used // (1024 * 1024),    # MB
            'disk_usage': psutil.disk_usage('/').percent if hasattr(psutil, 'disk_usage') else 0
        })
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return jsonify({
            'success': True,
            'cpu_usage': 0,
            'memory_usage': 0,
            'memory_total': 0,
            'memory_used': 0,
            'disk_usage': 0,
            'simulated': True
        })

@app.route('/api/users')
@login_required
def get_users():
    """Get all users from database"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT *, 
                   (SELECT COUNT(*) FROM user_files WHERE user_id = users.id) as file_count
            FROM users 
            ORDER BY join_date DESC
        ''')
        
        users = []
        for row in cursor.fetchall():
            user = dict(row)
            
            # Calculate subscription status
            if user['subscription_expiry']:
                try:
                    expiry_date = datetime.fromisoformat(user['subscription_expiry'])
                    user['subscription_active'] = expiry_date > datetime.now()
                    if user['subscription_active']:
                        user['days_left'] = (expiry_date - datetime.now()).days
                    else:
                        user['days_left'] = 0
                except:
                    user['subscription_active'] = False
                    user['days_left'] = 0
            else:
                user['subscription_active'] = False
                user['days_left'] = 0
            
            users.append(user)
        
        conn.close()
        
        return jsonify({'success': True, 'users': users})
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/user/<int:user_id>/toggle-ban', methods=['POST'])
@login_required
def toggle_ban_user(user_id):
    """Ban/Unban a user"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Check current ban status
        cursor.execute('SELECT banned FROM users WHERE id = ?', (user_id,))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        current_status = result[0]
        new_status = 0 if current_status else 1
        
        cursor.execute('UPDATE users SET banned = ? WHERE id = ?', (new_status, user_id))
        conn.commit()
        conn.close()
        
        action = 'banned' if new_status else 'unbanned'
        logger.info(f"User {user_id} {action}")
        
        return jsonify({'success': True, 'message': f'User {action} successfully'})
    except Exception as e:
        logger.error(f"Error toggling ban: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/files')
@login_required
def get_files():
    """Get all files from uploads directory"""
    try:
        files = []
        total_size = 0
        
        if os.path.exists(UPLOADS_DIR):
            for root, dirs, filenames in os.walk(UPLOADS_DIR):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    try:
                        stat = os.stat(filepath)
                        files.append({
                            'name': filename,
                            'path': filepath,
                            'size': stat.st_size,
                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'user_folder': os.path.basename(os.path.dirname(filepath))
                        })
                        total_size += stat.st_size
                    except:
                        continue
        
        # Sort by modification time (newest first)
        files.sort(key=lambda x: x['modified'], reverse=True)
        
        return jsonify({
            'success': True,
            'files': files,
            'total_files': len(files),
            'total_size': total_size
        })
    except Exception as e:
        logger.error(f"Error getting files: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/file/delete', methods=['POST'])
@login_required
def delete_file():
    """Delete a file"""
    try:
        data = request.get_json()
        filepath = data.get('path')
        
        if not filepath:
            return jsonify({'success': False, 'error': 'No file specified'}), 400
        
        # Security check: ensure file is within uploads directory
        if not filepath.startswith(UPLOADS_DIR):
            return jsonify({'success': False, 'error': 'Invalid file path'}), 400
        
        if os.path.exists(filepath):
            os.remove(filepath)
            logger.info(f"File deleted: {filepath}")
            
            # Also remove from database if it exists
            try:
                conn = sqlite3.connect(DATABASE_PATH)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM user_files WHERE file_path = ?', (filepath,))
                conn.commit()
                conn.close()
            except:
                pass
            
            return jsonify({'success': True, 'message': 'File deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'File not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stats')
@login_required
def get_stats():
    """Get dashboard statistics"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get user stats
        cursor.execute('SELECT COUNT(*) FROM users')
        total_users = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM users WHERE banned = 0')
        active_users = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM users WHERE subscription_expiry IS NOT NULL AND subscription_expiry > date("now")')
        premium_users = cursor.fetchone()[0]
        
        # Get file stats from database
        cursor.execute('SELECT COUNT(*), COALESCE(SUM(size), 0) FROM user_files')
        db_files = cursor.fetchone()
        db_file_count = db_files[0] if db_files else 0
        db_total_size = db_files[1] if db_files else 0
        
        conn.close()
        
        # Get actual files from disk
        disk_files = []
        disk_file_count = 0
        disk_total_size = 0
        
        if os.path.exists(UPLOADS_DIR):
            for root, dirs, filenames in os.walk(UPLOADS_DIR):
                disk_file_count += len(filenames)
                for filename in filenames:
                    try:
                        filepath = os.path.join(root, filename)
                        disk_total_size += os.path.getsize(filepath)
                    except:
                        continue
        
        return jsonify({
            'success': True,
            'stats': {
                'total_users': total_users,
                'active_users': active_users,
                'banned_users': total_users - active_users,
                'premium_users': premium_users,
                'db_file_count': db_file_count,
                'db_total_size': db_total_size,
                'disk_file_count': disk_file_count,
                'disk_total_size': disk_total_size
            }
        })
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle file upload"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        # Secure filename
        filename = secure_filename(file.filename)
        
        # Create user folder (use admin as default)
        user_folder = os.path.join(UPLOADS_DIR, 'admin')
        os.makedirs(user_folder, exist_ok=True)
        
        filepath = os.path.join(user_folder, filename)
        file.save(filepath)
        
        # Save to database
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO user_files 
            (user_id, filename, file_path, file_type, upload_date, size)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            1,  # admin user ID
            filename,
            filepath,
            os.path.splitext(filename)[1][1:].lower() if '.' in filename else 'unknown',
            datetime.now().isoformat(),
            os.path.getsize(filepath)
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"File uploaded: {filename}")
        
        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'filename': filename
        })
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Health check endpoint
@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'database': os.path.exists(DATABASE_PATH),
        'uploads_dir': os.path.exists(UPLOADS_DIR)
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

# This is required for Vercel
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
else:
    # For Vercel serverless
    pass
