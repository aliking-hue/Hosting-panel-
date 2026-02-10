import sys
import os

# Add the current directory to Python path for module resolution
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
print(f"Python path: {sys.path}")
print(f"Current directory: {os.path.dirname(os.path.abspath(__file__))}")

from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
import sqlite3
import json
import time
import psutil
from datetime import datetime
from werkzeug.utils import secure_filename
import zipfile
import shutil
import tempfile
import threading
from functools import wraps
import uuid
import logging
from logging.handlers import RotatingFileHandler

# Try relative imports for local modules
try:
    print("Attempting to import local modules...")
    from . import auth
    from . import database
    from . import utils
    print("Local modules imported successfully")
    
    # Import specific functions
    from .auth import login_required
    from .database import init_db, get_db, get_stats, get_users, get_user_files, log_event
    from .utils import allowed_file, save_user_file, delete_user_file
    
except ImportError as e:
    print(f"Relative import error: {e}")
    print("Attempting direct import...")
    try:
        # Try direct import as fallback
        import auth
        import database
        import utils
        
        from auth import login_required
        from database import init_db, get_db, get_stats, get_users, get_user_files, log_event
        from utils import allowed_file, save_user_file, delete_user_file
        print("Direct import successful")
        
    except ImportError as e2:
        print(f"Direct import also failed: {e2}")
        print("Creating fallback functions...")
        
        # Create fallback functions
        def login_required(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                return f(*args, **kwargs)
            return decorated_function
        
        def init_db():
            print("Fallback init_db called")
            pass
        
        def get_db():
            print("Fallback get_db called")
            return None
        
        def get_stats():
            return {'total_users': 0, 'active_users': 0, 'total_files': 0}
        
        def get_users():
            return []
        
        def get_user_files(user_id):
            return []
        
        def log_event(level, message, source='web'):
            print(f"[{level.upper()}] {message}")
        
        def allowed_file(filename):
            return '.' in filename and \
                   filename.rsplit('.', 1)[1].lower() in {'py', 'js', 'zip'}
        
        def save_user_file(user_id, filename, file_path):
            print(f"Fallback: Saving file {filename} for user {user_id}")
            return True
        
        def delete_user_file(file_id):
            print(f"Fallback: Deleting file {file_id}")
            return True

# Set up absolute paths for Vercel
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(PROJECT_ROOT, 'templates')
STATIC_DIR = os.path.join(PROJECT_ROOT, 'static')

# Use /tmp for Vercel writable storage
UPLOADS_DIR = '/tmp/uploads'
LOGS_DIR = '/tmp/logs'
DATABASE_PATH = '/tmp/database.db'

print(f"BASE_DIR: {BASE_DIR}")
print(f"PROJECT_ROOT: {PROJECT_ROOT}")
print(f"TEMPLATE_DIR: {TEMPLATE_DIR}")
print(f"STATIC_DIR: {STATIC_DIR}")
print(f"DATABASE_PATH: {DATABASE_PATH}")
print(f"Files in current directory: {os.listdir(BASE_DIR)}")

# Create necessary directories in /tmp
try:
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    print("Created necessary directories in /tmp")
except Exception as e:
    print(f"Error creating directories: {e}")

# Initialize Flask app with absolute paths
try:
    app = Flask(__name__, 
                template_folder=TEMPLATE_DIR,
                static_folder=STATIC_DIR)
    
    app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')
    app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20MB limit
    app.config['UPLOAD_FOLDER'] = UPLOADS_DIR
    app.config['ALLOWED_EXTENSIONS'] = {'py', 'js', 'zip'}
    
    print(f"Flask app initialized with template folder: {app.template_folder}")
    print(f"Flask app initialized with static folder: {app.static_folder}")
    
except Exception as e:
    print(f"Error initializing Flask app: {e}")
    raise

# Setup logging
logging.basicConfig(level=logging.INFO)
try:
    handler = RotatingFileHandler(os.path.join(LOGS_DIR, 'app.log'), maxBytes=10000, backupCount=3)
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    print("Logging configured successfully")
except Exception as e:
    print(f"Error setting up logging: {e}")

# Try to initialize database with /tmp path
try:
    # Update database path in environment
    os.environ['DATABASE_PATH'] = DATABASE_PATH
    
    print("Initializing database at:", DATABASE_PATH)
    init_db()
    print("Database initialized successfully")
except Exception as e:
    print(f"Error initializing database: {e}")

# Mock script runner for Vercel (serverless-friendly)
class ScriptRunner:
    def __init__(self):
        self.running_scripts = {}
        self.script_logs = {}
        self.system_logs = []
    
    def simulate_run(self, file_path, file_type, user_id):
        """Simulate script execution"""
        script_id = str(uuid.uuid4())
        filename = os.path.basename(file_path)
        
        self.running_scripts[script_id] = {
            'id': script_id,
            'file': file_path,
            'filename': filename,
            'type': file_type,
            'user_id': user_id,
            'start_time': datetime.now(),
            'status': 'running'
        }
        
        # Generate simulated logs
        logs = [
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting {file_type.upper()} script: {filename}",
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Script ID: {script_id}",
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] User ID: {user_id}",
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Running in simulated environment...",
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Bot started successfully!",
        ]
        
        self.script_logs[script_id] = logs
        
        # Add to system logs
        self.add_system_log(f"Script started: {filename} (User: {user_id})", "info")
        
        # Simulate completion after delay
        def complete_script():
            time.sleep(30)  # Run for 30 seconds
            if script_id in self.running_scripts and self.running_scripts[script_id]['status'] == 'running':
                self.running_scripts[script_id]['status'] = 'completed'
                logs.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Script execution completed")
                self.add_system_log(f"Script completed: {filename}", "success")
        
        threading.Thread(target=complete_script, daemon=True).start()
        
        return script_id
    
    def stop_script(self, script_id):
        """Stop a running script"""
        if script_id in self.running_scripts:
            self.running_scripts[script_id]['status'] = 'stopped'
            filename = self.running_scripts[script_id]['filename']
            if script_id in self.script_logs:
                self.script_logs[script_id].append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Script stopped by user")
            
            self.add_system_log(f"Script stopped: {filename}", "warning")
            return True
        return False
    
    def get_logs(self, script_id):
        """Get script logs"""
        return self.script_logs.get(script_id, [])
    
    def get_running_scripts(self):
        """Get all running scripts"""
        return [s for s in self.running_scripts.values() if s['status'] == 'running']
    
    def add_system_log(self, message, level="info"):
        """Add system log"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'message': message,
            'source': 'system'
        }
        self.system_logs.append(log_entry)
        # Keep only last 1000 logs
        if len(self.system_logs) > 1000:
            self.system_logs = self.system_logs[-1000:]
        
        # Also log to file
        try:
            log_event(level, message, 'web')
        except:
            pass
        
        # Also print to console
        app.logger.info(f"{timestamp} [{level.upper()}] {message}")
    
    def get_system_logs(self, limit=100):
        """Get system logs"""
        return self.system_logs[-limit:]

script_runner = ScriptRunner()

# Add initial system log
script_runner.add_system_log("Bot Dashboard started", "info")

# Routes for HTML pages
@app.route('/')
@login_required
def index():
    """Dashboard home page"""
    try:
        stats = get_stats()
        running_scripts = script_runner.get_running_scripts()
        
        # Get system info for stats
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        memory_usage = memory.percent
        
        return render_template('index.html', 
                             stats=stats,
                             cpu_usage=cpu_usage,
                             memory_usage=memory_usage,
                             running_scripts=len(running_scripts))
    except Exception as e:
        app.logger.error(f"Error in index route: {e}")
        return render_template('error.html', error=str(e)), 500

@app.route('/files')
@login_required
def files_page():
    """File manager page"""
    try:
        db = get_db()
        if db:
            cursor = db.cursor()
            
            # Get all files with user info
            cursor.execute('''
                SELECT uf.*, u.username, u.user_id as telegram_id 
                FROM user_files uf
                LEFT JOIN users u ON uf.user_id = u.id
                ORDER BY uf.upload_date DESC
            ''')
            files = [dict(row) for row in cursor.fetchall()]
            
            # Get users for dropdown
            cursor.execute('SELECT id, username, user_id FROM users ORDER BY username')
            users = [dict(row) for row in cursor.fetchall()]
            
            db.close()
        else:
            files = []
            users = []
        
        return render_template('files.html', files=files, users=users)
    except Exception as e:
        app.logger.error(f"Error in files_page route: {e}")
        return render_template('error.html', error=str(e)), 500

@app.route('/users')
@login_required
def users_page():
    """User management page"""
    try:
        users = get_users()
        return render_template('users.html', users=users)
    except Exception as e:
        app.logger.error(f"Error in users_page route: {e}")
        return render_template('error.html', error=str(e)), 500

@app.route('/logs')
@login_required
def logs_page():
    """Terminal/logs page"""
    try:
        return render_template('logs.html')
    except Exception as e:
        app.logger.error(f"Error in logs_page route: {e}")
        return render_template('error.html', error=str(e)), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login page"""
    try:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            # Simple hardcoded admin credentials
            if username == 'admin' and password == os.environ.get('ADMIN_PASSWORD', 'admin123'):
                session['logged_in'] = True
                session['username'] = username
                script_runner.add_system_log(f"Admin logged in: {username}", "info")
                return redirect(url_for('index'))
            
            return render_template('login.html', error='Invalid credentials')
        
        return render_template('login.html')
    except Exception as e:
        app.logger.error(f"Error in login route: {e}")
        return render_template('error.html', error=str(e)), 500

@app.route('/logout')
def logout():
    """Logout admin"""
    try:
        script_runner.add_system_log(f"Admin logged out: {session.get('username', 'Unknown')}", "info")
        session.clear()
        return redirect(url_for('login'))
    except Exception as e:
        app.logger.error(f"Error in logout route: {e}")
        return redirect(url_for('login'))

# API Endpoints
@app.route('/api/stats')
@login_required
def api_stats():
    """Get system statistics"""
    try:
        stats = get_stats()
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_users': stats['total_users'],
                'active_users': stats['active_users'],
                'total_files': stats['total_files'],
                'running_scripts': len(script_runner.get_running_scripts()),
                'cpu_usage': cpu_usage,
                'memory_usage': memory.percent,
                'memory_total': memory.total // (1024 * 1024),  # MB
                'memory_used': memory.used // (1024 * 1024)     # MB
            }
        })
    except Exception as e:
        app.logger.error(f"Error in api_stats: {e}")
        script_runner.add_system_log(f"Error getting stats: {str(e)}", "error")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users')
@login_required
def api_users():
    """Get user list"""
    try:
        users = get_users()
        return jsonify({'success': True, 'users': users})
    except Exception as e:
        app.logger.error(f"Error in api_users: {e}")
        script_runner.add_system_log(f"Error getting users: {str(e)}", "error")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/user/<int:user_id>/toggle-ban', methods=['POST'])
@login_required
def toggle_ban_user(user_id):
    """Ban/Unban a user"""
    try:
        db = get_db()
        if not db:
            return jsonify({'success': False, 'error': 'Database not available'}), 500
            
        cursor = db.cursor()
        
        # Check if user is already banned
        cursor.execute('SELECT user_id, username, banned FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if user:
            new_status = 0 if user['banned'] else 1
            cursor.execute('UPDATE users SET banned = ? WHERE id = ?', (new_status, user_id))
            db.commit()
            
            action = 'banned' if new_status else 'unbanned'
            message = f"User {user['username']} (ID: {user['user_id']}) {action}"
            script_runner.add_system_log(message, "warning" if new_status else "success")
            
            return jsonify({'success': True, 'message': message})
        
        return jsonify({'success': False, 'error': 'User not found'}), 404
    except Exception as e:
        app.logger.error(f"Error in toggle_ban_user: {e}")
        script_runner.add_system_log(f"Error banning user: {str(e)}", "error")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/user/<int:user_id>/set-limit', methods=['POST'])
@login_required
def set_user_limit(user_id):
    """Set user file limit"""
    try:
        data = request.get_json()
        limit = data.get('limit')
        
        if not limit or not isinstance(limit, int) or limit < 0:
            return jsonify({'success': False, 'error': 'Invalid limit value'}), 400
        
        db = get_db()
        if not db:
            return jsonify({'success': False, 'error': 'Database not available'}), 500
        
        cursor = db.cursor()
        
        # Get user info for logging
        cursor.execute('SELECT username, user_id FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        cursor.execute('UPDATE users SET file_limit = ? WHERE id = ?', (limit, user_id))
        db.commit()
        
        if user:
            script_runner.add_system_log(f"Set file limit {limit} for {user['username']} (ID: {user['user_id']})", "info")
        
        return jsonify({'success': True, 'message': 'User limit updated'})
    except Exception as e:
        app.logger.error(f"Error in set_user_limit: {e}")
        script_runner.add_system_log(f"Error setting user limit: {str(e)}", "error")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/user/<int:user_id>/set-subscription', methods=['POST'])
@login_required
def set_user_subscription(user_id):
    """Set user subscription"""
    try:
        data = request.get_json()
        days = data.get('days', 30)
        
        db = get_db()
        if not db:
            return jsonify({'success': False, 'error': 'Database not available'}), 500
        
        cursor = db.cursor()
        
        # Calculate expiry date
        from datetime import timedelta
        expiry_date = datetime.now().date() if days == 0 else datetime.now().date()
        if days > 0:
            expiry_date = datetime.now().date() + timedelta(days=days)
        
        cursor.execute('UPDATE users SET subscription_expiry = ? WHERE id = ?', 
                      (expiry_date.isoformat(), user_id))
        db.commit()
        
        script_runner.add_system_log(f"Set subscription for user {user_id} for {days} days", "info")
        return jsonify({'success': True, 'message': 'Subscription updated'})
    except Exception as e:
        app.logger.error(f"Error in set_user_subscription: {e}")
        script_runner.add_system_log(f"Error setting subscription: {str(e)}", "error")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/files')
@login_required
def api_files():
    """Get all files"""
    try:
        db = get_db()
        if not db:
            return jsonify({'success': True, 'files': []})
        
        cursor = db.cursor()
        
        cursor.execute('''
            SELECT uf.*, u.username 
            FROM user_files uf
            LEFT JOIN users u ON uf.user_id = u.id
            ORDER BY uf.upload_date DESC
        ''')
        files = [dict(row) for row in cursor.fetchall()]
        db.close()
        
        return jsonify({'success': True, 'files': files})
    except Exception as e:
        app.logger.error(f"Error in api_files: {e}")
        script_runner.add_system_log(f"Error getting files: {str(e)}", "error")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle file upload"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        user_id = request.form.get('user_id', 1)  # Default to admin user
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        # Check file extension
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': 'File type not allowed. Only .py, .js, .zip allowed'}), 400
        
        # Save file
        filename = secure_filename(file.filename)
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
        os.makedirs(user_folder, exist_ok=True)
        file_path = os.path.join(user_folder, filename)
        file.save(file_path)
        
        # Handle ZIP files
        if filename.endswith('.zip'):
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    extract_path = os.path.join(user_folder, 'extracted_' + str(int(time.time())))
                    zip_ref.extractall(extract_path)
                    
                    # Find and process script files
                    script_files = []
                    for root, dirs, files in os.walk(extract_path):
                        for f in files:
                            if f.endswith(('.py', '.js')):
                                src_path = os.path.join(root, f)
                                dest_path = os.path.join(user_folder, f)
                                
                                # Avoid overwriting
                                counter = 1
                                while os.path.exists(dest_path):
                                    name, ext = os.path.splitext(f)
                                    dest_path = os.path.join(user_folder, f"{name}_{counter}{ext}")
                                    counter += 1
                                
                                shutil.move(src_path, dest_path)
                                script_files.append(os.path.basename(dest_path))
                    
                    # Cleanup extracted folder
                    shutil.rmtree(extract_path)
                    
                    # Save each script file
                    for script_file in script_files:
                        script_path = os.path.join(user_folder, script_file)
                        save_user_file(user_id, script_file, script_path)
                        script_runner.add_system_log(f"Extracted file: {script_file} for user {user_id}", "info")
                    
                    message = f"ZIP extracted: {len(script_files)} files"
            except Exception as e:
                return jsonify({'success': False, 'error': f'Error extracting ZIP: {str(e)}'}), 500
        else:
            # Save single file record to database
            save_user_file(user_id, filename, file_path)
            message = 'File uploaded successfully'
        
        script_runner.add_system_log(f"File uploaded: {filename} by user {user_id}", "success")
        
        return jsonify({
            'success': True,
            'message': message,
            'filename': filename,
            'path': file_path
        })
    except Exception as e:
        app.logger.error(f"Error in upload_file: {e}")
        script_runner.add_system_log(f"Error uploading file: {str(e)}", "error")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/file/<int:file_id>/delete', methods=['DELETE'])
@login_required
def delete_file(file_id):
    """Delete a file"""
    try:
        if delete_user_file(file_id):
            script_runner.add_system_log(f"File deleted: {file_id}", "warning")
            return jsonify({'success': True, 'message': 'File deleted successfully'})
        return jsonify({'success': False, 'error': 'File not found'}), 404
    except Exception as e:
        app.logger.error(f"Error in delete_file: {e}")
        script_runner.add_system_log(f"Error deleting file: {str(e)}", "error")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/file/<int:file_id>/run', methods=['POST'])
@login_required
def run_file(file_id):
    """Run a script file"""
    try:
        db = get_db()
        if not db:
            return jsonify({'success': False, 'error': 'Database not available'}), 500
        
        cursor = db.cursor()
        
        # Get file info
        cursor.execute('SELECT * FROM user_files WHERE id = ?', (file_id,))
        file_info = cursor.fetchone()
        
        if not file_info:
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        # Check if file exists
        if not os.path.exists(file_info['file_path']):
            return jsonify({'success': False, 'error': 'File not found on disk'}), 404
        
        # Simulate script execution
        script_id = script_runner.simulate_run(
            file_info['file_path'], 
            file_info['file_type'],
            file_info['user_id']
        )
        
        return jsonify({
            'success': True,
            'message': 'Script started (simulated)',
            'script_id': script_id
        })
    except Exception as e:
        app.logger.error(f"Error in run_file: {e}")
        script_runner.add_system_log(f"Error running script: {str(e)}", "error")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/script/<script_id>/stop', methods=['POST'])
@login_required
def stop_script(script_id):
    """Stop a running script"""
    try:
        if script_runner.stop_script(script_id):
            return jsonify({'success': True, 'message': 'Script stopped'})
        return jsonify({'success': False, 'error': 'Script not found'}), 404
    except Exception as e:
        app.logger.error(f"Error in stop_script: {e}")
        script_runner.add_system_log(f"Error stopping script: {str(e)}", "error")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scripts/running')
@login_required
def get_running_scripts():
    """Get all running scripts"""
    try:
        scripts = script_runner.get_running_scripts()
        return jsonify({'success': True, 'scripts': scripts})
    except Exception as e:
        app.logger.error(f"Error in get_running_scripts: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/logs')
@login_required
def get_logs():
    """Get system logs"""
    try:
        limit = request.args.get('limit', 100, type=int)
        logs = script_runner.get_system_logs(limit)
        
        # Format logs for terminal display
        formatted_logs = []
        for log in logs:
            timestamp = log['timestamp']
            level = log['level']
            message = log['message']
            
            # Add color coding based on level
            if level == 'error':
                formatted_logs.append(f'[{timestamp}] [ERROR] {message}')
            elif level == 'warning':
                formatted_logs.append(f'[{timestamp}] [WARNING] {message}')
            elif level == 'success':
                formatted_logs.append(f'[{timestamp}] [SUCCESS] {message}')
            else:
                formatted_logs.append(f'[{timestamp}] [INFO] {message}')
        
        return jsonify({'success': True, 'logs': formatted_logs})
    except Exception as e:
        app.logger.error(f"Error in get_logs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/file/<int:file_id>/download')
@login_required
def download_file(file_id):
    """Download a file"""
    try:
        db = get_db()
        if not db:
            return jsonify({'success': False, 'error': 'Database not available'}), 500
        
        cursor = db.cursor()
        cursor.execute('SELECT file_path, filename FROM user_files WHERE id = ?', (file_id,))
        file_info = cursor.fetchone()
        
        if not file_info or not os.path.exists(file_info['file_path']):
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        return send_file(file_info['file_path'], 
                        as_attachment=True, 
                        download_name=file_info['filename'])
    except Exception as e:
        app.logger.error(f"Error in download_file: {e}")
        script_runner.add_system_log(f"Error downloading file: {str(e)}", "error")
        return jsonify({'success': False, 'error': str(e)}), 500

# Health check endpoint for Vercel
@app.route('/health')
def health():
    return jsonify({
        'status': 'ok', 
        'timestamp': datetime.now().isoformat(),
        'database': os.path.exists(DATABASE_PATH),
        'uploads_dir': os.path.exists(UPLOADS_DIR),
        'templates_dir': os.path.exists(TEMPLATE_DIR),
        'files_in_api': os.listdir(BASE_DIR)
    })

# Error handler
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"500 Error: {error}")
    return render_template('error.html', error='Internal server error'), 500

# Static route for serving static files directly (for debugging)
@app.route('/debug-static/<path:filename>')
def debug_static(filename):
    return send_from_directory(STATIC_DIR, filename)

# This is required for Vercel
if __name__ == '__main__':
    try:
        print("Starting Flask app in development mode...")
        app.run(debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        print(f"Failed to start Flask app: {e}")
        raise
else:
    # This is for Vercel serverless
    print("Flask app initialized for Vercel")
    # Vercel expects the app object to be named 'app'
