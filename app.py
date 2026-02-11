# -*- coding: utf-8 -*-
import os
import json
import uuid
import threading
import subprocess
import sqlite3
import psutil
import shutil
import time
import re
import zipfile
import tempfile
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response, send_file, flash
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'data/hosting_panel.db'
app.config['ALLOWED_EXTENSIONS'] = {'py', 'js', 'zip'}
app.config['TEMP_FOLDER'] = 'temp'

# Initialize session
Session(app)

# Setup logging
if not os.path.exists('logs'):
    os.makedirs('logs')
file_handler = RotatingFileHandler('logs/hosting_panel.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Hosting Panel Startup')

# Create necessary directories
for folder in ['uploads', 'logs', 'data', 'temp']:
    os.makedirs(folder, exist_ok=True)

# --- Database Setup ---
def init_db():
    """Initialize database with required tables"""
    conn = get_db()
    c = conn.cursor()
    
    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            file_limit INTEGER DEFAULT 5,
            subscription_expiry DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    ''')
    
    # Scripts table
    c.execute('''
        CREATE TABLE IF NOT EXISTS scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            filetype TEXT NOT NULL,
            status TEXT DEFAULT 'stopped',
            pid INTEGER,
            upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_started DATETIME,
            last_stopped DATETIME,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Installation logs
    c.execute('''
        CREATE TABLE IF NOT EXISTS install_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            module_name TEXT NOT NULL,
            package_name TEXT,
            status TEXT NOT NULL,
            log TEXT,
            install_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # System logs
    c.execute('''
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            details TEXT,
            user_id INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create default admin user if not exists
    c.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if c.fetchone()[0] == 0:
        password_hash = generate_password_hash('admin123')
        c.execute(
            "INSERT INTO users (username, password_hash, role, file_limit) VALUES (?, ?, ?, ?)",
            ('admin', password_hash, 'admin', 9999)
        )
        app.logger.info('Default admin user created')
    
    conn.commit()
    conn.close()

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# --- Helper Functions ---
def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_user_folder(user_id):
    """Get user's upload folder"""
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
    os.makedirs(user_folder, exist_ok=True)
    return user_folder

def log_event(event, details=None, user_id=None):
    """Log system event"""
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO system_logs (event, details, user_id) VALUES (?, ?, ?)",
        (event, details, user_id)
    )
    conn.commit()
    conn.close()

# --- Authentication Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'warning')
            return redirect(url_for('login'))
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        conn.close()
        
        if user and user['role'] in ['admin', 'owner']:
            return f(*args, **kwargs)
        
        flash('Admin access required', 'danger')
        return redirect(url_for('dashboard'))
    return decorated_function

# --- Routes ---
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            # Update last login
            conn = get_db()
            c = conn.cursor()
            c.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user['id'],))
            conn.commit()
            conn.close()
            
            log_event('login', f'User {username} logged in', user['id'])
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('register.html')
        
        conn = get_db()
        c = conn.cursor()
        
        # Check if username exists
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        if c.fetchone():
            flash('Username already exists', 'danger')
            conn.close()
            return render_template('register.html')
        
        # Create user
        password_hash = generate_password_hash(password)
        c.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email)
        )
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    log_event('logout', f'User {session.get("username")} logged out', session.get('user_id'))
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user info
    conn = get_db()
    c = conn.cursor()
    
    c.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    user = dict(c.fetchone())
    
    # Get scripts count
    c.execute("SELECT COUNT(*) as count FROM scripts WHERE user_id = ?", (session['user_id'],))
    scripts_count = c.fetchone()['count']
    
    # Get running scripts
    c.execute("SELECT COUNT(*) as count FROM scripts WHERE user_id = ? AND status = 'running'", (session['user_id'],))
    running_scripts = c.fetchone()['count']
    
    # Get recent activity
    c.execute('''
        SELECT * FROM system_logs 
        WHERE user_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 10
    ''', (session['user_id'],))
    recent_activity = [dict(row) for row in c.fetchall()]
    
    conn.close()
    
    # System stats
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    system_stats = {
        'cpu': cpu_percent,
        'memory': {
            'percent': memory.percent,
            'used': memory.used // (1024 ** 3),  # GB
            'total': memory.total // (1024 ** 3)
        },
        'disk': {
            'percent': disk.percent,
            'used': disk.used // (1024 ** 3),  # GB
            'total': disk.total // (1024 ** 3)
        }
    }
    
    return render_template('dashboard.html', 
                         user=user, 
                         scripts_count=scripts_count,
                         running_scripts=running_scripts,
                         recent_activity=recent_activity,
                         system_stats=system_stats)

@app.route('/scripts')
@login_required
def scripts():
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''
        SELECT * FROM scripts 
        WHERE user_id = ? 
        ORDER BY upload_time DESC
    ''', (session['user_id'],))
    
    user_scripts = [dict(row) for row in c.fetchall()]
    
    # Get total scripts and limit
    c.execute("SELECT COUNT(*) as count FROM scripts WHERE user_id = ?", (session['user_id'],))
    current_count = c.fetchone()['count']
    
    c.execute("SELECT file_limit FROM users WHERE id = ?", (session['user_id'],))
    file_limit = c.fetchone()['file_limit']
    
    conn.close()
    
    return render_template('scripts.html', 
                         scripts=user_scripts,
                         current_count=current_count,
                         file_limit=file_limit)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        # Check file limit
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) as count FROM scripts WHERE user_id = ?", (session['user_id'],))
        current_count = c.fetchone()['count']
        c.execute("SELECT file_limit FROM users WHERE id = ?", (session['user_id'],))
        file_limit = c.fetchone()['file_limit']
        
        if current_count >= file_limit:
            flash(f'File limit reached ({current_count}/{file_limit})', 'danger')
            conn.close()
            return redirect(url_for('scripts'))
        
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            conn.close()
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'danger')
            conn.close()
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_ext = filename.rsplit('.', 1)[1].lower()
            
            # Save file
            user_folder = get_user_folder(session['user_id'])
            filepath = os.path.join(user_folder, filename)
            file.save(filepath)
            
            # Check for dangerous code
            if not check_code_security(filepath, file_ext):
                os.remove(filepath)
                flash('File contains dangerous code and was rejected', 'danger')
                conn.close()
                return redirect(url_for('scripts'))
            
            # Add to database
            c.execute('''
                INSERT INTO scripts (user_id, filename, filetype, status)
                VALUES (?, ?, ?, 'stopped')
            ''', (session['user_id'], filename, file_ext))
            
            conn.commit()
            conn.close()
            
            log_event('upload', f'Uploaded {filename}', session['user_id'])
            flash('File uploaded successfully!', 'success')
            return redirect(url_for('scripts'))
        
        flash('Invalid file type. Allowed: .py, .js, .zip', 'danger')
        conn.close()
    
    return render_template('upload.html')

@app.route('/script/<int:script_id>/start')
@login_required
def start_script(script_id):
    conn = get_db()
    c = conn.cursor()
    
    # Get script info
    c.execute("SELECT * FROM scripts WHERE id = ? AND user_id = ?", (script_id, session['user_id']))
    script = c.fetchone()
    
    if not script:
        flash('Script not found', 'danger')
        conn.close()
        return redirect(url_for('scripts'))
    
    if script['status'] == 'running':
        flash('Script is already running', 'warning')
        conn.close()
        return redirect(url_for('scripts'))
    
    # Start script
    user_folder = get_user_folder(session['user_id'])
    filepath = os.path.join(user_folder, script['filename'])
    
    try:
        if script['filetype'] == 'py':
            process = subprocess.Popen(
                ['python', filepath],
                cwd=user_folder,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )
        elif script['filetype'] == 'js':
            process = subprocess.Popen(
                ['node', filepath],
                cwd=user_folder,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )
        else:
            flash('Unsupported file type', 'danger')
            conn.close()
            return redirect(url_for('scripts'))
        
        # Update database
        c.execute('''
            UPDATE scripts 
            SET status = 'running', pid = ?, last_started = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (process.pid, script_id))
        
        conn.commit()
        conn.close()
        
        log_event('start_script', f'Started {script["filename"]}', session['user_id'])
        flash('Script started successfully!', 'success')
        
    except Exception as e:
        flash(f'Error starting script: {str(e)}', 'danger')
    
    return redirect(url_for('scripts'))

@app.route('/script/<int:script_id>/stop')
@login_required
def stop_script(script_id):
    conn = get_db()
    c = conn.cursor()
    
    # Get script info
    c.execute("SELECT * FROM scripts WHERE id = ? AND user_id = ?", (script_id, session['user_id']))
    script = c.fetchone()
    
    if not script:
        flash('Script not found', 'danger')
        conn.close()
        return redirect(url_for('scripts'))
    
    if script['status'] != 'running':
        flash('Script is not running', 'warning')
        conn.close()
        return redirect(url_for('scripts'))
    
    try:
        # Kill process
        if script['pid']:
            try:
                import signal
                os.kill(script['pid'], signal.SIGTERM)
            except:
                pass
        
        # Update database
        c.execute('''
            UPDATE scripts 
            SET status = 'stopped', last_stopped = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (script_id,))
        
        conn.commit()
        conn.close()
        
        log_event('stop_script', f'Stopped {script["filename"]}', session['user_id'])
        flash('Script stopped successfully!', 'success')
        
    except Exception as e:
        flash(f'Error stopping script: {str(e)}', 'danger')
    
    return redirect(url_for('scripts'))

@app.route('/script/<int:script_id>/delete')
@login_required
def delete_script(script_id):
    conn = get_db()
    c = conn.cursor()
    
    # Get script info
    c.execute("SELECT * FROM scripts WHERE id = ? AND user_id = ?", (script_id, session['user_id']))
    script = c.fetchone()
    
    if not script:
        flash('Script not found', 'danger')
        conn.close()
        return redirect(url_for('scripts'))
    
    try:
        # Stop if running
        if script['status'] == 'running' and script['pid']:
            try:
                import signal
                os.kill(script['pid'], signal.SIGTERM)
            except:
                pass
        
        # Delete file
        user_folder = get_user_folder(session['user_id'])
        filepath = os.path.join(user_folder, script['filename'])
        if os.path.exists(filepath):
            os.remove(filepath)
        
        # Delete from database
        c.execute("DELETE FROM scripts WHERE id = ?", (script_id,))
        
        conn.commit()
        conn.close()
        
        log_event('delete_script', f'Deleted {script["filename"]}', session['user_id'])
        flash('Script deleted successfully!', 'success')
        
    except Exception as e:
        flash(f'Error deleting script: {str(e)}', 'danger')
    
    return redirect(url_for('scripts'))

@app.route('/script/<int:script_id>/logs')
@login_required
def get_logs(script_id):
    # This would stream logs from a log file
    # For simplicity, we'll return recent output
    return jsonify({'logs': 'Logs would appear here...'})

@app.route('/install', methods=['GET', 'POST'])
@login_required
def install_package():
    if request.method == 'POST':
        package_name = request.form.get('package_name')
        package_type = request.form.get('package_type', 'pip')
        
        if not package_name:
            flash('Package name is required', 'danger')
            return redirect(url_for('install_package'))
        
        try:
            if package_type == 'pip':
                result = subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', package_name],
                    capture_output=True,
                    text=True,
                    check=False
                )
            elif package_type == 'npm':
                user_folder = get_user_folder(session['user_id'])
                result = subprocess.run(
                    ['npm', 'install', package_name],
                    capture_output=True,
                    text=True,
                    cwd=user_folder,
                    check=False
                )
            else:
                flash('Invalid package type', 'danger')
                return redirect(url_for('install_package'))
            
            # Log installation
            conn = get_db()
            c = conn.cursor()
            c.execute('''
                INSERT INTO install_logs (user_id, module_name, package_name, status, log)
                VALUES (?, ?, ?, ?, ?)
            ''', (session['user_id'], package_name, package_name, 
                  'success' if result.returncode == 0 else 'failed', 
                  result.stdout + result.stderr))
            conn.commit()
            conn.close()
            
            if result.returncode == 0:
                flash(f'Package {package_name} installed successfully!', 'success')
                log_event('install_package', f'Installed {package_name}', session['user_id'])
            else:
                flash(f'Failed to install package: {result.stderr}', 'danger')
            
        except Exception as e:
            flash(f'Error installing package: {str(e)}', 'danger')
        
        return redirect(url_for('install_package'))
    
    # Get installation history
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT * FROM install_logs 
        WHERE user_id = ? 
        ORDER BY install_time DESC 
        LIMIT 20
    ''', (session['user_id'],))
    install_history = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return render_template('install.html', install_history=install_history)

@app.route('/system/stats')
@login_required
def system_stats():
    """Get real-time system statistics"""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # Get running processes
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as count FROM scripts WHERE status = 'running'")
    running_scripts = c.fetchone()['count']
    conn.close()
    
    stats = {
        'cpu': cpu_percent,
        'memory': {
            'percent': memory.percent,
            'used': memory.used // (1024 ** 2),  # MB
            'total': memory.total // (1024 ** 2)
        },
        'disk': {
            'percent': disk.percent,
            'used': disk.used // (1024 ** 3),  # GB
            'total': disk.total // (1024 ** 3)
        },
        'running_scripts': running_scripts,
        'uptime': time.time() - psutil.boot_time(),
        'timestamp': datetime.now().isoformat()
    }
    
    return jsonify(stats)

@app.route('/console/stream')
@login_required
def console_stream():
    """Server-Sent Events for live console"""
    def generate():
        # This is a simplified version - in production, you'd stream from actual log files
        import random
        messages = [
            "System initialized...",
            "Checking dependencies...",
            "Starting services...",
            "Ready for commands",
            "Monitoring system resources..."
        ]
        
        for msg in messages:
            yield f"data: {json.dumps({'message': msg})}\n\n"
            time.sleep(2)
        
        while True:
            cpu = psutil.cpu_percent()
            memory = psutil.virtual_memory().percent
            yield f"data: {json.dumps({'cpu': cpu, 'memory': memory})}\n\n"
            time.sleep(5)
    
    return Response(generate(), mimetype='text/event-stream')

# --- Admin Routes ---
@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, email, role, file_limit, subscription_expiry, created_at FROM users ORDER BY created_at DESC")
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return render_template('admin_users.html', users=users)

@app.route('/admin/user/<int:user_id>/update', methods=['POST'])
@admin_required
def update_user(user_id):
    role = request.form.get('role')
    file_limit = request.form.get('file_limit')
    
    if role and file_limit:
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            UPDATE users 
            SET role = ?, file_limit = ? 
            WHERE id = ?
        ''', (role, int(file_limit), user_id))
        conn.commit()
        conn.close()
        
        flash('User updated successfully', 'success')
        log_event('update_user', f'Updated user {user_id}', session['user_id'])
    
    return redirect(url_for('admin_users'))

@app.route('/admin/system')
@admin_required
def admin_system():
    # Get all running processes
    running_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            running_processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    # Get system logs
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT sl.*, u.username 
        FROM system_logs sl 
        LEFT JOIN users u ON sl.user_id = u.id 
        ORDER BY timestamp DESC 
        LIMIT 100
    ''')
    system_logs = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return render_template('admin_system.html', 
                         running_processes=running_processes[:20],
                         system_logs=system_logs)

# --- Security Functions ---
def check_code_security(filepath, filetype):
    """Check code for dangerous commands"""
    try:
        if filetype == 'zip':
            return check_zip_security(filepath)
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        dangerous_patterns = [
            r'\bos\.system\b',
            r'\bsubprocess\.Popen\b',
            r'\beval\b',
            r'\bexec\b',
            r'rm\s+-rf',
            r'format\s+c:',
            r'rm\s+-rf\s+/',
            r'\b__import__\b',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                app.logger.warning(f'Dangerous pattern detected in {filepath}: {pattern}')
                return False
        
        return True
    except Exception as e:
        app.logger.error(f'Error in security check: {e}')
        return False

def check_zip_security(zip_path):
    """Check ZIP contents for security"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for file_info in zip_ref.infolist():
                if file_info.filename.endswith(('.py', '.js')):
                    with zip_ref.open(file_info.filename) as f:
                        try:
                            content = f.read().decode('utf-8', errors='ignore')
                            
                            dangerous_patterns = [
                                r'\bos\.system\b',
                                r'\bsubprocess\.Popen\b',
                                r'\beval\b',
                                r'rm\s+-rf\s+/',
                            ]
                            
                            for pattern in dangerous_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    app.logger.warning(f'Dangerous pattern in zip file {file_info.filename}: {pattern}')
                                    return False
                        except:
                            continue
        return True
    except Exception as e:
        app.logger.error(f'Error scanning zip: {e}')
        return False

# --- API Endpoints ---
@app.route('/api/scripts')
@login_required
def api_scripts():
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT id, filename, filetype, status, upload_time, last_started, last_stopped
        FROM scripts 
        WHERE user_id = ? 
        ORDER BY upload_time DESC
    ''', (session['user_id'],))
    
    scripts = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify({'scripts': scripts})

@app.route('/api/script/<int:script_id>/console')
@login_required
def api_script_console(script_id):
    # This would return console output for a specific script
    # For now, return mock data
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT filename FROM scripts WHERE id = ? AND user_id = ?", (script_id, session['user_id']))
    script = c.fetchone()
    conn.close()
    
    if script:
        logs = [
            f"[{datetime.now().strftime('%H:%M:%S')}] Starting {script['filename']}...",
            f"[{datetime.now().strftime('%H:%M:%S')}] Initializing modules...",
            f"[{datetime.now().strftime('%H:%M:%S')}] Ready for input"
        ]
        return jsonify({'logs': logs})
    
    return jsonify({'error': 'Script not found'}), 404

# --- Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {error}')
    return render_template('500.html'), 500

# --- Background Tasks ---
def cleanup_temp_files():
    """Clean up temporary files periodically"""
    while True:
        try:
            temp_dir = app.config['TEMP_FOLDER']
            for filename in os.listdir(temp_dir):
                filepath = os.path.join(temp_dir, filename)
                file_age = time.time() - os.path.getmtime(filepath)
                if file_age > 3600:  # 1 hour
                    os.remove(filepath)
                    app.logger.info(f'Cleaned up temp file: {filename}')
        except Exception as e:
            app.logger.error(f'Error cleaning temp files: {e}')
        
        time.sleep(300)  # Run every 5 minutes

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_temp_files, daemon=True)
cleanup_thread.start()

# Initialize database
init_db()

if __name__ == '__main__':
    # Hugging Face default port is 7860
    port = int(os.environ.get('PORT', 7860))
    app.run(host='0.0.0.0', port=port, debug=False)
