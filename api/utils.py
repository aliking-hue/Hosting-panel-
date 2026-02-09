import os
from datetime import datetime

ALLOWED_EXTENSIONS = {'py', 'js', 'zip'}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_user_file(user_id, filename, file_path):
    """Save file record to database"""
    from database import get_db
    
    file_type = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'unknown'
    size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO user_files 
        (user_id, filename, file_path, file_type, upload_date, size)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, filename, file_path, file_type, 
          datetime.now().isoformat(), size))
    conn.commit()
    conn.close()
    
    return cursor.lastrowid

def delete_user_file(file_id):
    """Delete file record and physical file"""
    from database import get_db
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get file info
    cursor.execute('SELECT file_path FROM user_files WHERE id = ?', (file_id,))
    file_info = cursor.fetchone()
    
    if not file_info:
        return False
    
    # Delete physical file
    try:
        if os.path.exists(file_info['file_path']):
            os.remove(file_info['file_path'])
    except:
        pass  # Continue even if file deletion fails
    
    # Delete database record
    cursor.execute('DELETE FROM user_files WHERE id = ?', (file_id,))
    conn.commit()
    conn.close()
    
    return True
