import sqlite3
import os
from cryptography.fernet import Fernet
import hashlib
import csv
from datetime import datetime

DB_PATH = "secure_app.db"
KEY_PATH = "secret.key"

def add_access_column_if_missing():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("PRAGMA table_info(users)")
    columns = [info[1] for info in c.fetchall()]
    if "access" not in columns:
        c.execute("ALTER TABLE users ADD COLUMN access TEXT DEFAULT 'active'")
    conn.commit()
    conn.close()

def setup_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT,
                    role TEXT,
                    access TEXT DEFAULT 'active'
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    user TEXT,
                    action TEXT,
                    filename TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    conn.commit()
    conn.close()

def setup_and_initialize():
    setup_db()
    add_access_column_if_missing()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(password, hashed):
    return hash_password(password) == hashed

def login_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password, role, access FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()

    if result:
        hashed_pw, role, access = result
        if access != 'active':
            return False, "Account is blocked. Contact admin."
        if check_password(password, hashed_pw):
            return True, role
    return False, "Invalid credentials"

def register_user(username, password, role):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (username, hash_password(password), role, 'active'))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def load_key():
    if not os.path.exists(KEY_PATH):
        key = Fernet.generate_key()
        with open(KEY_PATH, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_PATH, "rb") as key_file:
            key = key_file.read()
    return key

def encrypt_file(filepath):
    key = load_key()
    fernet = Fernet(key)
    with open(filepath, "rb") as file:
        data = file.read()
    encrypted = fernet.encrypt(data)
    with open(filepath + ".enc", "wb") as file:
        file.write(encrypted)

def decrypt_file(filepath):
    key = load_key()
    fernet = Fernet(key)
    with open(filepath, "rb") as file:
        data = file.read()
    decrypted = fernet.decrypt(data)
    new_name = filepath.replace(".enc", "")
    with open(new_name, "wb") as file:
        file.write(decrypted)

def log_action(user, action, filename):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO logs VALUES (?, ?, ?, ?)", (user, action, filename, timestamp))
    conn.commit()
    conn.close()


def fetch_logs(username, role):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if role == 'admin':
        c.execute("SELECT user, action, filename, timestamp FROM logs ORDER BY timestamp DESC")
    else:
        c.execute("SELECT user, action, filename, timestamp FROM logs WHERE user=? ORDER BY timestamp DESC", (username,))
    logs = c.fetchall()
    conn.close()
    return logs


def change_user_password(username, old_pw, new_pw):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    result = c.fetchone()
    if not result:
        return False, "User not found."

    old_hashed = hash_password(old_pw)
    if result[0] != old_hashed:
        return False, "Old password incorrect."

    new_hashed = hash_password(new_pw)
    c.execute("UPDATE users SET password=? WHERE username=?", (new_hashed, username))
    conn.commit()
    conn.close()
    return True, "Password changed successfully."

def get_all_users_with_access():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, role, access FROM users ORDER BY username")
    users = c.fetchall()
    conn.close()
    return users

def update_user_access(username, role, access):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET role=?, access=? WHERE username=?", (role, access, username))
    conn.commit()
    conn.close()

def delete_user(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()

def get_user_statistics():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT role, COUNT(*) FROM users GROUP BY role")
    stats = c.fetchall()
    conn.close()
    return stats

def export_users_csv(filepath):
    users = get_all_users_with_access()
    with open(filepath, 'w', newline='', encoding='utf-8-sig') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Username', 'Role', 'Access'])
        for user in users:
            writer.writerow(user)


