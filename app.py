import json
import re
import sqlite3
import hashlib
import random
import string
import base64
from flask import Flask, jsonify, request, g
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

DATABASE = 'database.db'

# Connection to the database
def get_db():
    if not hasattr(g, '_database'):
        g._database = sqlite3.connect(DATABASE)
    return g._database

# Creating dbt tables
def create_table():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            '''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            master_password TEXT NOT NULL,
            salt TEXT NOT NULL
            );''')
        cursor.execute(
            '''CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            account_id TEXT NOT NULL,
            account_username TEXT NOT NULL,
            account_password TEXT NOT NULL,
            comment TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
            );''')
        db.commit()
    except Exception as e:
        return "Dbt exists like- it do be there"

with app.app_context():
    create_table()

# Password complexity check
def check_password_complexity(password):
    if len(password) < 6:
        return "Weak password: at least 6 chars long"
    if not (re.search(r'[A-Z]', password) and
            re.search(r'[a-z]', password) and
            re.search(r'\d', password)):
        return "Weak password: must have uppercase and lower case letters + numbers"
    if not re.search(r'[!@#$%^&*()_+{}|:"<>?]', password):
        return "Mid... I demand more special characters!"
    return "Strong: your password is good enough, congrats"

# Generate salt
def generate_salt(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

# Encrypt password with AES
def encrypt_password(master_password, password):
    salt = generate_salt().encode()
    key = PBKDF2(master_password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(password.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return json.dumps({'iv': iv, 'ciphertext': ct, 'salt': base64.b64encode(salt).decode('utf-8')})

# Decrypt password with AES
def decrypt_password(master_password, json_input):
    try:
        b64 = json.loads(json_input)
        iv = base64.b64decode(b64['iv'])
        ct = base64.b64decode(b64['ciphertext'])
        salt = base64.b64decode(b64['salt'])
        key = PBKDF2(master_password, salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except (ValueError, KeyError):
        return None

# ROUTES
@app.route('/', methods=['GET'])
def default_route():
    return ""

@app.route('/register', methods=['POST'])
def create_user():
    try:
        user_data = request.json
        name = user_data.get('name')
        email = user_data.get('email')
        master_password = user_data.get('password')

        # Password complexity check
        password_requirements = check_password_complexity(master_password)
        if not password_requirements.startswith("Strong"):
            return jsonify({'message': password_requirements}), 400

        db = get_db()
        cursor = db.cursor()

        # Check if email exists
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({"message": "Email already exists"}), 400

        # Store encrypted master password
        salt = generate_salt()
        encrypted_master_password = encrypt_password(master_password, master_password)

        cursor.execute(
            "INSERT INTO users (name, email, master_password, salt) VALUES (?, ?, ?, ?)",
            (name, email, encrypted_master_password, salt)
        )
        db.commit()

        return jsonify({"message": "User registered successfully!"}), 201

    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route('/login', methods=['POST'])
def login_user():
    try:
        user_data = request.json
        email = user_data.get('email')
        master_password = user_data.get('password')

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT id, master_password, salt FROM users WHERE email = ?", (email,))
        user_record = cursor.fetchone()

        if user_record is None:
            return jsonify({"message": "User not found"}), 400

        user_id, encrypted_master_password, salt = user_record

        decrypted_master_password = decrypt_password(master_password, encrypted_master_password)

        if decrypted_master_password != master_password:
            return jsonify({"message": "Invalid email or password"}), 400

        return jsonify({"message": "Logged in successfully!", "user_id": user_id}), 200

    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route('/account', methods=['POST'])
def create_account():
    try:
        account_data = request.json
        user_id = account_data.get('user_id')
        master_password = account_data.get('master_password')
        account_id = account_data.get('account_id')
        account_username = account_data.get('account_username')
        account_password = account_data.get('account_password')
        comment = account_data.get('comment', '')

        db = get_db()
        cursor = db.cursor()

        # Retrieve the user's encrypted master password
        cursor.execute("SELECT master_password FROM users WHERE id = ?", (user_id,))
        user_record = cursor.fetchone()

        if user_record is None:
            return jsonify({"message": "User not found"}), 400

        encrypted_master_password = user_record[0]

        # Decrypt the master password
        decrypted_master_password = decrypt_password(master_password, encrypted_master_password)

        if decrypted_master_password != master_password:
            return jsonify({"message": "Invalid master password"}), 400

        # Encrypt the account password
        encrypted_account_password = encrypt_password(master_password, account_password)

        cursor.execute(
            "INSERT INTO accounts (user_id, account_id, account_username, account_password, comment) VALUES (?, ?, ?, ?, ?)",
            (user_id, account_id, account_username, encrypted_account_password, comment)
        )
        db.commit()

        return jsonify({"message": "Account created successfully!"}), 201

    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route('/accounts/<int:user_id>', methods=['GET'])
def get_accounts(user_id):
    try:
        master_password = request.headers.get('master_password')

        db = get_db()
        cursor = db.cursor()

        # Retrieve the user's encrypted master password
        cursor.execute("SELECT master_password FROM users WHERE id = ?", (user_id,))
        user_record = cursor.fetchone()

        if user_record is None:
            return jsonify({"message": "User not found"}), 400

        encrypted_master_password = user_record[0]

        # Decrypt the master password
        decrypted_master_password = decrypt_password(master_password, encrypted_master_password)

        if decrypted_master_password != master_password:
            return jsonify({"message": "Invalid master password"}), 400

        cursor.execute("SELECT account_id, account_username, account_password, comment FROM accounts WHERE user_id = ?", (user_id,))
        accounts = cursor.fetchall()

        account_list = []
        for account in accounts:
            decrypted_account_password = decrypt_password(master_password, account[2])
            account_list.append({
                'account_id': account[0],
                'account_username': account[1],
                'account_password': decrypted_account_password,
                'comment': account[3]
            })

        return jsonify(account_list), 200

    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
