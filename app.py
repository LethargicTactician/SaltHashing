import json
import re
import sqlite3
import hashlib
import random, string
from flask import Flask, jsonify, request, g

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
            salt NOT NULL,
            name text NOT NULL,
            email text NOT NULL,
            password text NOT NULL        
            );''') 
        db.commit()

    except Exception as e:
        return "Dbt exists like- it do be there"
    
with app.app_context():
    create_table()

#PW complexity stuff
def check_password_complexity(password):
    if len(password) < 6:
        return "Weak password: at least 6 chars long"
    
    if not (re.search (r'[A-Z]', password) and
            re.search (r'[a-z]', password) and
            re.search (r'\d', password)):
        return "Weak password: must have uppercase and lower case letters + numbers"
        
    if not re.search (r'[!@#$%^&*()_+{}|:"<>?]', password):
        return "Mid... I demand more special characters!"
    
    return "Strong: your password is good enough, congrats"

#Salting
def generate_salt(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))


 #ROUTES
@app.route('/', methods=['GET'])
def default_route():
    return ""

@app.route('/register', methods=['POST'])
def create_user():
    try:
        user_data = request.json
        name = user_data.get('name')
        email = user_data.get('email')
        password = user_data.get('password')

        # Password complexity check
        password_requirements = check_password_complexity(password)
        if not password_requirements.startswith("Strong"):
            return jsonify({'message': password_requirements}), 400

        db = get_db()
        cursor = db.cursor()

        # Check if email exists
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({"message": "Email already exists"}), 400

        salt = generate_salt()

        # Concatenate salt and password, then hash
        salted_password = password + salt
        hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()

        # Store
        cursor.execute(
            "INSERT INTO users (name, email, salt, password) VALUES (?, ?, ?, ?)",
            (name, email, salt, hashed_password)
        )
        db.commit()

        return jsonify({"message": "User registered successfully!"}), 201

    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


@app.route('/login', methods=['POST', 'GET'])
def login_user():
    try:
        user_data = request.json
        email = user_data.get('email')
        password = user_data.get('password')

        db = get_db()
        cursor = db.cursor()

        # Retrieve the user's salt and hashed password from the database
        cursor.execute("SELECT salt, password FROM users WHERE email = ?", (email,))
        user_record = cursor.fetchone()

        if user_record is None:
            return jsonify({"message": "User not found"}), 400

        salt, stored_hashed_password = user_record

        # Concatenate the salt with the provided password
        salted_password = password + salt

        # Hash the concatenated result
        hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()

        # Compare the hashed password with the stored hashed password
        if hashed_password != stored_hashed_password:
            return jsonify({"message": "Invalid email or password"}), 400

        return jsonify({"message": "Logged in successfully!"}), 200

    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500



#UPDAE HERE
@app.route('/update', methods=['PATCH'])
def update_user():
    try:
        user_data = request.json
        email = user_data.get('email')
        current_password = user_data.get('password')
        new_password = user_data.get('new_pass')

        # Password complexity check
        password_requirements = check_password_complexity(new_password)
        if not password_requirements.startswith("Strong"):
            return jsonify({'message': password_requirements}), 400

        db = get_db()
        cursor = db.cursor()

        # Retrieve the user's salt and hashed password from the database
        cursor.execute("SELECT salt, password FROM users WHERE email = ?", (email,))
        user_record = cursor.fetchone()

        if user_record is None:
            return jsonify({"message": "User not found"}), 400

        salt, stored_hashed_password = user_record

        # Concatenate the salt with the provided current password
        salted_current_password = current_password + salt

        # Hash the concatenated result
        hashed_current_password = hashlib.sha256(salted_current_password.encode()).hexdigest()

        # Verify the current password
        if hashed_current_password != stored_hashed_password:
            return jsonify({"message": "Incorrect current password"}), 400

        # Generate a new salt for the new password
        new_salt = generate_salt()

        # Concatenate the new salt with the new password
        salted_new_password = new_password + new_salt

        # Hash the concatenated result
        hashed_new_password = hashlib.sha256(salted_new_password.encode()).hexdigest()

        # Update the user's password and salt in the database
        cursor.execute(
            "UPDATE users SET salt = ?, password = ? WHERE email = ?",
            (new_salt, hashed_new_password, email)
        )
        db.commit()

        return jsonify({"message": "Password updated successfully!"}), 200

    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500




if __name__ == '__main__':
    app.run(debug=True)

