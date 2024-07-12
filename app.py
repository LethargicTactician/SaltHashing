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
            salted_key NOT NULL,
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
def randomword(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))

 #ROUTES
@app.route('/', methods=['GET'])
def default_route():
    return ""

@app.route('/register', methods=['POST'])
def create_user():
    # Get the user json information
    try:
        user_data = request.json
        name = user_data.get('name')
        email = user_data.get('email')
        salt_key = user_data.get('salted_key')
        password = user_data.get('password')
        real_pw = password+salt_key

    # password complexity thing
        password_requiremnts = check_password_complexity(password)
        if not password_requiremnts.startswith("Strong"):
            return jsonify({'message': password_requiremnts}), 400
    
    # Parse user json information
        db = get_db()
        cursor = db.cursor()

    # check if email exists
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()

        if existing_user: 
            return jsonify({"message": "Email already exixts"}), 400
        
        #add salt to the pw entered and store as salt


    # hash password - sha256

        hashed_password = hashlib.sha256(real_pw.encode()).hexdigest()

    #naew user instance cus we aint callin it lol     
    # store in db
        cursor.execute(
            "INSERT INTO users (name, email, salt, password) VALUES (?, ?, ?)",
            (name, email, hashed_password)
        )
        db.commit()
    # return 201 response saying created
        return jsonify({"message": "a person was born!"}), 201
    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route('/login', methods=['POST', 'GET'])
def login_user():
    # get the user json info
    # parse the son info
    # check if email exists
    # check if password is correct
    # set the user instance to that
    try:
        user_data = request.json
        email = user_data.get('email')
        salt_key = user_data.get('salted_key')
        password = user_data.get('password')
        

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        
        #when you login you get the salt strored in the dbt and 
        #join that with the JSON that the person entered in the pw and then you compare both hashes



        #password thing compare thing
        hash_password = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, hash_password))

        intruder = cursor.fetchone()

        if intruder is None:
            return jsonify({"message": "NUH UH THIS AINT U"}), 400

        return jsonify ({"message": "Logged innn!"}), 200
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
        password = user_data.get('password')
        new_pass = user_data.get('new_pass')


        # password complexity thing
        password_requiremnts = check_password_complexity(new_pass)
        if not password_requiremnts.startswith("Strong"):
            return jsonify({'message': password_requiremnts}), 400
        

        db = get_db()
        cursor = db.cursor()

        hash_password = hashlib.sha256(password.encode()).hexdigest()

        cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, hash_password))
        email_verification = cursor.fetchone()
        if email_verification is None:
            return jsonify ({"message": "email doesnt exist lol"}), 400      

        hash_new_pass = hashlib.sha256(new_pass.encode()).hexdigest()
        cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hash_new_pass, email)) 
        db.commit()
        

        return jsonify({"message": "User updated"}), 200
    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500



if __name__ == '__main__':
    app.run(debug=True)

