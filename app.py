import json
import sqlite3
import hashlib
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
    #connect frfr on skibidi
    try:
        db = get_db() #method above
        cursor = db.cursor() # get the database cursor / writer
        cursor.execute(
            '''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name text NOT NULL,
            email text NOT NULL,
            password text NOT NULL        
            );''') 
        db.commit()

    except Exception as e:
        return "Dbt exists like- it do be there"
    
# Initialize the database table
with app.app_context():
    create_table()


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
        password = user_data.get('password')
    # Parse user json information
        db = get_db()
        cursor = db.cursor()

    # check if email exists
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()

        if existing_user: 
            return jsonify({"message": "Email already exixts"}), 400

    # hash password - sha256

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

    #naew user instance cus we aint callin it lol     
    # store in db
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
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
        password = user_data.get('password')

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        
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

