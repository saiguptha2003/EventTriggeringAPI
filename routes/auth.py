from flask import Blueprint, request, jsonify,session
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_db_connection
from utils.jwtToken import create_token

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    print(username, password)
    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"message": "Username already exists"}), 409
    finally:
        conn.close()

    return jsonify({"message": "User registered successfully"}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user["password"], password):
        session["user_id"] = user[0]
        session["username"] = username
        token = create_token(username,additional_claims={"userid":user[0]})
        return jsonify({"message": "Login successful", "token": token,'user_id':session['user_id']}), 200
    else:
        return jsonify({"message": "Invalid username or password"}), 401
