import datetime
from flask_mail import Message
from bson import ObjectId
from flask import Blueprint, json, redirect, request, jsonify, session, url_for
import jwt
import urllib

import requests
from functions import decode_token
from DB.db import STUDY_USER_collection
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from extension import mail
from functions import generate_token
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
import os

load_dotenv()  # load from .env

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
FRONTEND_CALLBACK = os.getenv("FRONTEND_CALLBACK")
JWT_SECRET = os.getenv("JWT_SECRET")



bcrypt = Bcrypt()
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('firstName')
    last_name = data.get('lastName')

    if STUDY_USER_collection.find_one({'email': email}):
        return jsonify({'success': False, 'error': 'Email already exists'}), 400

    hashed_pw = generate_password_hash(password)
    user_id =STUDY_USER_collection.insert_one({
        'email': email,
        'password': hashed_pw,
        'firstName': first_name,
        'lastName': last_name,
        'login_type': 'gmail',
        'createdAt': datetime.datetime.utcnow()
    }).inserted_id

    token = generate_token(user_id)
    user =STUDY_USER_collection.find_one({'_id': user_id})
    user_data = {
        'id': str(user['_id']),
        'email': user['email'],
        'firstName': user['firstName'],
        'lastName': user['lastName'],
        'createdAt': user['createdAt'].isoformat()
    }

    return jsonify({'success': True, 'data': {'user': user_data, 'token': token}})

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = STUDY_USER_collection.find_one({'email': email})

    if user:
        if user["login_type"]=="google":
            return jsonify({'success': False, 'error': 'Your account is registered using google login. Try logging using Google Signin '}), 401




    if not user or not check_password_hash(user['password'], password):
        return jsonify({'success': False, 'error': 'Invalid email or password'}), 401

    token = generate_token(user['_id'])
    user_data = {
        'id': str(user['_id']),
        'email': user['email'],
        'firstName': user['firstName'],
        'lastName': user['lastName'],
        'createdAt': user['createdAt'].isoformat()
    }

    return jsonify({'success': True, 'data': {'user': user_data, 'token': token}})

@auth_bp.route('/logout', methods=['POST'])
def logout():
    return jsonify({'success': True, 'message': 'Successfully logged out'})




@auth_bp.route('/me', methods=['GET'])
def get_current_user():
    auth_header = request.headers.get('Authorization')
    print(auth_header)
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({'success': False, 'error': 'Invalid or missing token'}), 401

    token = auth_header.split(" ")[1]
    print(token)
    try:
        user_id = decode_token(token)
    except Exception as err:
        print(err)
    print(user_id)
    if not user_id:
        return jsonify({'success': False, 'error': 'Invalid or expired token'}), 401

    user = STUDY_USER_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    user_data = {
        'id': str(user['_id']),
        'email': user['email'],
        'firstName': user['firstName'],
        'lastName': user['lastName'],
        'createdAt': user['createdAt'].isoformat()
    }

    return jsonify({'success': True, 'data': {'user': user_data}})

serializer = URLSafeTimedSerializer("Dheeraj@2006")

@auth_bp.route("/request-reset", methods=["POST"])
def request_reset():
    data = request.json
    email = data.get("email")

    if  not STUDY_USER_collection.find_one({'email': email}):
        return jsonify({'success': False, 'error': 'Account not  exists'}), 400

    token = serializer.dumps(email, salt='password-reset-salt')
    # reset_url = url_for('auth.reset_password', token=token, _external=True)
    reset_url=f"https://georgia.registrarnegocio.com/auth/reset-password/?token={token}"
    msg = Message("Password Reset Request", sender="business@registrarnegocio.com", recipients=[email])
    msg.body = f"Click here to reset your password: {reset_url}"
    mail.send(msg)

    return jsonify({"message": "Reset email sent"}), 200

@auth_bp.route("/reset-password/<token>", methods=["POST","GET"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        return jsonify({"message": "Invalid or expired token"}), 400

    data = request.json
    new_password = data.get("new_password")

    if not new_password:
        return jsonify({"message": "New password is required"}), 400

    hashed_password = generate_password_hash(new_password)

    result = STUDY_USER_collection.update_one(
        {"email": email},
        {"$set": {"password": hashed_password}}
    )

    if result.modified_count == 0:
        return jsonify({"message": "Password update failed"}), 500

    return jsonify({"message": "Password reset successful"}), 200



# === Google Sign Route ===
@auth_bp.route('/googleauth/sign')
def google_sign():
    mode = request.args.get("mode", "login")
    session['mode'] = mode
    oauth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        + urllib.parse.urlencode({
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "prompt": "consent",
        })
    )
    print("Redirecting to Google:", oauth_url)
    print("Using redirect_uri:", REDIRECT_URI)

    return redirect(oauth_url)

# === Google Callback Route ===
@auth_bp.route('googleauth/callback')
def google_callback():
    
    code = request.args.get("code")
    mode = session.get("mode", "login")
    print(code)
    if not code:
        return redirect(f"{FRONTEND_CALLBACK}?success=false&error=Missing+authorization+code")

    token_res = requests.post("https://oauth2.googleapis.com/token", data={
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    })

    if token_res.status_code != 200:
        return redirect(f"{FRONTEND_CALLBACK}?success=false&error=Token+exchange+failed")

    tokens = token_res.json()
    id_token_data = jwt.decode(tokens["id_token"], options={"verify_signature": False})

    email = id_token_data.get("email")
    name = id_token_data.get("name")
    sub = id_token_data.get("sub")
    first_name = name.split(" ")[0]
    last_name = " ".join(name.split(" ")[1:]) if len(name.split(" ")) > 1 else ""

    user = STUDY_USER_collection.find_one({"email": email})

    if user:
        if user.get("login_type") == "gmail":
            return redirect(f"{FRONTEND_CALLBACK}?success=false&error=This+account+was+created+with+email+and+password.+Please+login+with+those+credentials.")
    else:
        user_id = STUDY_USER_collection.insert_one({
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "google_id": sub,
            "login_type": "google",
            "createdAt": datetime.datetime.utcnow()
        }).inserted_id
        user = STUDY_USER_collection.find_one({"_id": user_id})

    token = generate_token(user["_id"])
    user_data = {
        "id": str(user["_id"]),
        "email": user["email"],
        "firstName": user.get("firstName"),
        "lastName": user.get("lastName"),
        "createdAt": user["createdAt"].isoformat()
    }

    return redirect(
        f"{FRONTEND_CALLBACK}?success=true"
        f"&user={urllib.parse.quote(json.dumps(user_data))}"
        f"&token={token}"
    )
