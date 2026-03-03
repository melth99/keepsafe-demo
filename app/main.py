from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
#from flask_limiter.util import get_remote_address
from functools import wraps
import os
import random
import secrets
import sqlite3
import time


app=Flask(__name__)
port="8000"
host="0.0.0.0"

DATABASE="keepsafe.db"

def get_email():
    return request.form.get("email", "unknown")

limiter=Limiter(
    get_email, 
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

CODE_EXPIRY_SECONDS= 300
SESSION_EXPIRY_SECONDS=1800
MAX_FAILED_ATTEMPTS= 3#you can workaround by making a new account
LOCKOUT_WINDOW_SECONDS=900


def get_db():
    if "db" not in g:
        g.db=sqlite3.connect(DATABASE)
        g.db.row_factory=sqlite3.Row
    return g.db




def init_db():
    db=sqlite3.connect(DATABASE)
    
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL)""")

    db.execute("""CREATE TABLE IF NOT EXISTS codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        code TEXT NOT NULL,
        used INTEGER DEFAULT 0,
        expires_at INTEGER NOT NULL)""")

    db.execute("""CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at INTEGER NOT NULL)""")

    db.execute("""CREATE TABLE IF NOT EXISTS failed_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        created_at INTEGER DEFAULT CURRENT_TIMESTAMP)""")
    db.commit()
    db.close()


@app.errorhandler(429)
def rate_limit_handler(e):
 
    print(f"\nRATE LIMITED")
    print(f"email:{get_email()}\n")
    return jsonify({"error":"Too many requests, slow down"}), 429

@app.errorhandler(500)
def internal_error(e):
    print(f"INTERNAL ERROR: {e}")
    return jsonify({"error": "internal server error"}), 500

@app.errorhandler(503)
def service_unavailable(e):
    print(f"SERVICE UNAVAILABLE: {e}")
    return jsonify({"error": "service unavailable"}), 503

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        
        auth_header=request.headers.get("Authorization", "")
        parts= auth_header.split()
        token= parts[1] if len(parts)==2 and parts[0].lower()=="bearer" else None
        
        if not token:
            return jsonify({"error":"unauthorized"}), 401
        db=get_db()
        row= db.execute(
            "SELECT user_id, expires_at FROM sessions WHERE token=?", (token,)
        ).fetchone()

        if not row:
            return jsonify({"error" :"invalid token"}), 401

        if time.time() > row["expires_at"]:
            db.execute("DELETE FROM sessions WHERE token=?", (token,))
            db.commit()
            print(f"SESSION EXPIRED token {token[:10]}...")
            return jsonify({"error":"session expired,please log in again"}), 401

        g.user_id=row["user_id"]
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def index():
    auth_header=request.headers.get("Authorization", "")
    parts=auth_header.split()
    token=parts[1] if len(parts) ==2 and parts[0].lower() =="bearer" else None

    if token:
        db= get_db()
        row=db.execute(
            "SELECT u.email FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token=?",
            (token,)
        ).fetchone()
        if row:
            return jsonify({"message" :f"logged in as:{row['email']}"}),200
    return jsonify({"message":"you are not logged in"}), 200


@app.route('/sign-up',methods=['POST'])
def sign_up():
    email=request.form.get("email")
    if not email:
        return jsonify({"error":"email needed!"}), 400

    db=get_db()
    try:
        db.execute("INSERT INTO users (email) VALUES (?)", (email,))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error":"user already exists!"}), 409

    return jsonify({"message":"user created!"}), 201


@app.route("/auth/code/request", methods=["POST"])
@limiter.limit("3 per hour")
def request_code():
    email= request.form.get("email")
    device_id= request.form.get("device_id")

    if not email or not device_id:
        return jsonify({"error":"email and device_id needed!"}), 400

    db= get_db()
    user=db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if not user:
        return jsonify({"error":"user not found!"}), 400

    code=f"{random.randint(0, 9999):04d}"
    expires_at=int(time.time()) + CODE_EXPIRY_SECONDS

    db.execute(
        "INSERT INTO codes (email, code, expires_at) VALUES (?, ?, ?)",
        (email, code, expires_at)
    )
    db.commit()

    print(f"Code for {email} :{code} (expires in 5 minutes)!")
    print(code)

    return jsonify({"message":"code sent", "code": code}), 200


@app.route("/auth/code/verify", methods=["POST"])
@limiter.limit("5 per minute")
def verify_code():
    code=request.form.get("code")
    device_id=request.form.get("device_id")

    if not code or not device_id:
        return jsonify({"error": "code and device_id needed for verification!"}), 400

    db =get_db()
    row =db.execute(
        "SELECT id, email, expires_at FROM codes WHERE code=? AND used=0", (code,)
    ).fetchone()

    if not row:
        # loging the failed attempt
        email=request.form.get("email", "unknown")
        db.execute("INSERT INTO failed_attempts (email, created_at) VALUES (?, ?)", (email, int(time.time())))
        db.commit()
        return jsonify({"error":"invalid/expired code!"}), 403

    cutoff=int(time.time()) - LOCKOUT_WINDOW_SECONDS
    fails=db.execute(
        "SELECT COUNT(*) as count FROM failed_attempts WHERE email=? AND created_at > ?",
        (row["email"], cutoff)
    ).fetchone()["count"]

    if fails >= MAX_FAILED_ATTEMPTS:
        print(f"ACCOUNT LOCKED\n{row['email']}\n{fails} failed attempts")
        return jsonify({"error" :"too many failed trys, try again in 15 min"}), 429

    if int(time.time()) > row["expires_at"]:
        db.execute("UPDATE codes SET used=1 WHERE id=?", (row["id"],))
        # expired code counts as a failedattempt
        db.execute("INSERT INTO failed_attempts (email, created_at) VALUES (?, ?)", (row["email"], int(time.time())))
        db.commit()
        return jsonify({"error":"code expired, request a new one with sign-up route"}), 403

    # failed attempts so lockout resets after a successful login with that same email
    db.execute("DELETE FROM failed_attempts WHERE email=?", (row["email"],))

    user=db.execute(
        "SELECT id FROM users WHERE email=?", (row["email"],)
    ).fetchone()

    db.execute("UPDATE codes SET used=1 WHERE id=?", (row["id"],))
    token=secrets.token_urlsafe(32)
    expires_at=int(time.time()) + SESSION_EXPIRY_SECONDS
    db.execute(
        "INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
        (user["id"], token, expires_at)
    )
    db.commit()


    return jsonify({
        "session_token":token,
        "expires_in":f" You have {SESSION_EXPIRY_SECONDS // 60} minutes"
    }), 200



@app.route('/sign-out', methods=['POST'])
@login_required
def sign_out():
    db=get_db()
    auth_header=request.headers.get("Authorization", "")
    parts=auth_header.split()
    token=parts[1] if len(parts)==2 and parts[0].lower()=="bearer" else ""
    db.execute("DELETE FROM sessions WHERE token=?", (token,))
    db.commit()
    return jsonify({"message":"signed user out"}), 200


@app.route("/file/<file_name>", methods=["POST"]) #uplaoding
@login_required
def upload_file(file_name):
    upload_path=f"uploads/{file_name}"

    if not os.path.exists(upload_path):
        return jsonify({"error" :f"{file_name} not found in /uploads"}), 404

    with open(upload_path, "rb") as f:
        data=f.read()

    folder=f"storage/{g.user_id}"
    os.makedirs(folder, exist_ok=True)

    with open(f"{folder}/{file_name}", "wb") as f:
        f.write(data)

    return jsonify({"message":"uploaded!", "file": file_name}), 200


@app.route("/file/<file_name>", methods=["GET"]) #this is to download and place in downloads folder
@login_required
def download_file(file_name):
    storage_path=f"storage/{g.user_id}/{file_name}"

    if not os.path.exists(storage_path):
        return jsonify({"error":"file not found!"}), 404

    with open(storage_path, "rb") as f:
        file_data=f.read()

    os.makedirs("downloads", exist_ok=True)
    with open(f"downloads/{file_name}", "wb") as f:
        f.write(file_data)

    return file_data, 200


init_db()

if __name__=='__main__':
    print(f"Starting server on http://{host}:{port}\n\n")
    print(f"POST http://{host}:{port}/sign-up\n")
    print(f"POST http://{host}:{port}/auth/code/request\n")
    print(f"POST http://{host}:{port}/auth/code/verify\n")
    print(f"POST http://{host}:{port}/sign-out\n")
    print(f"GET  http://{host}:{port}/file/<file_name>\n")
    print(f"POST http://{host}:{port}/file/<file_name>\n")
    print("enjoy this demo!")
    app.run(debug=True, port=port, host=host)