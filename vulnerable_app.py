"""
vulnerable_app.py
INTENTIONALLY VULNERABLE FOR TESTING PURPOSES
"""

import os
import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)

# ❌ Hardcoded secret
SECRET_KEY = "super-secret-password-123"

# ❌ Hardcoded DB credentials
DB_PASSWORD = "admin123"

DATABASE = "users.db"


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # ❌ SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()

    if user:
        return "Login successful"
    else:
        return "Invalid credentials"


@app.route("/ping")
def ping():
    host = request.args.get("host")

    # ❌ Command Injection vulnerability
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)

    return result


@app.route("/readfile")
def read_file():
    filename = request.args.get("file")

    # ❌ Path Traversal vulnerability
    with open(filename, "r") as f:
        content = f.read()

    return content


@app.route("/debug")
def debug():
    # ❌ Information Disclosure
    return str(os.environ)


@app.route("/exec")
def exec_code():
    code = request.args.get("code")

    # ❌ Arbitrary Code Execution
    exec(code)

    return "Code executed"


if __name__ == "__main__":
    init_db()

    # ❌ Debug mode enabled in production
    app.run(host="0.0.0.0", port=5000, debug=True)
