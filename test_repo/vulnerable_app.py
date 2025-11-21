"""
Vulnerable Python application for testing security scanner.
WARNING: This file contains intentional security vulnerabilities for testing purposes only.
DO NOT use this code in production!
"""

import os
import pickle
import hashlib
import random
import subprocess
import xml.etree.ElementTree as ET
from flask import Flask, request
import sqlite3

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded credentials
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdefghijklmnop"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


# VULNERABILITY 2: SQL Injection via string formatting
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()


# VULNERABILITY 3: SQL Injection via string concatenation
@app.route("/search")
def search_users():
    username = request.args.get("username")
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


# VULNERABILITY 4: Command Injection
@app.route("/ping")
def ping_server():
    host = request.args.get("host")
    # Command injection vulnerability
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout


# VULNERABILITY 5: Weak hashing (MD5)
def hash_password_weak(password):
    # MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


# VULNERABILITY 6: Weak hashing (SHA1)
def hash_password_sha1(password):
    # SHA1 is deprecated for security
    return hashlib.sha1(password.encode()).hexdigest()


# VULNERABILITY 7: eval() usage
@app.route("/calculate")
def calculate():
    expression = request.args.get("expr")
    # Code injection vulnerability
    result = eval(expression)
    return str(result)


# VULNERABILITY 8: Insecure deserialization with pickle
@app.route("/load_data")
def load_data():
    data = request.data
    # Pickle deserialization can lead to RCE
    obj = pickle.loads(data)
    return str(obj)


# VULNERABILITY 9: Weak random for security
def generate_session_token():
    # random.random() is not cryptographically secure
    return str(random.random())


def generate_password_reset_token():
    # Predictable token generation
    return str(random.randint(1000, 9999))


# VULNERABILITY 10: Path traversal
@app.route("/read_file")
def read_file():
    filename = request.args.get("file")
    # Path traversal vulnerability
    with open(filename, "r") as f:
        return f.read()


# VULNERABILITY 11: XXE (XML External Entity)
@app.route("/parse_xml")
def parse_xml():
    xml_data = request.data
    # XXE vulnerability - no protection against external entities
    tree = ET.fromstring(xml_data)
    return ET.tostring(tree)


# VULNERABILITY 12: Insecure SSL/TLS
import ssl
import urllib.request


def fetch_insecure():
    # Disabling certificate verification
    context = ssl._create_unverified_context()
    response = urllib.request.urlopen("https://example.com", context=context)
    return response.read()


# VULNERABILITY 13: Debug mode in production
if __name__ == "__main__":
    # Running Flask with debug=True is dangerous in production
    app.run(debug=True, host="0.0.0.0", port=5000)


# VULNERABILITY 14: Using banned functions
def deserialize_unsafe(data):
    # marshal is also unsafe for untrusted data
    import marshal

    return marshal.loads(data)


# VULNERABILITY 15: Weak cryptography
from Crypto.Cipher import DES


def encrypt_weak(data, key):
    # DES is weak and deprecated
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)


# VULNERABILITY 16: Hardcoded temp file
import tempfile


def create_temp_insecure():
    # mktemp is insecure (race condition)
    tmpfile = tempfile.mktemp()
    return tmpfile


# VULNERABILITY 17: Assert used for access control
def check_admin(user):
    # Assert can be disabled with -O flag
    assert user.is_admin, "Not an admin"
    return True


# VULNERABILITY 18: Unvalidated redirect
@app.route("/redirect")
def redirect_user():
    url = request.args.get("url")
    # Open redirect vulnerability
    return f"<meta http-equiv='refresh' content='0;url={url}'>"


# Additional vulnerable patterns
class UserManager:
    def __init__(self):
        self.db_password = "password123"  # Hardcoded password

    def authenticate(self, username, password):
        # Timing attack vulnerability
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        return query


# YAML loading vulnerability
def load_config(config_file):
    import yaml

    # yaml.load is unsafe without Loader
    with open(config_file) as f:
        # This can lead to arbitrary code execution
        config = yaml.load(f)
        return config
