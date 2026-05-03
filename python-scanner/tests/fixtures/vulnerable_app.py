"""
Test fixture: A deliberately vulnerable Python application for testing the security scanner.
DO NOT USE IN PRODUCTION - This code contains intentional security vulnerabilities.
"""

import sqlite3
import pickle
import hashlib
import yaml
import requests
from flask import Flask, request

app = Flask(__name__)

# VULNERABILITY: Hardcoded secrets (OWASP A07)
DATABASE_PASSWORD = "super_secret_password123"
API_KEY = "sk-1234567890abcdef1234567890abcdef"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULNERABILITY: Debug mode enabled (OWASP A05)
DEBUG = True


# VULNERABILITY: SQL Injection (OWASP A03)
def get_user(username):
    """Fetch user from database - VULNERABLE TO SQL INJECTION"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Using f-string for query - DANGEROUS!
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()


# VULNERABILITY: Another SQL Injection variant
def search_users(search_term):
    """Search users - VULNERABLE TO SQL INJECTION"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Using .format() - ALSO DANGEROUS!
    query = "SELECT * FROM users WHERE name LIKE '%{}%'".format(search_term)
    cursor.execute(query)
    return cursor.fetchall()


# VULNERABILITY: Weak cryptographic hash (OWASP A02)
def hash_password(password):
    """Hash a password - USING WEAK MD5"""
    return hashlib.md5(password.encode()).hexdigest()


# VULNERABILITY: Weak SHA1 hash (OWASP A02)
def hash_token(token):
    """Hash a token - USING WEAK SHA1"""
    return hashlib.sha1(token.encode()).hexdigest()


# VULNERABILITY: Dangerous eval (OWASP A03)
def calculate(expression):
    """Calculate mathematical expression - USING DANGEROUS eval()"""
    # eval() allows arbitrary code execution!
    return eval(expression)


# VULNERABILITY: Insecure deserialization (OWASP A08)
def load_user_data(data):
    """Load serialized user data - INSECURE pickle.loads()"""
    # pickle.loads() can execute arbitrary code!
    return pickle.loads(data)


# VULNERABILITY: Insecure YAML loading (OWASP A08)
def load_config(yaml_string):
    """Load YAML config - INSECURE yaml.load()"""
    # yaml.load() without SafeLoader is dangerous!
    return yaml.load(yaml_string)


# VULNERABILITY: SSRF (OWASP A010)
def fetch_url(user_url):
    """Fetch URL from user input - SSRF VULNERABLE"""
    # No URL validation - attacker can access internal services!
    response = requests.get(user_url)
    return response.text


# VULNERABILITY: CORS misconfiguration (OWASP A05)
@app.route("/api/data")
def get_data():
    """API endpoint with wildcard CORS - MISCONFIGURED"""
    # In real Flask-CORS this would be:
    # CORS(app, resources={r"/*": {"origins": "*"}})
    return {"data": "sensitive information"}


# VULNERABILITY: Hardcoded admin check (OWASP A01)
def is_admin(user):
    """Check if user is admin - HARDCODED CHECK"""
    if user == "admin":
        return True
    return False


# VULNERABILITY: Weak password validation (OWASP A07)
def validate_password(password):
    """Validate password strength - WEAK REQUIREMENTS"""
    # Only checking length of 6 characters!
    if len(password) < 6:
        return False
    return True


# VULNERABILITY: Password in exception (OWASP A09)
def authenticate(username, password):
    """Authenticate user - LOGGING PASSWORD IN EXCEPTION"""
    try:
        # Some authentication logic
        if username == "admin" and password == DATABASE_PASSWORD:
            return True
        raise Exception(f"Auth failed for {username} with password {password}")
    except Exception as e:
        print(f"Error: {e}")  # Password leaked in logs!
        return False


# Flask route with SQL injection
@app.route("/user/<username>")
def user_route(username):
    """Get user by username - SQL INJECTION VIA URL"""
    user = get_user(username)
    if user:
        return {"username": user[0], "email": user[1]}
    return {"error": "User not found"}, 404


# Flask route with POST data SQL injection
@app.route("/search", methods=["POST"])
def search_route():
    """Search endpoint - SQL INJECTION VIA POST DATA"""
    search_term = request.form.get("q", "")
    results = search_users(search_term)
    return {"results": results}


# Flask route with eval
@app.route("/calculate", methods=["POST"])
def calculate_route():
    """Calculator endpoint - CODE INJECTION VIA eval"""
    expression = request.form.get("expr", "")
    try:
        result = calculate(expression)
        return {"result": result}
    except Exception as e:
        return {"error": str(e)}, 400


if __name__ == "__main__":
    app.run(debug=DEBUG)
