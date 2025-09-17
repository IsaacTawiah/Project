from flask import Flask, request, render_template_string, redirect, url_for, session
from werkzeug.security import generate_password_hash
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace-this-with-a-secure-key'
DB_PATH = 'users.db'

# --- DB Setup ---
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)

init_db()

# --- Validation Helpers ---
def is_valid_email(email):
    import re
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)

def is_strong_password(password):
    import re
    return len(password) >= 8 and re.search(r'[A-Z]', password) and re.search(r'\d', password)

def email_exists(email):
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE email = ?", (email,))
        return cur.fetchone() is not None

def save_user(full_name, email, password_hash):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)",
            (full_name, email, password_hash)
        )

# --- Routes ---
@app.route("/", methods=["GET", "POST"])
def register():
    errors = {}
    success = None
    name = email = ""

    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        pw = request.form.get("password", "")
        pw2 = request.form.get("confirm_password", "")

        # Validation
        if not name:
            errors["full_name"] = "Full name is required."
        if not email or not is_valid_email(email):
            errors["email"] = "Valid email is required."
        elif email_exists(email):
            errors["email"] = "Email already registered."
        if not pw or not is_strong_password(pw):
            errors["password"] = "Password must be ≥8 chars, include uppercase and digit."
        if pw != pw2:
            errors["confirm_password"] = "Passwords do not match."

        if not errors:
            hash_pw = generate_password_hash(pw)
            save_user(name, email, hash_pw)
            success = f"Demo account created for {name} ({email})!"
            name = email = ""

    return render_template_string(TEMPLATE, errors=errors, success=success, name=name, email=email)

# --- Template ---
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Create Demo Account</title>
    <style>
        body { font-family: Arial; background: #f0f2f5; padding: 2rem; }
        .container { max-width: 400px; margin: auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        input, button { width: 100%; padding: 0.5rem; margin-top: 0.5rem; }
        .error { color: red; font-size: 0.9rem; }
        .success { color: green; font-size: 1rem; margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Create Your Demo Account</h2>
        <form method="POST">
            <label>Full Name:</label>
            <input type="text" name="full_name" value="{{ name }}">
            {% if errors.full_name %}<div class="error">{{ errors.full_name }}</div>{% endif %}

            <label>Email:</label>
            <input type="email" name="email" value="{{ email }}">
            {% if errors.email %}<div class="error">{{ errors.email }}</div>{% endif %}

            <label>Password:</label>
            <input type="password" name="password">
            {% if errors.password %}<div class="error">{{ errors.password }}</div>{% endif %}

            <label>Confirm Password:</label>
            <input type="password" name="confirm_password">
            {% if errors.confirm_password %}<div class="error">{{ errors.confirm_password }}</div>{% endif %}

            <button type="submit">Create Demo Account</button>
        </form>
        {% if success %}
            <div class="success">{{ success }}</div>
        {% endif %}
    </div>
</body>
</html>
"""

# --- Run App ---
if __name__ == "__main__":
    app.run(debug=True)
