from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure key

# Database connection function
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",  # add your MySQL password if you have one
        database="fight_zone"
    )

# ========== ROUTES ==========

# Default route - redirect to login
@app.route('/')
def index():
    return redirect(url_for('login'))

# ---------------- Register ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    popup_message = None
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if username or email already exists
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        existing = cursor.fetchone()

        if existing:
            popup_message = "⚠️ Username or Email already exists!"
        else:
            # 🔒 Hash the password before saving
            hashed_password = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_password)
            )
            conn.commit()
            popup_message = "✅ Account created successfully! You can now log in."

        cursor.close()
        conn.close()

    return render_template('register.html', popup_message=popup_message)

# ---------------- Login ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    popup_message = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user:
            if check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('home'))
            else:
                popup_message = "❌ Incorrect password. Try again."
        else:
            popup_message = "⚠️ Account not found."

    return render_template('login.html', popup_message=popup_message)

# ---------------- Home ----------------
@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('home.html', username=session.get('username'))

# ---------------- Logout ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
