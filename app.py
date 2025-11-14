from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error

# ---------- Config ----------
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # CHANGE THIS FOR PRODUCTION

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "fight_zone"
}

# ---------- DB helper ----------
def get_db_connection():
    return mysql.connector.connect(
        host=DB_CONFIG["host"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        database=DB_CONFIG["database"],
    )

# ---------- Dev convenience: ensure admin exists ----------
def ensure_admin():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", ("Administrator",))
        admin = cursor.fetchone()

        if not admin:
            hashed = generate_password_hash("admin123")
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                ("Administrator", "admin@fightzone.com", hashed)
            )
            conn.commit()
            print("[setup] Administrator account created.")
        else:
            print("[setup] Administrator exists.")
    except Error as e:
        print("[setup] DB error:", e)
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

# ========== ROUTES ==========

@app.route('/')
def index():
    return redirect(url_for('login'))


# ---------------- Register ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    popup_message = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not username or not email or not password:
            popup_message = "⚠️ Please fill all fields."
            return render_template('register.html', popup_message=popup_message)

        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s",
                           (username, email))
            existing = cursor.fetchone()

            if existing:
                popup_message = "⚠️ Username or Email already exists!"
            else:
                hashed_password = generate_password_hash(password)
                cursor.execute(
                    "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, hashed_password)
                )
                conn.commit()
                popup_message = "✅ Account created successfully!"

        except Error as e:
            print("Register DB error:", e)
            popup_message = "⚠️ Database error."
        finally:
            try:
                cursor.close()
                conn.close()
            except:
                pass

    return render_template('register.html', popup_message=popup_message)


# ---------------- Login ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    popup_message = None

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not email or not password:
            popup_message = "⚠️ Please enter email and password."
            return render_template('login.html', popup_message=popup_message)

        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
        except Error as e:
            print("Login DB error:", e)
            user = None
        finally:
            try:
                cursor.close()
                conn.close()
            except:
                pass

        if not user:
            popup_message = "⚠️ Account not found."
            return render_template('login.html', popup_message=popup_message)

        stored_pw = user['password']
        login_success = False

        try:
            if check_password_hash(stored_pw, password):
                login_success = True
        except:
            if stored_pw == password:
                login_success = True

        if not login_success:
            popup_message = "❌ Incorrect password."
            return render_template('login.html', popup_message=popup_message)

        session['user_id'] = user['id']
        session['username'] = user['username']

        if user['username'].lower() == 'administrator':
            return redirect(url_for('admin_dashboard'))

        return redirect(url_for('home'))

    return render_template('login.html', popup_message=popup_message)


# ---------------- User pages ----------------
@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('home.html', username=session.get('username'))


@app.route('/about')
def about():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('about.html', username=session.get('username'))


@app.route('/benefits')
def benefits():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('benefits.html', username=session.get('username'))


@app.route('/membership')
def membership():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('membership.html', username=session.get('username'))


# ---------------- ADMIN DASHBOARD ----------------
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('username', '').lower() != 'administrator':
        return redirect(url_for('login'))

    users = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id, username, email, password FROM users")
        users = cursor.fetchall()

    except Error as e:
        print("Admin dashboard error:", e)
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return render_template('admin_dashboard.html', users=users)


# ---------------- DELETE USER (Modal Confirm) ----------------
@app.route('/admin/delete_user/<int:id>')
def delete_user(id):

    # Prevent deleting the admin
    if id == session.get('user_id'):
        return redirect('/admin_dashboard')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM users WHERE id = %s", (id,))
    conn.commit()

    cursor.close()
    conn.close()

    return redirect('/admin_dashboard')


# ---------------- EDIT USER ----------------
@app.route('/admin/edit_user/<int:id>')
def edit_user(id):
    new_username = request.args.get("username")
    new_email = request.args.get("email")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET username = %s, email = %s
        WHERE id = %s
    """, (new_username, new_email, id))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/admin_dashboard')


# ---------------- ADD USER ----------------
@app.route('/admin/add_user')
def add_user():

    username = request.args.get("username")
    email = request.args.get("email")
    password = request.args.get("password")

    hashed_pw = generate_password_hash(password)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO users (username, email, password)
        VALUES (%s, %s, %s)
    """, (username, email, hashed_pw))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/admin_dashboard')


# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ---------- App startup ----------
if __name__ == '__main__':
    ensure_admin()
    app.run(debug=True)