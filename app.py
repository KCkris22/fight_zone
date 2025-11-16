from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import mysql.connector
from mysql.connector import Error
import os
from datetime import datetime

# ---------- Config ----------
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # CHANGE THIS FOR PRODUCTION

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "fight_zone"
}

UPLOAD_FOLDER = os.path.join('static', 'payment_proofs')
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'pdf'}

# ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
        except Exception:
            # fallback to plaintext check for legacy accounts
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

    user_id = session['user_id']
    status = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT status 
            FROM subscriptions 
            WHERE user_id = %s 
            ORDER BY id DESC 
            LIMIT 1
        """, (user_id,))
        row = cursor.fetchone()

        if row:
            status = row['status']

    except:
        pass
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return render_template(
        'membership.html',
        username=session.get('username'),
        status=status
    )

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

# ----------------- MEMBERSHIP: SUBMIT GCASH -----------------
@app.route('/membership/submit_gcash', methods=['POST'])
def submit_gcash():
    if 'user_id' not in session:
        return jsonify({"error": "not_logged_in"}), 401

    user_id = session['user_id']
    plan = request.form.get('plan') or request.form.get('plan', '')
    price = request.form.get('price') or request.form.get('price', 0)

    proof = request.files.get('proof')
    proof_filename = None

    if proof:
        fn = secure_filename(proof.filename)
        ext = fn.rsplit('.', 1)[-1].lower() if '.' in fn else ''
        if ext not in ALLOWED_EXT:
            return jsonify({"error": "invalid_file_type"}), 400
        # ensure unique filename
        proof_filename = f"{user_id}_{int(__import__('time').time())}_{fn}"
        save_path = os.path.join(UPLOAD_FOLDER, proof_filename)
        proof.save(save_path)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO subscriptions (user_id, plan, price, payment_method, gcash_proof, status)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, plan, price, "GCASH", proof_filename, "Pending"))
        conn.commit()
    except Error as e:
        print("submit_gcash DB error:", e)
        return jsonify({"error": "db_error"}), 500
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return jsonify({"status": "ok"})

# ----------------- MEMBERSHIP: SUBMIT BANK -----------------
@app.route('/membership/submit_bank', methods=['POST'])
def submit_bank():
    if 'user_id' not in session:
        return jsonify({"error": "not_logged_in"}), 401

    user_id = session['user_id']
    plan = request.form.get('plan') or request.form.get('plan', '')
    price = request.form.get('price') or request.form.get('price', 0)

    bank_name = request.form.get('bank_name')
    card_number = request.form.get('card_number')
    cvv = request.form.get('cvv')

    # basic validation for numeric lengths
    if card_number and (not card_number.isdigit() or len(card_number) not in (15,16)):
        # allow 15 or 16 (just in case), but you requested 16
        return jsonify({"error": "invalid_card"}), 400
    if cvv and (not cvv.isdigit() or len(cvv) not in (3,4)):
        return jsonify({"error": "invalid_cvv"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO subscriptions (user_id, plan, price, payment_method, bank_name, card_number, cvv, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (user_id, plan, price, "BANK", bank_name, card_number, cvv, "Pending"))
        conn.commit()
    except Error as e:
        print("submit_bank DB error:", e)
        return jsonify({"error": "db_error"}), 500
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return jsonify({"status": "ok"})

# ----------------- ADMIN: VIEW SUBSCRIPTIONS -----------------
@app.route('/admin/subscriptions')
def admin_subscriptions():
    # admin check: username equals Administrator (case-insensitive)
    if 'user_id' not in session or session.get('username', '').lower() != 'administrator':
        return redirect(url_for('login'))

    subs = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        # select both the subscription fields and user info (username & email)
        cursor.execute("""
            SELECT s.*, u.username AS requester_username, u.email AS requester_email
            FROM subscriptions s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.created_at DESC
        """)
        subs = cursor.fetchall()
    except Error as e:
        print("admin_subscriptions DB error:", e)
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return render_template('admin_subscriptions.html', subs=subs)

# ----------------- ADMIN: ACCEPT / REJECT -----------------
@app.route('/admin/subscriptions/accept/<int:id>')
def accept_subscription(id):
    if 'user_id' not in session or session.get('username', '').lower() != 'administrator':
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE subscriptions SET status = %s WHERE id = %s", ("Accepted", id))
        conn.commit()
    except Error as e:
        print("accept_subscription DB error:", e)
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return redirect(url_for('admin_subscriptions'))

@app.route('/admin/subscriptions/reject/<int:id>')
def reject_subscription(id):
    if 'user_id' not in session or session.get('username', '').lower() != 'administrator':
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE subscriptions SET status = %s WHERE id = %s", ("Rejected", id))
        conn.commit()
    except Error as e:
        print("reject_subscription DB error:", e)
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return redirect(url_for('admin_subscriptions'))

# ----------------- ADMIN: DELETE SUBSCRIPTION -----------------
@app.route('/admin/subscriptions/delete/<int:id>')
def delete_subscription(id):
    if 'user_id' not in session or session.get('username', '').lower() != 'administrator':
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM subscriptions WHERE id = %s", (id,))
        conn.commit()
    except Error as e:
        print("delete_subscription DB error:", e)
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return redirect(url_for('admin_subscriptions'))

# ----------------- ADMIN: EDIT SUBSCRIPTION (POST) -----------------
@app.route('/admin/subscriptions/edit', methods=['POST'])
def edit_subscription_post():
    if 'user_id' not in session or session.get('username', '').lower() != 'administrator':
        return redirect(url_for('login'))

    sub_id = request.form.get('id')
    plan = request.form.get('plan')
    price = request.form.get('price')
    status = request.form.get('status')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE subscriptions SET plan = %s, price = %s, status = %s
            WHERE id = %s
        """, (plan, price, status, sub_id))
        conn.commit()
    except Error as e:
        print("edit_subscription_post DB error:", e)
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return redirect(url_for('admin_subscriptions'))

# ---------- App startup ----------
if __name__ == '__main__':
    ensure_admin()
    app.run(debug=True)