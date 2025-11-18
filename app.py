from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
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

# Use payment_proofs folder (consistent with your templates)
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
        auth_plugin='mysql_native_password'  # optional, depending on local config
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

# ---------- Helper to update status robustly ----------
def update_status(table: str, item_id: int, new_status: str, message: str = None):
    """
    Update status column and optionally status_message column.
    If the status_message column doesn't exist, it will fallback to updating only status.
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if message is not None:
            # Try to update both status and status_message (some tables may not have status_message)
            try:
                cursor.execute(f"UPDATE {table} SET status = %s, status_message = %s WHERE id = %s",
                               (new_status, message, item_id))
                conn.commit()
                return True
            except Error:
                # fallback to only updating status
                pass

        cursor.execute(f"UPDATE {table} SET status = %s WHERE id = %s", (new_status, item_id))
        conn.commit()
        return True
    except Exception as e:
        print("update_status error:", e)
        return False
    finally:
        try:
            if cursor: cursor.close()
            if conn: conn.close()
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
    popup_message = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, status, status_message
            FROM subscriptions
            WHERE user_id = %s
            ORDER BY id DESC
            LIMIT 1
        """, (user_id,))
        row = cursor.fetchone()

        if row:
            status = row.get('status')
            popup_message = row.get('status_message')
            # If accepted/rejected, popup_message will be shown; if pending and no status_message, membership.html shows generic pending
    except Exception as e:
        print("membership fetch error:", e)
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return render_template(
        'membership.html',
        username=session.get('username'),
        status=status,
        popup_message=popup_message
    )

@app.route('/store')
def store():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('store.html')

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

# ----------------- MEMBERSHIP: SUBMIT GCASH (AJAX-style or fetch) -----------------
@app.route('/membership/submit_gcash', methods=['POST'])
def submit_gcash():
    if 'user_id' not in session:
        return jsonify({"error": "not_logged_in"}), 401

    user_id = session['user_id']
    plan = request.form.get('plan') or ''
    price = request.form.get('price') or 0

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
        try:
            proof.save(save_path)
        except Exception as e:
            print("file save error:", e)
            return jsonify({"error": "save_failed"}), 500

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO subscriptions (user_id, plan, price, payment_method, gcash_proof, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (user_id, plan, price, "GCASH", proof_filename, "Pending", datetime.now()))
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

# ----------------- MEMBERSHIP: PAY GCASH (form) -----------------
@app.route('/pay/gcash', methods=['POST'])
def pay_gcash():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    plan = request.form.get('plan')
    price = request.form.get('price')

    file = request.files.get('payment_proof')
    if not file:
        flash("No file uploaded.", "error")
        return redirect(url_for('membership'))

    filename = secure_filename(file.filename)
    filename = f"{user_id}_{int(__import__('time').time())}_{filename}"
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    try:
        file.save(save_path)
    except Exception as e:
        print("Error saving uploaded file:", e)
        flash("Failed to save file.", "error")
        return redirect(url_for('membership'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO subscriptions (user_id, plan, price, payment_method, gcash_proof, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (user_id, plan, price, "GCASH", filename, "Pending", datetime.now()))
        conn.commit()
    except Error as e:
        print("pay_gcash DB error:", e)
        flash("Database error. Try again.", "error")
        return redirect(url_for('membership'))
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return redirect(url_for('processing_page'))

# ----- PROCESSING page (loading) -----
@app.route('/processing')
def processing_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template("processing.html")

# ----------------- MEMBERSHIP: SUBMIT BANK -----------------
@app.route('/membership/submit_bank', methods=['POST'])
def submit_bank():
    if 'user_id' not in session:
        return jsonify({"error": "not_logged_in"}), 401

    user_id = session['user_id']
    plan = request.form.get('plan') or ''
    price = request.form.get('price') or 0

    bank_name = request.form.get('bank_name')
    card_number = request.form.get('card_number')
    cvv = request.form.get('cvv')

    # basic validation for numeric lengths
    if card_number and (not card_number.isdigit() or len(card_number) not in (15,16)):
        return jsonify({"error": "invalid_card"}), 400
    if cvv and (not cvv.isdigit() or len(cvv) not in (3,4)):
        return jsonify({"error": "invalid_cvv"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO subscriptions (user_id, plan, price, payment_method, bank_name, card_number, cvv, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (user_id, plan, price, "BANK", bank_name, card_number, cvv, "Pending", datetime.now()))
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

@app.route('/store/pay', methods=['POST'])
def store_pay():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    product = request.form.get('product_name')
    price = request.form.get('price')
    method = request.form.get('payment_method')

    gcash_proof_filename = None

    # Handle GCash upload
    if method == "GCASH":
        file = request.files.get('gcash_proof')
        if file:
            filename = secure_filename(file.filename)
            gcash_proof_filename = f"{user_id}_{int(__import__('time').time())}_{filename}"
            try:
                file.save(os.path.join(UPLOAD_FOLDER, gcash_proof_filename))
            except Exception as e:
                print("store file save error:", e)
                flash("Failed to save proof file.", "error")
                return redirect(url_for('store'))

    bank_name = request.form.get('bank_name') if method == "BANK" else None
    card_number = request.form.get('card_number') if method == "BANK" else None
    cvv = request.form.get('cvv') if method == "BANK" else None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO store_orders
                (user_id, product_name, price, payment_method, gcash_proof, bank_name, card_number, cvv, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (user_id, product, price, method, gcash_proof_filename, bank_name, card_number, cvv, "Pending", datetime.now()))
        conn.commit()
    except Error as e:
        print("store_pay DB error:", e)
        flash("Database error. Try again.", "error")
        return redirect(url_for('store'))
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return redirect(url_for('processing_page'))

# ----------------- ADMIN: VIEW (unified) SUBSCRIPTIONS + STORE ORDERS -----------------
@app.route("/admin/subscriptions")
def admin_subscriptions():
    # admin check
    if 'user_id' not in session or session.get('username', '').lower() != 'administrator':
        return redirect(url_for('login'))

    combined = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # fetch membership subscriptions
        cursor.execute("""
            SELECT
                s.id,
                s.user_id,
                u.username AS requester_username,
                u.email AS requester_email,
                s.payment_method,
                s.plan AS item,
                s.price,
                s.gcash_proof AS proof,
                s.status,
                s.created_at,
                'membership' AS type
            FROM subscriptions s
            LEFT JOIN users u ON s.user_id = u.id
        """)
        mem = cursor.fetchall()

        # fetch store orders
        cursor.execute("""
            SELECT
                o.id,
                o.user_id,
                u.username AS requester_username,
                u.email AS requester_email,
                o.payment_method,
                o.product_name AS item,
                o.price,
                o.gcash_proof AS proof,
                o.status,
                o.created_at,
                'store' AS type
            FROM store_orders o
            LEFT JOIN users u ON o.user_id = u.id
        """)
        store = cursor.fetchall()

        combined = (mem or []) + (store or [])
        combined.sort(key=lambda r: r.get('created_at') or datetime.min, reverse=True)

    except Error as e:
        print("admin_subscriptions DB error:", e)
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return render_template('admin_subscriptions.html', subs=combined)

# ----------------- ADMIN: ACCEPT / REJECT (unified for membership+store) -----------------
@app.route('/admin/transactions/accept/<string:typ>/<int:id>')
def admin_accept(typ, id):
    if 'user_id' not in session or session.get('username', '').lower() != 'administrator':
        return redirect(url_for('login'))

    message = "✅ Your payment has been accepted!"
    try:
        if typ == 'membership':
            update_status('subscriptions', id, 'Accepted', message)
        elif typ == 'store':
            update_status('store_orders', id, 'Accepted', message)
    except Error as e:
        print("admin_accept error:", e)

    return redirect(url_for('admin_subscriptions'))

@app.route('/admin/transactions/reject/<string:typ>/<int:id>')
def admin_reject(typ, id):
    if 'user_id' not in session or session.get('username', '').lower() != 'administrator':
        return redirect(url_for('login'))

    message = "❌ Your payment was rejected. Please resubmit a valid proof."
    try:
        if typ == 'membership':
            update_status('subscriptions', id, 'Rejected', message)
        elif typ == 'store':
            update_status('store_orders', id, 'Rejected', message)
    except Error as e:
        print("admin_reject error:", e)

    return redirect(url_for('admin_subscriptions'))

@app.route('/admin/transactions/delete/<string:typ>/<int:id>')
def admin_delete(typ, id):
    if 'user_id' not in session or session.get('username', '').lower() != 'administrator':
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # remove file if exists (gcash_proof)
        tbl = 'subscriptions' if typ == 'membership' else 'store_orders'
        cursor.execute(f"SELECT gcash_proof FROM {tbl} WHERE id = %s", (id,))
        row = cursor.fetchone()

        proof_filename = None
        if row:
            # cursor may return tuple or dict depending on cursor type
            if isinstance(row, dict):
                proof_filename = row.get('gcash_proof')
            else:
                proof_filename = row[0]

        if proof_filename:
            file_on_disk = os.path.join(UPLOAD_FOLDER, proof_filename)
            if os.path.exists(file_on_disk):
                try:
                    os.remove(file_on_disk)
                except Exception as e:
                    print("Could not remove file:", e)

        # delete row
        cursor.execute(f"DELETE FROM {tbl} WHERE id = %s", (id,))
        conn.commit()
    except Error as e:
        print("admin_delete error:", e)
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

# ----------------- ADMIN: TRANSACTIONS PAGE (keeps nav link working) -----------------
@app.route('/admin/transactions')
def admin_transactions():
    if 'user_id' not in session or session.get('username', '').lower() != 'administrator':
        return redirect(url_for('login'))

    transactions = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # union the two tables, then order by created_at
        cursor.execute("""
            SELECT * FROM (
                SELECT
                    s.id,
                    s.user_id,
                    u.username,
                    s.payment_method,
                    s.plan AS item,
                    s.price,
                    s.gcash_proof AS proof,
                    s.status,
                    'membership' AS type,
                    s.created_at
                FROM subscriptions s
                JOIN users u ON s.user_id = u.id
                UNION ALL
                SELECT
                    o.id,
                    o.user_id,
                    u.username,
                    o.payment_method,
                    o.product_name AS item,
                    o.price,
                    o.gcash_proof AS proof,
                    o.status,
                    'store' AS type,
                    o.created_at
                FROM store_orders o
                JOIN users u ON o.user_id = u.id
            ) AS alltx
            ORDER BY created_at DESC
        """)
        transactions = cursor.fetchall()
    except Error as e:
        print("admin_transactions DB error:", e)
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    return render_template('admin_transactions.html', transactions=transactions)


# ---------- App startup ----------
if __name__ == '__main__':
    ensure_admin()
    app.run(debug=True)