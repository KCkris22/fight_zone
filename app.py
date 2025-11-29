from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import mysql.connector
from mysql.connector import Error
import os
from datetime import datetime, timedelta
import random
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ---------- Config ----------
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "fight_zone"
}

# Admin configuration (Option A: Admin by email)
ADMIN_EMAIL = "admin@fightzone.com"
ADMIN_PASSWORD = "admin123"

# Email (placeholder - used for OTP sending)
EMAIL_SENDER = "magalloncynric@gmail.com"
EMAIL_APP_PASSWORD = "lehb diih shza rmnx"
EMAIL_SMTP = "smtp.gmail.com"
EMAIL_PORT = 465

# Use payment_proofs folder
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
        auth_plugin='mysql_native_password'
    )

# ---------- Dev convenience: ensure admin exists ----------
def ensure_admin():
    """
    Ensure the admin user (by ADMIN_EMAIL) exists. If not, create with default password.
    Uses fields: first_name, last_name, address, email, password.
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (ADMIN_EMAIL,))
        admin = cursor.fetchone()

        if not admin:
            hashed = generate_password_hash(ADMIN_PASSWORD)
            cursor.execute(
                "INSERT INTO users (first_name, last_name, address, email, password) VALUES (%s, %s, %s, %s, %s)",
                ("Administrator", "", "", ADMIN_EMAIL, hashed)
            )
            conn.commit()
            print("[setup] Administrator account created (email=%s)." % ADMIN_EMAIL)
        else:
            print("[setup] Administrator exists (email=%s)." % ADMIN_EMAIL)
    except Error as e:
        print("[setup] DB error:", e)
    finally:
        try:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
        except:
            pass

# ---------- Helper to update status robustly ----------
def update_status(table: str, item_id: int, new_status: str, message: str = None):
    """
    Update status column and optionally status_message column.
    If status_message column doesn't exist, it falls back to updating only status.
    Returns True/False.
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
            if cursor:
                cursor.close()
            if conn:
                conn.close()
        except:
            pass

# ---------- OTP / Email helpers ----------
def generate_otp(length=6):
    """Return a numeric OTP as string."""
    start = 10**(length-1)
    return str(random.randint(start, start * 10 - 1))


def send_otp_email(recipient_email, otp_code):
    """Send OTP to user's email using Gmail SMTP. Returns True if sent successfully."""
    subject = "FightZone — Your Verification Code"
    body = (
        f"Greetings Champ!,\n\n"
        f"Your FightZone verification code is:\n\n"
        f"🔐 OTP: {otp_code}\n\n"
        f"If you did not request this, simply ignore this email.\n\n"
        f"— FightZone Security Team"
    )

    msg = MIMEMultipart()
    msg["From"] = EMAIL_SENDER
    msg["To"] = recipient_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(EMAIL_SMTP, EMAIL_PORT, context=context) as server:
            server.login(EMAIL_SENDER, EMAIL_APP_PASSWORD)
            server.sendmail(EMAIL_SENDER, recipient_email, msg.as_string())

        print("OTP email sent successfully!")
        return True

    except Exception as e:
        print("send_otp_email ERROR:", e)
        return False

# ========== ROUTES ==========
@app.route('/')
def index():
    return redirect(url_for('landing_page'))

# ---------------- Landing Page ----------------
@app.route('/landing')
def landing_page():
    return render_template('landing.html')

# ---------------- Register ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Registration flow updated for the new users table fields:
    - first_name, last_name, address, email, password
    OTP-first approach: POST stores pending in session and sends OTP; user verifies on /verify_otp.
    """
    popup_message = None

    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        address = request.form.get('address', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not first_name or not last_name or not email or not password:
            popup_message = "⚠️ Please fill all required fields (First, Last, Email, Password)."
            return render_template('register.html', popup_message=popup_message)

        # Check uniqueness by email
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            existing = cursor.fetchone()
        except Error as e:
            print("Register DB error (check existing):", e)
            existing = None
        finally:
            try:
                cursor.close()
                conn.close()
            except:
                pass

        if existing:
            popup_message = "⚠️ Email already exists! Try logging in instead."
            return render_template('register.html', popup_message=popup_message)

        # generate OTP and attempt to send email
        otp = generate_otp(6)
        sent = send_otp_email(email, otp)

        if not sent:
            popup_message = "⚠️ Failed to send verification email. Please try again later."
            return render_template('register.html', popup_message=popup_message)

        # store pending registration in session until OTP verified (expires in 10 minutes)
        expiry = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        session['pending_registration'] = {
            "first_name": first_name,
            "last_name": last_name,
            "address": address,
            "email": email,
            "password_hash": generate_password_hash(password),
            "otp": otp,
            "otp_expires_at": expiry
        }

        # redirect to verification page
        return redirect(url_for('verify_otp'))

    return render_template('register.html', popup_message=None)

# ---------------- Verify OTP ----------------
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    """
    Page for entering OTP sent to email.
    On success: create user in DB and show the success popup.
    """
    pending = session.get('pending_registration')
    if not pending:
        flash("No pending registration. Please register first.", "error")
        return redirect(url_for('register'))

    if request.method == 'POST':
        code = request.form.get('otp_code', '').strip()
        if not code:
            return render_template('verify_otp.html', error="Please enter the code sent to your email.")

        # Check expiration
        try:
            expires_at = datetime.fromisoformat(pending['otp_expires_at'])
        except Exception:
            expires_at = datetime.utcnow() - timedelta(seconds=1)

        if datetime.utcnow() > expires_at:
            session.pop('pending_registration', None)
            return render_template('verify_otp.html', error="OTP expired. Please register again.")

        # Incorrect
        if code != pending.get('otp'):
            return render_template('verify_otp.html', error="Incorrect code. Try again.")

        # Correct → Create user (first_name, last_name, address, email, password)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (first_name, last_name, address, email, password)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                pending.get('first_name'),
                pending.get('last_name'),
                pending.get('address'),
                pending.get('email'),
                pending.get('password_hash')
            ))
            conn.commit()
        except Error as e:
            print("verify_otp DB insert error:", e)
            return render_template('verify_otp.html', error="Database error while creating account.")
        finally:
            try:
                cursor.close()
                conn.close()
            except:
                pass

        # Clear pending registration
        session.pop('pending_registration', None)

        # Show popup confirming account created
        return render_template("verify_otp.html", account_created=True)

    # GET (pre-fill masked email)
    masked_email = None
    if pending and 'email' in pending:
        em = pending['email']
        parts = em.split("@")
        if len(parts[0]) > 2:
            masked_local = parts[0][0] + "*"*(len(parts[0])-2) + parts[0][-1]
        else:
            masked_local = parts[0][0] + "*"
        masked_email = masked_local + "@" + parts[1]

    return render_template('verify_otp.html', masked_email=masked_email)

# Resend OTP route (in case user requests)
@app.route('/resend_otp')
def resend_otp():
    pending = session.get('pending_registration')
    if not pending:
        flash("No pending registration to resend OTP for.", "error")
        return redirect(url_for('register'))

    new_otp = generate_otp(6)
    sent = send_otp_email(pending['email'], new_otp)
    if not sent:
        flash("Failed to resend OTP. Try again later.", "error")
        return redirect(url_for('verify_otp'))

    # update session pending
    pending['otp'] = new_otp
    pending['otp_expires_at'] = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    session['pending_registration'] = pending
    flash("A new code was sent to your email.", "success")
    return redirect(url_for('verify_otp'))

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

        # set session values (use full name for username compatibility)
        session['user_id'] = user['id']
        full_name = (user.get('first_name') or '') + ((' ' + user.get('last_name')) if user.get('last_name') else '')
        session['username'] = full_name.strip() or user.get('email')
        session['email'] = user.get('email')
        session['first_name'] = user.get('first_name')
        session['last_name'] = user.get('last_name')

        # admin check by email (Option A)
        if user.get('email') and user.get('email').lower() == ADMIN_EMAIL.lower():
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


@app.route("/my_account")
def my_account():
    # ensure logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 1) Fetch user basic profile
        cursor.execute("""
            SELECT id, first_name, last_name, address, email
            FROM users
            WHERE id = %s
            LIMIT 1
        """, (user_id,))
        user = cursor.fetchone()

        # If somehow the user record is missing, redirect to login
        if not user:
            session.clear()
            return redirect(url_for("login"))

        # 2) Fetch latest membership/subscription row for this user
        # We'll show the most recent subscription regardless of status so the user can see Pending/Accepted/Rejected.
        cursor.execute("""
            SELECT id, plan, price, payment_method, gcash_proof, status, created_at
            FROM subscriptions
            WHERE user_id = %s
            ORDER BY id DESC
            LIMIT 1
        """, (user_id,))
        sub = cursor.fetchone()

        membership_data = None
        if sub:
            created_at = sub.get("created_at")
            # created_at from mysql connector should already be a datetime object.
            # If it's None or not a datetime, fall back to now().
            if not created_at:
                created_at = datetime.utcnow()

            # NOTE: your subscriptions table does not appear to have an explicit end_date field.
            # We'll assume a 30-day membership window starting from created_at. If you have different rules,
            # change the `membership_duration_days` value or add an end_date field to the DB.
            membership_duration_days = 30
            end_dt = created_at + timedelta(days=membership_duration_days)

            # days left (floor to 0)
            days_left = (end_dt.date() - datetime.utcnow().date()).days
            if days_left < 0:
                days_left = 0

            membership_data = {
                "id": sub.get("id"),
                "plan": sub.get("plan"),
                "price": sub.get("price"),
                "payment_method": sub.get("payment_method"),
                "status": sub.get("status"),
                "created_at": created_at,
                # ISO strings for JS usage
                "end_date": end_dt.strftime("%Y-%m-%d"),
                "end_date_js": end_dt.strftime("%Y-%m-%dT%H:%M:%S"),
                "days_left": days_left
            }

        # 3) Fetch store orders for this user (most recent first)
        cursor.execute("""
            SELECT id, product_name, price, payment_method, status, created_at
            FROM store_orders
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (user_id,))
        orders = cursor.fetchall() or []

    except Exception as e:
        # Log error and show minimal page instead of crashing
        print("my_account error:", e)
        # safe defaults
        user = user if 'user' in locals() and user else {"id": user_id, "first_name": "", "last_name": "", "address": "", "email": session.get("email")}
        membership_data = membership_data if 'membership_data' in locals() else None
        orders = orders if 'orders' in locals() else []
    finally:
        try:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
        except:
            pass

    # Render the my_account template (you'll need to create templates/my_account.html)
    return render_template(
        "my_account.html",
        user=user,
        membership=membership_data,
        orders=orders
    )

# ---------------- ADMIN DASHBOARD ----------------
@app.route('/admin_dashboard')
def admin_dashboard():
    # admin check via email
    if 'user_id' not in session or session.get('email', '').lower() != ADMIN_EMAIL.lower():
        return redirect(url_for('login'))

    users = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # select user info using first/last names
        cursor.execute("SELECT id, first_name, last_name, address, email, password FROM users")
        users = cursor.fetchall()

    except Error as e:
        print("Admin dashboard error:", e)
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    # add a 'display_name' to each user for templates
    for u in users:
        fn = u.get('first_name') or ''
        ln = u.get('last_name') or ''
        u['display_name'] = (fn + (' ' + ln if ln else '')).strip() or u.get('email')

    return render_template('admin_dashboard.html', users=users)

# ---------------- DELETE USER (Modal Confirm) ----------------
@app.route('/admin/delete_user/<int:id>')
def delete_user(id):
    # Prevent deleting the admin (by email)
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT email FROM users WHERE id = %s", (id,))
        row = cursor.fetchone()
        if row and row.get('email') and row.get('email').lower() == ADMIN_EMAIL.lower():
            flash(" ", "error")
            return redirect('/admin_dashboard')
    except Exception as e:
        print("delete_user lookup error:", e)
        # fall through to safe behavior
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

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
    new_first = request.args.get("first_name")
    new_last = request.args.get("last_name")
    new_email = request.args.get("email")
    new_address = request.args.get("address", "")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users
        SET first_name = %s, last_name = %s, email = %s, address = %s
        WHERE id = %s
    """, (new_first, new_last, new_email, new_address, id))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/admin_dashboard')

# ---------------- ADD USER ----------------
@app.route('/admin/add_user')
def add_user():
    # Creates a new user (admin interface)
    first_name = request.args.get("first_name", "New")
    last_name = request.args.get("last_name", "User")
    email = request.args.get("email")
    password = request.args.get("password", "changeme")

    if not email:
        flash("Email required to add user.", "error")
        return redirect(url_for('admin_dashboard'))

    hashed_pw = generate_password_hash(password)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (first_name, last_name, address, email, password)
        VALUES (%s, %s, %s, %s, %s)
    """, (first_name, last_name, "", email, hashed_pw))
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

# ----------------- MEMBERSHIP: PAY BANK (form) -----------------
@app.route('/pay/bank', methods=['POST'])
def pay_bank():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    plan = request.form.get('plan')
    price = request.form.get('price')
    fullname = request.form.get('fullname')
    card_number = request.form.get('card_number')
    cvv = request.form.get('cvv')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        sql = """
            INSERT INTO subscriptions (user_id, plan, price, payment_method, gcash_proof, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(sql, (
            session['user_id'],
            plan,
            price,
            "BANK",
            None,
            "Pending",
            datetime.now()
        ))

        conn.commit()

    except Exception as e:
        print("pay_bank ERROR:", e)
        return redirect(url_for('membership', status="error"))

    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    # ⭐ Send user to processing loading screen
    return redirect(url_for('processing_page'))

# ----------------- STORE PAY -----------------
@app.route('/store/pay', methods=['POST'])
def store_pay():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    product = request.form.get('product_name')
    price = request.form.get('price')
    method = request.form.get('payment_method')

    if not product or not price or not method:
        flash("Invalid order data.", "error")
        return redirect(url_for('store'))

    gcash_proof_filename = None
    card_number = None
    cvv = None

    # ==========================
    # GCASH PAYMENT HANDLING
    # ==========================
    if method == "GCASH":
        file = request.files.get('gcash_proof')

        if not file or file.filename == "":
            flash("Please upload your G-Cash payment proof.", "error")
            return redirect(url_for('store'))

        filename = secure_filename(file.filename)
        gcash_proof_filename = f"{user_id}_{int(__import__('time').time())}_{filename}"

        try:
            file.save(os.path.join(UPLOAD_FOLDER, gcash_proof_filename))
        except Exception as e:
            print("GCash upload error:", e)
            flash("Failed to save payment proof.", "error")
            return redirect(url_for('store'))

    # ==========================
    # BANK PAYMENT HANDLING
    # ==========================
    elif method == "BANK":
        card_number = request.form.get('card_number')
        cvv = request.form.get('cvv')

        if not card_number or not cvv:
            flash("Bank information incomplete.", "error")
            return redirect(url_for('store'))

    # Unknown method
    else:
        flash("Invalid payment method.", "error")
        return redirect(url_for('store'))

    # ==========================
    # SAVE ORDER TO DATABASE
    # ==========================
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO store_orders
                (user_id, product_name, price, payment_method, gcash_proof, card_number, cvv, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            user_id, product, price, method,
            gcash_proof_filename, card_number, cvv,
            "Pending", datetime.now()
        ))

        conn.commit()

    except Error as e:
        print("store_pay DB error:", e)
        flash("Database error. Please try again.", "error")
        return redirect(url_for('store'))

    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

    # Redirect user to your "Processing..." screen
    return redirect(url_for('processing_page'))

# ----------------- ADMIN: VIEW (unified) SUBSCRIPTIONS + STORE ORDERS -----------------
@app.route("/admin/subscriptions")
def admin_subscriptions():
    # admin check
    if 'user_id' not in session or session.get('email', '').lower() != ADMIN_EMAIL.lower():
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
                CONCAT(IFNULL(u.first_name,''), ' ', IFNULL(u.last_name,'')) AS requester_username,
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
                CONCAT(IFNULL(u.first_name,''), ' ', IFNULL(u.last_name,'')) AS requester_username,
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
    if 'user_id' not in session or session.get('email', '').lower() != ADMIN_EMAIL.lower():
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
    if 'user_id' not in session or session.get('email', '').lower() != ADMIN_EMAIL.lower():
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
    if 'user_id' not in session or session.get('email', '').lower() != ADMIN_EMAIL.lower():
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
    if 'user_id' not in session or session.get('email', '').lower() != ADMIN_EMAIL.lower():
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
    if 'user_id' not in session or session.get('email', '').lower() != ADMIN_EMAIL.lower():
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
                    CONCAT(IFNULL(u.first_name,''), ' ', IFNULL(u.last_name,'')) AS username,
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
                    CONCAT(IFNULL(u.first_name,''), ' ', IFNULL(u.last_name,'')) AS username,
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