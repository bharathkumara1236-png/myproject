# =========================
# CYBERSHIELD MAIN APPLICATION
# =========================

from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3
import os
import re
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(override=True)


# =========================
# IMPORT MODULES
# =========================

from modules.auth import (
    create_user,
    verify_user,
    log_login,
    log_failed_login,
    get_failed_attempts,
    create_scan_log,
    change_password
)
from modules.auth import create_otp, verify_otp

from modules.port_scanner import scan_ports
from modules.file_checker import save_file_hash, check_file_integrity
from modules.web_scanner import scan_website
from modules.network_scanner import scan_network
from modules.safeweb_analyzer import analyze_url


# =========================
# APP INITIALIZATION
# =========================

app = Flask(__name__)

# Use strong secret key
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))


# =========================
# DATABASE CONNECTION
# =========================

DATABASE = "database.db"


def get_db():
    """Return database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# =========================
# DATABASE INITIALIZATION
# =========================

def init_db():
    """Initialize database with required tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """
        )
        # ensure blocked column exists for user management
        cursor.execute("PRAGMA table_info(users)")
        usercols = [row[1] for row in cursor.fetchall()]
        if "blocked" not in usercols:
            cursor.execute("ALTER TABLE users ADD COLUMN blocked INTEGER DEFAULT 0")
            print("Migrated users: added blocked column")
        # ensure email column exists
        if "email" not in usercols:
            try:
                cursor.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")
                print("Migrated users: added email column")
            except Exception:
                pass
        # Create login logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                login_time TEXT NOT NULL
            )
        """)
        
        # Create failed logins table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS failed_logins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        
        # Create scan logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        
        # --- MIGRATIONS / ALTERATIONS FOR EXISTING DATABASE ---
        # Ensure login_logs has ip_address column (older DBs lack it)
        cursor.execute("PRAGMA table_info(login_logs)")
        existing = [row[1] for row in cursor.fetchall()]
        if "ip_address" not in existing:
            cursor.execute("ALTER TABLE login_logs ADD COLUMN ip_address TEXT DEFAULT ''")
            print("Migrated login_logs: added ip_address column")

        conn.commit()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {e}")
    finally:
        conn.close()

    # Ensure OTP table exists
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS otp_codes (id INTEGER PRIMARY KEY AUTOINCREMENT, identifier TEXT, method TEXT, code TEXT, expiry TEXT)")
        conn.commit()
        conn.close()
    except Exception:
        pass


# =========================
# AUTH CHECK DECORATOR
# =========================

def login_required():

    if "user" not in session:
        return False

    return True


# =========================
# LOGIN ROUTE
# =========================

# make login available at both root and /login for clarity
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:

            flash("Username and password required")
            return redirect(url_for("login"))

        failed_attempts = get_failed_attempts(username)

        if failed_attempts >= 5:

            flash("Account locked due to multiple failed attempts")
            return redirect(url_for("login"))

        # debug info
        print(f"Attempt login: {username} (failed attempts {failed_attempts})")

        if verify_user(username, password):

            session["user"] = username

            log_login(username)

            flash("Login successful")

            print(f"User {username} authenticated, redirecting to dashboard")

            return redirect(url_for("dashboard"))

        else:

            print(f"Authentication failed for user {username}")
            log_failed_login(username)

            remaining = max(0, 5 - (failed_attempts + 1))

            flash(f"Login failed. Remaining attempts: {remaining}")

            return redirect(url_for("login"))

    return render_template("login.html")


# =========================
# OTP LOGIN ROUTE
# =========================

@app.route("/login/otp", methods=["GET", "POST"])
def login_otp():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        method = "email" # Forced email-only

        # Check if user exists and get email
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username, email FROM users WHERE username=? OR email=?", (identifier, identifier))
        user_row = cursor.fetchone()
        conn.close()

        if not user_row:
            flash("No account found with that identity")
            return redirect(url_for("login_otp"))

        username, user_email = user_row
        if not user_email and "@" not in identifier:
            flash("No email registered for this account. Please use password login.")
            return redirect(url_for("login_otp"))

        target_email = user_email if user_email else identifier

        # Create and send OTP
        code = create_otp(username, method="email")

        # Real Email Delivery Logic
        try:
            import smtplib
            from email.message import EmailMessage
            smtp_host = os.environ.get("SMTP_HOST")
            smtp_port = int(os.environ.get("SMTP_PORT", "0"))
            smtp_user = os.environ.get("SMTP_USER")
            smtp_pass = os.environ.get("SMTP_PASS")

            if smtp_host and smtp_port and smtp_user and smtp_pass:
                msg = EmailMessage()
                msg.set_content(f"Your CyberShield Login OTP is: {code}.\nThis code is valid for 10 minutes.")
                msg["Subject"] = "CyberShield Security Token"
                msg["From"] = smtp_user
                msg["To"] = target_email
                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
                flash(f"Security token sent to {target_email}")
            else:
                flash("SMTP server not configured. Please contact the administrator.")
                return redirect(url_for("login_otp"))
        except Exception as e:
            print(f"SMTP Error: {e}")
            flash(f"Failed to transmit security token: {str(e)}")
            return redirect(url_for("login_otp"))

        session["otp_username"] = username
        flash("Enter the code sent to your email")
        return redirect(url_for("login_otp_verify"))

    return render_template("login_otp.html")


@app.route("/login/otp/verify", methods=["GET", "POST"])
def login_otp_verify():
    username = session.get("otp_username")
    if not username:
        return redirect(url_for("login_otp"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        if verify_otp(username, code):
            session.pop("otp_username", None)
            session["user"] = username
            log_login(username)
            flash("Login successful via OTP")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid or expired OTP")
            return redirect(url_for("login_otp_verify"))

    return render_template("login_otp_verify.html", username=username)


# =========================
# RESET PASSWORD ROUTE
# =========================

@app.route("/reset", methods=["GET", "POST"])
def reset_password():
    # Two-step reset with OTP
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        # Forced email method
        method = "email"

        # Find user and get email
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username, email FROM users WHERE username=? OR email=?", (identifier, identifier))
        user_row = cursor.fetchone()
        conn.close()

        if not user_row:
            flash("No account found with that identifier")
            return redirect(url_for("reset_password"))

        username, user_email = user_row

        # create and send OTP
        code = create_otp(identifier, method=method)

        sent_to = user_email or identifier
        # Real Email Delivery Logic
        try:
            import smtplib
            from email.message import EmailMessage

            smtp_host = os.environ.get("SMTP_HOST")
            smtp_port = int(os.environ.get("SMTP_PORT", "0"))
            smtp_user = os.environ.get("SMTP_USER")
            smtp_pass = os.environ.get("SMTP_PASS")

            if smtp_host and smtp_port and smtp_user and smtp_pass:
                msg = EmailMessage()
                msg.set_content(f"Your CyberShield Identity Recovery OTP is: {code}.\nThis code is valid for 10 minutes.")
                msg["Subject"] = "CyberShield Recovery Token"
                msg["From"] = smtp_user
                msg["To"] = sent_to

                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
                flash(f"Recovery token sent to {sent_to}")
            else:
                flash("SMTP server not configured. Please check your .env settings.")
                return redirect(url_for("reset_password"))
        except Exception as e:
            print(f"SMTP Error: {e}")
            flash(f"Failed to transmit security token: {str(e)}")
            return redirect(url_for("reset_password"))

        session["reset_identifier"] = identifier
        session["reset_method"] = method

        flash("OTP sent. Enter the code and new password.")
        return redirect(url_for("reset_verify"))

    return render_template("reset.html")


@app.route("/reset/verify", methods=["GET", "POST"])
def reset_verify():
    identifier = session.get("reset_identifier")

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()

        if not identifier:
            flash("Reset session expired. Start again.")
            return redirect(url_for("reset_password"))

        if not otp or not password or not confirm:
            flash("All fields are required")
            return redirect(url_for("reset_verify"))

        if password != confirm:
            flash("Passwords do not match")
            return redirect(url_for("reset_verify"))

        if not verify_otp(identifier, otp):
            flash("Invalid or expired OTP")
            return redirect(url_for("reset_verify"))

        # find username for identifier
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username=? OR email=?", (identifier, identifier))
        row = cursor.fetchone()
        conn.close()

        if not row:
            flash("User not found for identifier")
            return redirect(url_for("reset_password"))

        username = row[0]

        if change_password(username, password):
            session.pop("reset_identifier", None)
            session.pop("reset_method", None)
            flash("Password updated. Please login.")
            return redirect(url_for("login"))
        else:
            flash("Failed to update password")
            return redirect(url_for("reset_verify"))

    return render_template("reset_verify.html", identifier=identifier)


# =========================
# REGISTER ROUTE
# =========================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        email = request.form.get("email", "").strip() or None

        if not username or not password:

            flash("Username and password required")
            return redirect(url_for("register"))

        if create_user(username, password, email=email):

            flash("Registration successful. Please login.")
            return redirect(url_for("login"))

        else:

            flash("User already exists")
            return redirect(url_for("register"))

    return render_template("register.html")


# =========================
# DASHBOARD
# =========================

@app.route("/dashboard")
def dashboard():

    if not login_required():
        return redirect(url_for("login"))

    session.pop("is_admin", None)

    return render_template("dashboard.html")


# =========================
# LOGOUT
# =========================

@app.route("/logout")
def logout():

    session.clear()

    flash("Logged out successfully")

    return redirect(url_for("login"))


# =========================
# ADMIN PANEL
# =========================

@app.route("/admin", methods=["GET", "POST"])
def admin():

    if not login_required():
        return redirect(url_for("login"))

    # Require admin password each time (do not persist in session)
    if request.method == "POST":
        admin_pass = request.form.get("admin_password", "")
        expected = os.environ.get("ADMIN_PASSWORD", "Admin*0011")
        if admin_pass == expected:
            session["is_admin"] = True
            flash("Admin authenticated")
            # continue to render admin panel below
        else:
            flash("Invalid admin password")
            return render_template("admin_auth.html")

    # If not authenticated as admin in session, show prompt
    if not session.get("is_admin"):
        return render_template("admin_auth.html")

    conn = get_db()
    cursor = conn.cursor()
    # Total users
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    # Total successful logins
    cursor.execute("SELECT COUNT(*) FROM login_logs")
    total_logins = cursor.fetchone()[0]

    # Successful login logs (include id for per-entry actions)
    cursor.execute("""
        SELECT id, username, ip_address, login_time
        FROM login_logs
        ORDER BY login_time DESC
    """)

    logs = []

    for row in cursor.fetchall():
        # row: (id, username, ip_address, login_time)
        utc_time = row[3]
        try:
            utc_dt = datetime.strptime(utc_time, "%Y-%m-%d %H:%M:%S")
            ist_dt = utc_dt + timedelta(hours=5, minutes=30)
            pretty = ist_dt.strftime("%d/%m/%Y %H:%M:%S")
        except Exception:
            pretty = utc_time

        logs.append((row[0], row[1], row[2], pretty))

    # Failed logins (include id for per-entry actions)
    cursor.execute("""
        SELECT id, username, ip_address, timestamp
        FROM failed_logins
        ORDER BY timestamp DESC
    """)

    failed_logs = []
    for row in cursor.fetchall():
        # row: (id, username, ip_address, timestamp)
        utc_time = row[3]
        try:
            utc_dt = datetime.strptime(utc_time, "%Y-%m-%d %H:%M:%S")
            ist_dt = utc_dt + timedelta(hours=5, minutes=30)
            pretty = ist_dt.strftime("%d/%m/%Y %H:%M:%S")
        except Exception:
            pretty = utc_time
        failed_logs.append((row[0], row[1], row[2], pretty))

    # fetch users for management table
    cursor.execute("SELECT id, username, blocked FROM users ORDER BY username")
    users = cursor.fetchall()

    conn.close()

    return render_template(
        "admin.html",
        total_users=total_users,
        total_logins=total_logins,
        logs=logs,
        failed_logs=failed_logs,
        users=users
    )


# =========================
# USER MANAGEMENT ACTIONS
# =========================

@app.route("/admin/user_action", methods=["POST"])
def admin_user_action():
    if not login_required():
        return redirect(url_for("login"))
    if not session.get("is_admin"):
        flash("Admin access required")
        return redirect(url_for("admin"))

    username = request.form.get("username")
    action = request.form.get("action")

    conn = get_db()
    cursor = conn.cursor()

    if action == "delete":
        cursor.execute("DELETE FROM users WHERE username=?", (username,))
        flash(f"User {username} removed")
    elif action == "toggle_block":
        # flip blocked flag
        cursor.execute("SELECT blocked FROM users WHERE username=?", (username,))
        row = cursor.fetchone()
        if row:
            newval = 0 if row[0] else 1
            cursor.execute("UPDATE users SET blocked=? WHERE username=?", (newval, username))
            status = "unblocked" if newval == 0 else "blocked"
            flash(f"User {username} {status}")
    else:
        flash("Unknown action")

    conn.commit()
    conn.close()

    return redirect(url_for("admin"))


@app.route("/admin/delete_log", methods=["POST"])
def admin_delete_log():
    if not login_required():
        return redirect(url_for("login"))
    if not session.get("is_admin"):
        flash("Admin access required")
        return redirect(url_for("admin"))

    log_type = request.form.get("log_type")
    entry_id = request.form.get("id")

    if not entry_id:
        flash("No log entry specified")
        return redirect(url_for("admin"))

    conn = get_db()
    cursor = conn.cursor()

    try:
        if log_type == "success":
            cursor.execute("DELETE FROM login_logs WHERE id=?", (entry_id,))
            flash("Selected successful login entry removed")
        elif log_type == "failed":
            cursor.execute("DELETE FROM failed_logins WHERE id=?", (entry_id,))
            flash("Selected failed login attempt removed")
        else:
            flash("Unknown log type for deletion")

        conn.commit()
    except Exception as e:
        flash(f"Failed to remove log entry: {e}")
    finally:
        conn.close()

    return redirect(url_for("admin"))


@app.route("/admin/clear_logs", methods=["POST"])
def admin_clear_logs():
    if not login_required():
        return redirect(url_for("login"))

    if not session.get("is_admin"):
        flash("Admin access required")
        return redirect(url_for("admin"))

    log_type = request.form.get("log_type")

    conn = get_db()
    cursor = conn.cursor()

    if log_type == "success":
        cursor.execute("DELETE FROM login_logs")
        flash("All successful login history cleared")
    elif log_type == "failed":
        cursor.execute("DELETE FROM failed_logins")
        flash("All failed login attempts history cleared")
    else:
        flash("Unknown log type")

    conn.commit()
    conn.close()

    return redirect(url_for("admin"))


# =========================
# PORT SCAN
# =========================

@app.route("/portscan", methods=["POST"])
def portscan():

    if not login_required():
        return redirect(url_for("login"))

    target = request.form.get("target", "").strip()

    if not target:
        flash("Target required")
        return redirect(url_for("dashboard"))

    # Simple validation for IP or Domain
    is_ip = re.match(r"^(\d{1,3}\.){3}\d{1,3}$", target)
    is_domain = re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target)
    
    if not (is_ip or is_domain):
        flash("Please enter a valid IP address or domain name (e.g., 192.168.1.1 or example.com)")
        return redirect(url_for("dashboard"))

    ports = scan_ports(target)

    create_scan_log("Port Scan", target, str(ports))

    return render_template(
        "dashboard.html",
        ports=ports,
        target=target
    )


# =========================
# WEB SCAN
# =========================

@app.route("/webscan", methods=["POST"])
def webscan():

    if not login_required():
        return redirect(url_for("login"))

    url = request.form.get("url", "").strip()

    if not url:
        flash("URL required")
        return redirect(url_for("dashboard"))

    # Validate URL/Domain
    if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", url) and not url.startswith("http"):
        flash("Please check and enter a valid URL (e.g., example.com)")
        return redirect(url_for("dashboard"))

    if not url.startswith("http"):
        url = "http://" + url

    results = scan_website(url)

    create_scan_log("Web Scan", url, str(results))

    return render_template(
        "dashboard.html",
        web_results=results,
        scanned_url=url
    )


# =========================
# SAFEWEB ANALYZER
# =========================

@app.route("/safeweb", methods=["POST"])
def safeweb():

    if not login_required():
        return redirect(url_for("login"))

    query = request.form.get("url", "").strip()

    if not query:
        flash("URL required for analysis")
        return redirect(url_for("dashboard"))

    # Validate URL/Domain
    if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", query) and not query.startswith("http"):
        flash("Please check and enter a valid URL or domain for analysis")
        return redirect(url_for("dashboard"))

    response = analyze_url(query)
    results = response['findings']
    status = response['status']
    log_target = query

    create_scan_log("SafeWeb URL Analysis", log_target, f"[{status}] {str(results)}")

    return render_template(
        "dashboard.html",
        safeweb_results=results,
        safeweb_status=status,
        analyzed_url=log_target
    )


# =========================
# NETWORK SCAN
# =========================

@app.route("/networkscan", methods=["POST"])
def networkscan():

    if not login_required():
        return redirect(url_for("login"))

    base_ip = request.form.get("base_ip", "").strip()

    if not base_ip:
        flash("Network IP required")
        return redirect(url_for("dashboard"))

    # Validate IP prefix (e.g., 192.168.1)
    if not re.match(r"^(\d{1,3}\.){2}\d{1,3}$", base_ip):
        flash("Please enter a valid network IP prefix (e.g., 192.168.1)")
        return redirect(url_for("dashboard"))

    hosts = scan_network(base_ip)

    create_scan_log("Network Scan", base_ip, str(hosts))

    return render_template(
        "dashboard.html",
        network_hosts=hosts,
        base_ip=base_ip
    )


# =========================
# FILE CHECK
# =========================

@app.route("/filecheck", methods=["POST"])
def filecheck():

    if not login_required():
        return redirect(url_for("login"))

    file_path = request.form.get("file_path")

    if not file_path or not os.path.exists(file_path):

        flash("File not found")
        return redirect(url_for("dashboard"))

    analysis = check_file_integrity(file_path)

    create_scan_log("File Check", file_path, analysis["status"])

    return render_template(
        "dashboard.html",
        file_status=analysis["status"],
        file_message=analysis["message"],
        file_saved=analysis["last_saved"],
        file_path=file_path
    )


# =========================
# SAVE HASH
# =========================

@app.route("/savehash", methods=["POST"])
def savehash():

    if not login_required():
        return redirect(url_for("login"))

    file_path = request.form.get("file_path")

    if not file_path or not os.path.exists(file_path):

        flash("File not found")
        return redirect(url_for("dashboard"))

    save_file_hash(file_path)

    create_scan_log("Hash Saved", file_path, "Original hash stored")

    flash("Hash saved successfully")

    return redirect(url_for("dashboard"))


# =========================
# SCAN LOGS
# =========================

@app.route("/scanlogs")
def scanlogs():

    if not login_required():
        return redirect(url_for("login"))

    session.pop("is_admin", None)

    conn = get_db()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT scan_type, target, result, timestamp
        FROM scan_logs
        ORDER BY timestamp DESC
    """)

    logs = cursor.fetchall()

    conn.close()

    return render_template("scanlogs.html", logs=logs)


# =========================
# MAIN
# =========================

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )