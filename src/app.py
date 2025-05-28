import os
import sys
from os.path import relpath
from flask import Flask, flash, g, render_template, request, session, url_for, redirect , jsonify , send_from_directory
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from helpers import login_required, generate_token , verify_token, validate_email , encrypt_message , decrypt_message, generate_unique_filename
from validation import (
    InputValidator, CSRFTokenGenerator, validate_login_form, 
    validate_registration_form, validate_user_form, validate_patient_form,
    validate_doctor_form, validate_password_reset_form, validate_appointment_form,
    validate_prescription_form, validate_medical_record_form, validate_file_upload_form,
    validate_expense_form
)
import sqlite3
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, date, timedelta
import re
import calendar
from collections import defaultdict
from flask_socketio import SocketIO, emit , join_room, leave_room

# Import CSRF protection and forms
try:
    # from flask_wtf.csrf import CSRFProtect, CSRFError  # Commented out if not available
    CSRF_AVAILABLE = True
except ImportError:
    print("Warning: Flask-WTF not available. Using custom CSRF protection.")
    CSRF_AVAILABLE = False



app = Flask(__name__)
socketio = SocketIO(app)

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Generate a secure secret key for CSRF protection
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# Configure Flask environment
app.config['ENV'] = os.getenv('FLASK_ENV', 'development')
app.config['DEBUG'] = os.getenv('DEBUG', 'True').lower() == 'true'

# Initialize CSRF Protection
if CSRF_AVAILABLE:
    # csrf = CSRFProtect(app)  # Commented out if not available
      # @app.errorhandler(CSRFError)  # Commented out if not available
    def handle_csrf_error(e):
        flash('Security token expired. Please try again.', 'error')
        return render_template('csrf_error.html', reason=e.description), 400
else:
    # Custom CSRF protection when Flask-WTF is not available
    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=CSRFTokenGenerator.generate_token)
    
    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            token = request.form.get('csrf_token')
            if not CSRFTokenGenerator.validate_token(token):
                flash('Security token missing or invalid. Please try again.', 'error')
                return redirect(request.url)

# Custom CSRF validation helper
def validate_csrf_token():
    """Validate CSRF token for manual validation when needed"""
    if CSRF_AVAILABLE:
        # Flask-WTF handles CSRF automatically, so we just return True here
        # If there was a CSRF error, it would have been caught by Flask-WTF's error handler
        return True
    else:
        # Manual CSRF validation for custom implementation
        token = request.form.get('csrf_token')
        return CSRFTokenGenerator.validate_token(token)


# Configuration for session

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg'}
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configuration for database - Environment-based selection
if os.getenv('FLASK_ENV') == 'production':
    DATABASE = 'database/mediflow_production.db'
else:
    DATABASE = 'database/mediflow.db'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        # Check if database exists before connecting
        if not os.path.exists(DATABASE):
            raise FileNotFoundError(
                f"Database file '{DATABASE}' does not exist. "
                f"Please run 'python init_database.py' to create the database first."
            )
        db = g._database = sqlite3.connect(DATABASE)
    return db.cursor()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.after_request
def after_request(response):
    """Ensure responses aren't cached and add security headers"""
    # Cache control headers
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    
    # Security headers for production
    if os.getenv('FLASK_ENV') == 'production':
        # Prevent clickjacking attacks
        response.headers["X-Frame-Options"] = "DENY"
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Enable XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Strict Transport Security (HTTPS only)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
          # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://code.jquery.com https://cdn.jsdelivr.net https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://cdn.jsdelivr.net https://unpkg.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net https://unpkg.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        
        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Feature Policy / Permissions Policy
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )
    
    return response

def format_phone_number(phone_number):
    # Handle None or empty values
    if phone_number is None or phone_number == '':
        return 'N/A'
    
    # Ensure phone_number is a string
    phone_number = str(phone_number)
    
    # Check if the phone number is already formatted
    pattern = r'^\(\d{3}\) \d{3}-\d{4}$'
    if re.match(pattern, phone_number):
        return phone_number

    # Remove any non-digit characters from the input
    phone_number = re.sub(r'\D', '', phone_number)

    # Check if the phone number has the correct length
    if len(phone_number) != 10:
        return phone_number

    # Format the phone number
    formatted_number = "({}) {}-{}".format(phone_number[:3], phone_number[3:6], phone_number[6:])
    return formatted_number

app.jinja_env.filters['format_phone'] = format_phone_number

# Define a custom Jinja filter for converting military time to standard time
def military_to_standard_time(time_str):
    if not time_str:  # Check if time_str is empty
        return "None"  # Or any other appropriate action
    military_time = datetime.strptime(time_str, '%H:%M')
    return military_time.strftime('%I:%M %p')

# Add the filter to the Jinja environment
app.jinja_env.filters['military_to_standard_time'] = military_to_standard_time


@app.route("/register", methods=["POST" , "GET"])
def register():
    error_messages = []

    if request.method == "POST":
        # Validate form input using secure validation
        validation_errors, validated_data = validate_registration_form()
        print(f"Validation errors: {validation_errors}")    
        if validation_errors:
            error_messages.extend(validation_errors)
        else:
            try:
                db = get_db()
                # Double-check email uniqueness (already checked in validation, but be extra safe)
                db.execute("SELECT id FROM admins WHERE LOWER(email) = ?", (validated_data["email"],))
                if db.fetchone():
                    error_messages.append("Email is already in use")
                else:
                    hashed_password = generate_password_hash(validated_data["password"])
                    db.execute("INSERT INTO admins (email, hash, first_name, last_name) VALUES (?, ?, ?, ?)",
                               (validated_data["email"], hashed_password, validated_data["first_name"], validated_data["last_name"]))
                    db.connection.commit()
                    flash("Successfully registered! You can now login to your account.", "success")
                    return redirect("/login")
                    
            except sqlite3.Error as e:
                error_messages.append("Database error occurred. Please try again.")
                print(f"Database error in register: {e}")

    # Generate CSRF token for the form
    csrf_token = CSRFTokenGenerator.generate_token() if not CSRF_AVAILABLE else None
    
    return render_template("register.html", 
                         error_messages=error_messages,
                         csrf_token=csrf_token)


@app.route("/forgotten", methods=["GET", "POST"])
def forgotten():
    if request.method == "POST":
        email = request.form.get("email").lower()
        error_message = None  # Initialize error message variable
        if not email and not validate_email(email):
            error_message = "Invalid email address"
            if error_message:
                return render_template("forgotten.html", error_message = error_message)

        try:
            db = get_db()
            admin = db.execute("SELECT * FROM admins WHERE email = ?", (email,)).fetchone()
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            doctors = db.execute("SELECT * FROM doctors WHERE email = ?" , (email,)).fetchone()

            if not admin and not user and not doctors:
                error_message = "No users found with this email address"

            if error_message:
                return render_template("forgotten.html", error_message=error_message)

            reset_token = generate_token(email)  # Generate reset token
            if admin:
                db.execute("UPDATE admins SET reset_token = ? WHERE id = ?", (reset_token, admin[0]))
            elif user:
                db.execute("UPDATE users SET reset_token = ? WHERE users_id = ?", (reset_token, user[0]))
            else:
                db.execute("UPDATE doctors SET reset_token = ? WHERE doctor_id = ?", (reset_token, doctors[0]))

            db.connection.commit()

            reset_link =  f"http://127.0.0.1:5000/reset?token={reset_token}&email={email}"  # Replace with actual website url

            message = MIMEMultipart()
            message['From'] = "mediflow31@gmail.com"
            message['To'] = admin[1] if admin else user[1]
            message['Subject'] = "Password Reset Request"

            recipient_name = admin[2] if admin else user[3] if user else doctors[2]


            intro_message = f"Hi {recipient_name},\n\n"
            reset_password_message = "We received a request to reset your password. If this was you, please click the link below (expires after one hour):\n\n"
            reset_password_link = f"<a href='{reset_link}'>Reset Password</a>"
            ignore_message = "If you didn't request a password reset, you can ignore this email.\n\n"
            signature = "Thanks,\nThe Mediflow Team"

            body = intro_message + reset_password_message + reset_password_link + "\n\n" + ignore_message + signature

            message.attach(MIMEText(body, 'html'))

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login("mediflow31@gmail.com", "ywav hzor zqbp cadv")
                server.sendmail("mediflow31@gmail.com", message['To'], message.as_string())

            return render_template("success.html")

        except sqlite3.Error as e:
            error_message = "Database error: " + str(e)

        except Exception as e:
            error_message = "An error occurred: " + str(e)

        finally:
            if 'db' in locals():
                db.close()  # Close the database connection

        return render_template("forgotten.html", error_message=error_message)

    else:
        return render_template("forgotten.html")


@app.route("/reset", methods=["GET", "POST"])
def reset():
    error_message = None
    token = request.args.get("token")
    email = request.args.get("email")

    if request.method == "POST":
        # Validate form input using secure validation
        validation_errors, validated_data = validate_password_reset_form()
        
        if validation_errors:
            error_message = validation_errors[0]  # Show first error for compatibility
            return render_template("reset.html", error_message=error_message)

        try:
            db = get_db()
            
            # Verify token and email combination
            admin_token = db.execute("SELECT reset_token FROM admins WHERE email = ?", (email,)).fetchone()
            user_token = db.execute("SELECT reset_token FROM users WHERE email = ?", (email,)).fetchone()
            doctor_token = db.execute("SELECT reset_token FROM doctors WHERE email = ?", (email,)).fetchone()

            # Check if token matches any of the stored tokens
            token_valid = False
            user_type = None
            
            if admin_token and token == admin_token[0]:
                token_valid = True
                user_type = "admin"
            elif user_token and token == user_token[0]:
                token_valid = True
                user_type = "user"
            elif doctor_token and token == doctor_token[0]:
                token_valid = True
                user_type = "doctor"
            
            if not token_valid:
                error_message = "Invalid or expired token"
                return render_template("reset.html", error_message=error_message)

            # Verify token hasn't expired
            if not verify_token(token):
                flash("Link has expired. Please enter your email address to get another one", "error")
                return redirect("/forgotten")

            if not email:
                error_message = "Please enter an email address"
                return render_template("reset.html", error_message=error_message)

            # Update password based on user type
            hashed_password = generate_password_hash(validated_data["password"])
            
            if user_type == "admin":
                db.execute("UPDATE admins SET hash = ?, reset_token = NULL WHERE email = ?", (hashed_password, email))
            elif user_type == "user":
                db.execute("UPDATE users SET hash = ?, reset_token = NULL WHERE email = ?", (hashed_password, email))
            elif user_type == "doctor":
                db.execute("UPDATE doctors SET hash = ?, reset_token = NULL WHERE email = ?", (hashed_password, email))

            db.connection.commit()
            flash("Successfully changed password. You can now login with your new password.", "success")
            return redirect("/login")

        except sqlite3.Error as e:
            error_message = "Database error occurred. Please try again."    # Validate that we have a token for GET requests
    if not token:
        return redirect("/login")
    
    return render_template("reset.html", error_message=error_message)



@app.route("/login", methods=["GET", "POST"])
def login():
    error_messages = []

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        # Validate form input using secure validation
        validation_errors, validated_data = validate_login_form()
        
        if validation_errors:
            error_messages.extend(validation_errors)
        else:
            email = validated_data["email"]
            password = validated_data["password"]
            
            
            try:
                db = get_db()
                admin = db.execute("SELECT * FROM admins WHERE email = ?", (email,)).fetchone()
                user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
                doctor = db.execute("SELECT * FROM doctors WHERE email = ?", (email,)).fetchone()
                if admin and check_password_hash(admin[4], password):  # Access hash using index 4
                    session["user_id"] = admin[0]  # Access id using index 0
                    session["user_type"] = "admin"
                    flash(f"Welcome back, {admin[2]}!", "success")
                    return redirect("/")
                elif user and check_password_hash(user[2], password):  # Access hash using index 2
                    session["user_id"] = user[0]  # Access users_id using index 0
                    session["user_type"] = user[5]
                    flash(f"Welcome back, {user[3]}!", "success")  # Show first name
                    if session["user_type"] == "Receptionist":
                        return redirect("/receptionist")
                elif doctor and check_password_hash(doctor[10], password):
                    session["user_id"] = doctor[0]
                    session["user_type"] = doctor[11]
                    flash(f"Welcome back, Dr. {doctor[2]}!", "success")  # Show last name
                    if session["user_type"] == "Doctor":
                        return redirect("/doctor")
                else:
                    error_messages.append("Invalid email and/or password")
                    
            except sqlite3.Error as e:
                error_messages.append("Database error occurred. Please try again.")
                print(f"Database error in login: {e}")    # Generate CSRF token for the form
    csrf_token = CSRFTokenGenerator.generate_token() if not CSRF_AVAILABLE else None
    
    return render_template("login.html", 
                         error_messages=error_messages,
                         csrf_token=csrf_token)


@app.route("/logout")
def logout():
    session.clear()
    # Redirect user to login form
    return redirect("/")

#messages----------------------------------------------------------


# Function to handle connection
@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    user_type = session.get('user_type')
    if user_id and user_type:
        room = f"{user_type}_{user_id}"
        join_room(room)
        print(f"User {user_id} connected and joined room {room}")
    else:
        print("User not authenticated")

# Function to handle disconnection
@socketio.on('disconnect')
def handle_disconnect():
    user_id = session.get('user_id')
    user_type = session.get('user_type')
    if user_id and user_type:
        room = f"{user_type}_{user_id}"
        leave_room(room)
        print(f"User {user_id} disconnected and left room {room}")



@socketio.on("private_message")
def handle_private_message(data):
    try:
        receiver_id = data["receiver_id"]
        receiver_user_type = data["receiver_user_type"]
        message = data["message"]
        sender_id = session.get("user_id")  # Get sender's user ID from session
        sender_user_type = session.get("user_type")
        timestamp = datetime.now() # Get current timestamp


        # Connect to the SQLite database
        db = get_db()

        # Generate encryption key
        key = os.urandom(32)

        # Encrypt the message
        encrypted_message, iv = encrypt_message(key, message)


        # Insert the message into the messages table
        db.execute("INSERT INTO messages (sender_id, receiver_id, message, iv, timestamp, encryption_key, receiver_user_type, sender_user_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   (sender_id, receiver_id, encrypted_message, iv, timestamp, key, receiver_user_type, sender_user_type))
        db.connection.commit()

        sender_room = f"{sender_user_type}_{sender_id}"
        receiver_room = f"{receiver_user_type}_{receiver_id}"

        # Emit the message to the recipient's room
        socketio.emit('private_message', {'message': message, 'sender_id': sender_id , 'sender_user_type' : sender_user_type}, room=receiver_room)

    except Exception as e:
        print("Error:", e)
    finally:
        db.close()  # Close the database connection



@app.route("/messages", methods=["GET", "POST"])
@login_required
def messages():
    error_message = None
    user_id = session.get("user_id")
    sender_type = session.get("user_type")

    # Check if the user is logged in and has the appropriate user type
    if sender_type not in ["admin", "Doctor", "Receptionist"]:
        return render_template("404.html"), 404

    db = get_db()
    admins = {}  # Initialize admins here

    if request.method == "POST":
        # Handle message sending
        selected_user_type = request.form.get("userType")
        message = request.form.get("message")

        # Check if the selected user type is valid
        if selected_user_type not in ["admin", "Doctor", "Receptionist"]:
            error_messages = "Invalid user"
            return render_template("messages.html", error_messages = error_messages)

        if sender_type == "admin":
            # Get the receiver ID based on the selected user type
            if selected_user_type == "Doctor":
                receiver_id = request.form.get("doctor")
            elif selected_user_type == "Receptionist":
                receiver_id = request.form.get("receptionist")

        elif sender_type == "Doctor":
            if selected_user_type == "Receptionist":
                receiver_id = request.form.get("receptionist")
            elif selected_user_type == "admin":
                receiver_id = request.form.get("admin")
            else:
                return render_template("messages.html", error="Receiver ID not provided"), 400

        elif sender_type == "Receptionist":
            if selected_user_type == "Doctor":
                receiver_id = request.form.get("doctor")
            elif selected_user_type == "admin":
                receiver_id = request.form.get("admin")
            else:
                return render_template("messages.html", error="Receiver ID not provided"), 400

        key = os.urandom(32)  # Make sure to set it as an environment variable

        # Encrypt the message
        encrypted_data, iv = encrypt_message(key, message)

        # Store the encrypted data and initialization vector in the database
        try:
            db.execute("INSERT INTO messages (sender_id, sender_user_type, receiver_id, receiver_user_type, message, iv, encryption_key) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (user_id, sender_type, receiver_id, selected_user_type, encrypted_data, iv, key))
            db.connection.commit()
            return redirect("/messages")
        except sqlite3.Error as e:
            error_message = "Database error: " + str(e)
            return render_template("messages.html", error_message=error_message, admins=admins), 500

    elif request.method == "GET":
        user_id = session.get("user_id")
        user_type = session.get("user_type")
        db = get_db()
        decrypted_messages = []

        if user_type == "admin":
            # Retrieve messages sent to receptionists
            receptionists = db.execute("SELECT users_id, first_name, last_name FROM users WHERE admin_id = ?", (user_id,)).fetchall()
            doctors = db.execute("SELECT doctor_id, last_name FROM doctors WHERE admin_id = ?", (user_id,)).fetchall()

            contacts = db.execute("""
                SELECT DISTINCT
                    m.sender_id AS contact_id,
                    CASE
                        WHEN m.sender_user_type = 'admin' THEN a1.first_name || ' ' || a1.last_name
                        WHEN m.sender_user_type = 'Doctor' THEN d1.first_name || ' ' || d1.last_name
                        WHEN m.sender_user_type = 'Receptionist' THEN u1.first_name || ' ' || u1.last_name
                    END AS contact_name,
                    m.sender_user_type
                FROM messages m
                LEFT JOIN admins a1 ON m.sender_id = a1.id AND m.sender_user_type = 'admin'
                LEFT JOIN doctors d1 ON m.sender_id = d1.doctor_id AND m.sender_user_type = 'Doctor'
                LEFT JOIN users u1 ON m.sender_id = u1.users_id AND m.sender_user_type = 'Receptionist'
                WHERE m.receiver_id = ? AND m.receiver_user_type = 'admin'
            UNION
                SELECT DISTINCT
                    m.receiver_id AS contact_id,
                    CASE
                        WHEN m.receiver_user_type = 'admin' THEN a2.first_name || ' ' || a2.last_name
                        WHEN m.receiver_user_type = 'Doctor' THEN d2.first_name || ' ' || d2.last_name
                        WHEN m.receiver_user_type = 'Receptionist' THEN u2.first_name || ' ' || u2.last_name
                    END AS contact_name,
                    m.receiver_user_type
                FROM messages m
                LEFT JOIN admins a2 ON m.receiver_id = a2.id AND m.receiver_user_type = 'admin'
                LEFT JOIN doctors d2 ON m.receiver_id = d2.doctor_id AND m.receiver_user_type = 'Doctor'
                LEFT JOIN users u2 ON m.receiver_id = u2.users_id AND m.receiver_user_type = 'Receptionist'
                WHERE m.sender_id = ? AND m.sender_user_type = 'admin'
            """, (user_id, user_id)).fetchall()

            if contacts:
                return render_template("messages.html", contacts=contacts , doctors = doctors, receptionists=receptionists , user_id = user_id , user_type = user_type)
            else:
                sender_name = None
                receiver_name = None
                contatcs = None

                # Render the template
                return render_template("messages.html", doctors=doctors, receptionists=receptionists , user_id = user_id , user_type = user_type)


        elif user_type == "Doctor":
            admin_id = db.execute("SELECT admin_id FROM doctors WHERE doctor_id = ?", (user_id,)).fetchone()[0]
            receptionists = db.execute("SELECT users_id, first_name, last_name FROM users WHERE admin_id = ?", (admin_id,)).fetchall()
            admin_info = db.execute("SELECT id, first_name, last_name FROM admins WHERE id = ?", (admin_id,)).fetchone()
            admins = {"id": admin_info[0], "first_name": admin_info[1], "last_name": admin_info[2]}

            # Fetch conatcs for this user
            contacts = db.execute("""
                SELECT DISTINCT
                    m.sender_id AS contact_id,
                    CASE
                        WHEN m.sender_user_type = 'admin' THEN a1.first_name || ' ' || a1.last_name
                        WHEN m.sender_user_type = 'Doctor' THEN d1.first_name || ' ' || d1.last_name
                        WHEN m.sender_user_type = 'Receptionist' THEN u1.first_name || ' ' || u1.last_name
                    END AS contact_name,
                    m.sender_user_type
                FROM messages m
                LEFT JOIN admins a1 ON m.sender_id = a1.id AND m.sender_user_type = 'admin'
                LEFT JOIN doctors d1 ON m.sender_id = d1.doctor_id AND m.sender_user_type = 'Doctor'
                LEFT JOIN users u1 ON m.sender_id = u1.users_id AND m.sender_user_type = 'Receptionist'
                WHERE (m.receiver_id = ? AND m.receiver_user_type = 'Doctor')
                UNION
                SELECT DISTINCT
                    m.receiver_id AS contact_id,
                    CASE
                        WHEN m.receiver_user_type = 'admin' THEN a2.first_name || ' ' || a2.last_name
                        WHEN m.receiver_user_type = 'Doctor' THEN d2.first_name || ' ' || d2.last_name
                        WHEN m.receiver_user_type = 'Receptionist' THEN u2.first_name || ' ' || u2.last_name
                    END AS contact_name,
                    m.receiver_user_type
                FROM messages m
                LEFT JOIN admins a2 ON m.receiver_id = a2.id AND m.receiver_user_type = 'admin'
                LEFT JOIN doctors d2 ON m.receiver_id = d2.doctor_id AND m.receiver_user_type = 'Doctor'
                LEFT JOIN users u2 ON m.receiver_id = u2.users_id AND m.receiver_user_type = 'Receptionist'
                WHERE (m.sender_id = ? AND m.sender_user_type = 'Doctor')
                """, (user_id, user_id)).fetchall()

            if contacts:
                return render_template("messages.html", contacts = contacts , admins = admins , receptionists = receptionists , user_id = user_id , user_type = user_type)
            else:
                sender_name = None
                receiver_name = None
                contatcs = None

                # Render the template
                return render_template("messages.html", admins=admins, receptionists=receptionists , user_id = user_id , user_type = user_type)


        elif user_type == "Receptionist":
            admin_id = db.execute("SELECT admin_id FROM users WHERE users_id = ?", (user_id,)).fetchone()[0]
            doctors = db.execute("SELECT doctor_id, last_name FROM doctors WHERE admin_id = ?", (admin_id,)).fetchall()
            admin_info = db.execute("SELECT id, first_name, last_name FROM admins WHERE id = ?", (admin_id,)).fetchone()
            admins = {"id": admin_info[0], "first_name": admin_info[1], "last_name": admin_info[2]}

            # fetch contacts for receptionist
            contacts = db.execute ("""
                SELECT DISTINCT
                    m.sender_id AS contact_id,
                    CASE
                        WHEN m.sender_user_type = 'admin' THEN a1.first_name || ' ' || a1.last_name
                        WHEN m.sender_user_type = 'Doctor' THEN d1.first_name || ' ' || d1.last_name
                        WHEN m.sender_user_type = 'Receptionist' THEN u1.first_name || ' ' || u1.last_name
                    END AS contact_name,
                    m.sender_user_type
                FROM messages m
                LEFT JOIN admins a1 ON m.sender_id = a1.id AND m.sender_user_type = 'admin'
                LEFT JOIN doctors d1 ON m.sender_id = d1.doctor_id AND m.sender_user_type = 'Doctor'
                LEFT JOIN users u1 ON m.sender_id = u1.users_id AND m.sender_user_type = 'Receptionist'
                WHERE (m.receiver_id = ? AND m.receiver_user_type = 'Receptionist')
                UNION
                SELECT DISTINCT
                    m.receiver_id AS contact_id,
                    CASE
                        WHEN m.receiver_user_type = 'admin' THEN a2.first_name || ' ' || a2.last_name
                        WHEN m.receiver_user_type = 'Doctor' THEN d2.first_name || ' ' || d2.last_name
                        WHEN m.receiver_user_type = 'Receptionist' THEN u2.first_name || ' ' || u2.last_name
                    END AS contact_name,
                    m.receiver_user_type
                FROM messages m
                LEFT JOIN admins a2 ON m.receiver_id = a2.id AND m.receiver_user_type = 'admin'
                LEFT JOIN doctors d2 ON m.receiver_id = d2.doctor_id AND m.receiver_user_type = 'Doctor'
                LEFT JOIN users u2 ON m.receiver_id = u2.users_id AND m.receiver_user_type = 'Receptionist'
                WHERE (m.sender_id = ? AND m.sender_user_type = 'Receptionist')
                """, (user_id, user_id)).fetchall()

            # Decrypt the last message
            if contacts:
                return render_template("messages.html", contacts = contacts , admins = admins , doctors = doctors , user_id = user_id , user_type = user_type)
            else:
                sender_name = None
                receiver_name = None
                contatcs = None

                # Render the template
                return render_template("messages.html", doctors= doctors, admins = admins , user_id = user_id , user_type = user_type)



# Route to fetch messages for a specific user
@app.route("/get_messages/<receiver_id>/<receiver_user_type>", methods=["GET"])
@login_required
def get_messages(receiver_id, receiver_user_type):
    user_id = session.get("user_id")
    user_type = session.get("user_type")
    db = get_db()

    # Execute SQL query to retrieve messages
    query = """
    SELECT * FROM messages
    WHERE
        (sender_id = ? AND sender_user_type = ? AND receiver_id = ? AND receiver_user_type = ?)
        OR
        (sender_id = ? AND sender_user_type = ? AND receiver_id = ? AND receiver_user_type = ?)
    ORDER BY timestamp ASC;
    """
    messages = db.execute(query, (user_id, user_type, receiver_id, receiver_user_type, receiver_id, receiver_user_type, user_id, user_type)).fetchall()

    # Decrypt messages
    decrypted_messages = []
    for msg in messages:
        sender_id = msg[1]
        sender_user_type = msg[2]
        receiver_id = msg[3]
        receiver_user_type = msg[4]
        ciphertext = msg[5]
        iv = msg[6]
        encryption_key = msg[7]
        timestamp = msg[8]

        # Decrypt the message
        decrypted_message = decrypt_message(encryption_key, ciphertext, iv)

        # Append decrypted message to the list
        decrypted_messages.append({
            "sender_id": sender_id,
            "sender_user_type": sender_user_type,
            "receiver_id": receiver_id,
            "receiver_user_type": receiver_user_type,
            "message": decrypted_message,
            "timestamp": timestamp
        })

    # Return the decrypted messages as a JSON response
    return jsonify(decrypted_messages)






#admin ----------------------------------------------------
@app.route("/", methods=["GET"])
@login_required
def index():
    user_type = session.get("user_type")
    if user_type != "admin":
        return render_template("404.html"), 404

    db = get_db()
    admin_id = session.get("user_id")

    # Get today's date
    today_date = date.today()

    # Execute the queries to get the count of patients, appointments, and total revenue for the admin
    patients_count = db.execute("SELECT COUNT(*) FROM patients WHERE created_by IN (SELECT users_id FROM users WHERE admin_id = ?)", (admin_id,)).fetchone()[0]
    # Query to get the count of appointments for today
    appointments_today = db.execute("SELECT COUNT(*) FROM Appointments WHERE date(AppointmentDate) = ? AND created_by IN (SELECT users_id FROM users WHERE admin_id = ?)", (today_date, admin_id)).fetchone()[0]
    appointments_count = db.execute("SELECT COUNT(*) FROM appointments WHERE created_by IN (SELECT users_id FROM users WHERE admin_id = ?)", (admin_id,)).fetchone()[0]
    total_revenue = db.execute("SELECT SUM(amount) AS total_revenue FROM billing WHERE created_by IN (SELECT users_id FROM users WHERE admin_id = ?)", (admin_id,)).fetchone()[0]

    db.execute('''
        SELECT
            admin_id,
            SUM(amount) AS total_amount
        FROM (
            SELECT admin_id, amount FROM medical_supplies
            UNION ALL
            SELECT admin_id, amount FROM utilities
            UNION ALL
            SELECT admin_id, amount FROM equipments
            UNION ALL
            SELECT admin_id, amount FROM marketing
            UNION ALL
            SELECT admin_id, amount FROM other_expenses
        ) AS all_expenses
        WHERE admin_id = ?
        GROUP BY admin_id;
    ''', (admin_id,))

    # Fetch the result
    result = db.fetchone()
    print(result)

    # Ensure total_revenue is not None
    total_revenue = total_revenue if total_revenue else 0

    return render_template("index.html", patients_count=patients_count, appointments_count=appointments_count, total_revenue=total_revenue, appointments_today=appointments_today, result = result)






@app.route("/admin_appointments")
def admin_appointments():
    user_type = session.get("user_type")
    if user_type != "admin":
        return render_template("404.html"), 404

    db = get_db()
    admin_id = session.get("user_id")

    # Calculate the start and end dates for the current week
    start_date_current_week = datetime.now().date() - timedelta(days=datetime.now().weekday())
    end_date_current_week = start_date_current_week + timedelta(days=6)    # Convert dates to string format for SQL query
    start_date_str_current_week = start_date_current_week.strftime('%Y-%m-%d')
    end_date_str_current_week = end_date_current_week.strftime('%Y-%m-%d')

    # Fetch appointments for the current week grouped by weekdays
    data = db.execute('''
        SELECT STRFTIME('%w', AppointmentDate) AS Weekday, COUNT(*) AS AppointmentCount
        FROM Appointments
        WHERE DoctorID IN (SELECT doctor_id FROM doctors WHERE admin_id = ?)
        AND AppointmentDate BETWEEN ? AND ?
        GROUP BY Weekday
    ''', (admin_id, start_date_str_current_week, end_date_str_current_week)).fetchall()

    # Calculate the start and end dates for the previous week
    end_date_previous_week = start_date_current_week - timedelta(days=1)
    start_date_previous_week = end_date_previous_week - timedelta(days=6)    # Convert dates to string format for SQL query
    start_date_str_previous_week = start_date_previous_week.strftime('%Y-%m-%d')
    end_date_str_previous_week = end_date_previous_week.strftime('%Y-%m-%d')

    # Fetch appointments for the previous week grouped by weekdays
    data_previous_week = db.execute('''
        SELECT STRFTIME('%w', AppointmentDate) AS Weekday, COUNT(*) AS AppointmentCount
        FROM Appointments
        WHERE DoctorID IN (SELECT doctor_id FROM doctors WHERE admin_id = ?)
        AND AppointmentDate BETWEEN ? AND ?
        GROUP BY Weekday
    ''', (admin_id, start_date_str_previous_week, end_date_str_previous_week)).fetchall()

    # Convert weekday numbers to weekday names and create dictionaries
    weekday_names = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
    data = {weekday_names[int(row[0])]: row[1] for row in data}
    data_previous_week = {weekday_names[int(row[0])]: row[1] for row in data_previous_week}

    percentage_change = 0
    total_count_current_week = sum(data.values())
    total_count_previous_week = sum(data_previous_week.values())

    if total_count_previous_week != 0:
        percentage_change = ((total_count_current_week - total_count_previous_week) / total_count_previous_week) * 100

    response_data = {
        'data': data,
        'percentage_change': percentage_change
    }

    return jsonify(response_data)

@app.route("/get_payments")
@login_required
def get_payments():
    # Check if the user is an admin
    user_type = session.get("user_type")
    if user_type != "admin":
        return render_template("404.html"), 404

    # Get the admin's user_id
    admin_id = session.get("user_id")
    db = get_db()

    # Fetch count of paid and unpaid invoices
    payments_paid_count = db.execute("SELECT COUNT(*) FROM billing WHERE payment_status = 'paid' AND created_by IN (SELECT users_id FROM users WHERE admin_id = ?)", (admin_id,)).fetchone()[0] or 0
    payments_unpaid_count = db.execute("SELECT COUNT(*) FROM billing WHERE payment_status IS NULL AND created_by IN (SELECT users_id FROM users WHERE admin_id = ?)", (admin_id,)).fetchone()[0] or 0

    # Construct the payments dictionary
    payments = {
        "payments_paid_count": payments_paid_count,
        "payments_unpaid_count": payments_unpaid_count
    }
    print(payments)

    return jsonify(payments)


@app.route("/users", methods=["GET"])
@login_required
def users():
    user_type = session.get("user_type")
    if user_type is None or user_type != "admin":
        return render_template("404.html"), 404

    else:

        admin_id = session.get("user_id")
        db = get_db()
        users = db.execute("SELECT * FROM users WHERE admin_id = ?",(admin_id,)).fetchall()
        print(users)
        total_users = len(users)

        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Number of patients per page
        offset = (page - 1) * per_page
        users = users[offset:offset + per_page]
        total_pages = (total_users + per_page - 1) // per_page

        return render_template("users.html", users=users, page=page, total_pages=total_pages)


@app.route("/add_users" , methods=["GET","POST"])
@login_required
def add_users():
    user_type = session.get("user_type")
    if user_type is None or user_type != "admin":
        return render_template("404.html"), 404
    
    error_messages = []
    
    if request.method == "POST":
        # Validate form input using secure validation
        validation_errors, validated_data = validate_user_form()
        
        if validation_errors:
            error_messages.extend(validation_errors)
        else:
            try:
                db = get_db()
                admin_id = session.get("user_id")

                # Insert the new user with validated data
                hashed_password = generate_password_hash(validated_data["password"])
                db.execute("INSERT INTO users (email, hash, first_name, last_name, usertype, payroll, admin_id, phone_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                           (validated_data["email"], hashed_password, validated_data["first_name"], 
                            validated_data["last_name"], validated_data["position"], 
                            validated_data["payroll"], admin_id, validated_data["phone"]))
                db.connection.commit()

                flash(f"Successfully created new user: {validated_data['first_name']} {validated_data['last_name']}!", "success")
                return redirect("/users")
                
            except sqlite3.Error as e:
                error_messages.append("Database error occurred. Please try again.")
                print(f"Database error in add_users: {e}")

    # Generate CSRF token for the form
    csrf_token = CSRFTokenGenerator.generate_token() if not CSRF_AVAILABLE else None
    
    if error_messages:
        return render_template("add_users.html", error_messages=error_messages, csrf_token=csrf_token)
    else:
        return render_template("add_users.html", csrf_token=csrf_token)


@app.route("/add_doctors", methods=["GET", "POST"])
@login_required
def add_doctors():
    error_messages = []
    user_type = session.get("user_type")

    # Check if the user is an admin
    if user_type is None or user_type != "admin":
        return render_template("404.html"), 404

    if request.method == "POST":
        # Validate form input using secure validation
        validation_errors, validated_data = validate_doctor_form()
        
        if validation_errors:
            error_messages.extend(validation_errors)
            return render_template("add_doctors.html", error_messages=error_messages)
        
        try:
            db = get_db()
            admin_id = session.get("user_id")
            
            # Check if email already exists across all user types
            email_check_queries = [
                ("SELECT email FROM doctors WHERE LOWER(email) = ?", "A doctor with this email already exists"),
                ("SELECT email FROM users WHERE LOWER(email) = ?", "A user with this email address already exists"),
                ("SELECT email FROM admins WHERE LOWER(email) = ?", "An admin with this email address already exists")
            ]
            
            for query, error_msg in email_check_queries:
                result = db.execute(query, (validated_data["email"],))
                if result.fetchone():
                    error_messages.append(error_msg)
            
            if error_messages:
                return render_template("add_doctors.html", error_messages=error_messages)
            
            # Insert doctor into the database
            hashed_password = generate_password_hash(validated_data["password"])
            
            db.execute("""
                INSERT INTO doctors (email, phone, years_of_experience, hash, first_name, last_name, 
                                   specialization, usertype, address, payroll, admin_id) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                validated_data["email"], validated_data["phone"], validated_data["experience"],
                hashed_password, validated_data["first_name"], validated_data["last_name"],
                validated_data["specialization"], "Doctor", validated_data["address"],
                validated_data["payroll"], admin_id
            ))
            
            # Get the newly created doctor ID
            doc_id_cursor = db.execute("SELECT doctor_id FROM doctors WHERE email = ?", (validated_data["email"],))
            doc_id = doc_id_cursor.fetchone()[0]

            # Insert working hours
            days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
            day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            
            for day, day_name in zip(days, day_names):
                start_time = validated_data["working_hours"].get(f"{day}_start")
                end_time = validated_data["working_hours"].get(f"{day}_end")
                
                if start_time and end_time:  # Only insert if both times are provided
                    db.execute("""
                        INSERT INTO doctor_working_hours (doctor_id, day_of_week, start_working_hours, end_working_hours) 
                        VALUES (?, ?, ?, ?)
                    """, (doc_id, day_name, start_time, end_time))
            
            db.connection.commit()
            flash("Successfully created a new doctor!", "success")
            return redirect("/view_doctors")
            
        except sqlite3.Error as e:
            error_messages.append("Database error occurred. Please try again.")
            return render_template("add_doctors.html", error_messages=error_messages)

    else:
        return render_template("add_doctors.html")


@app.route("/view_doctors", methods=["GET"])
@login_required
def view_doctors():
    user_type = session.get("user_type")
    if user_type is None or user_type != "admin":
        return render_template("404.html"), 404
    db = get_db()
    admin_id = session.get("user_id")
    doctors = db.execute("SELECT * FROM doctors WHERE admin_id = ?", (admin_id,)).fetchall()
    total_doctors = len(doctors)

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of patients per page
    offset = (page - 1) * per_page
    doctors = doctors[offset:offset + per_page]
    total_pages = (total_doctors + per_page - 1) // per_page
    return render_template("view_doctors.html", doctors=doctors, page = page , total_pages = total_pages )

#analytics----------------------------------------

@app.route("/analytics" , methods=["GET"])
@login_required
def analytics():
    db=get_db()
    gender_data = db.execute("SELECT gender, COUNT(*) FROM patients GROUP BY gender").fetchall()

    total_patients = sum(count for gender, count in gender_data)

    gender_percentages=[(gender, count / total_patients * 100) for gender, count in gender_data]
    labels = [row[0] for row in gender_percentages]
    percentages = [row[1] for row in gender_percentages]

    return render_template('analytics.html',  labels=labels, percentages=percentages)



#Receptionist------------------------------------------
@app.route("/receptionist", methods=["GET"])
@login_required
def rece():
    user_type = session.get("user_type")
    if user_type != "Receptionist":
        return render_template("404.html"), 404
    db = get_db()
    today_date = datetime.today().date()
    appointments = db.execute("""
        SELECT Appointments.StartTime, Patients.name, Patients.date_of_birth
        FROM Appointments
        INNER JOIN Patients ON Appointments.PatientID = Patients.patient_id
        WHERE date(Appointments.AppointmentDate) = ?
    """, (today_date,)).fetchall()

    return render_template("rece.html", appointments=appointments)

@app.route("/cancel_appointments/<int:app_id>" , methods=["DELETE"])
@login_required
def cancel_app(app_id):
    print(app_id)
    user_type = session.get("user_type")
    if user_type != "Receptionist":
        return render_template("404.html"),404
    db = get_db()
    try:
        db.execute("DELETE FROM Appointments WHERE AppointmentID = ?",(app_id,))
        db.connection.commit()
        flash("Sucessfully canceled appointment")
        return redirect("/receptionist")
    except sqlite3.Error as e:
        error_message = "Database error: " + e
        print(error_message)
    return jsonify({'error': 'Error message here'})





@app.route("/patients" , methods=["GET"])
@login_required
def patients():
    user_type = session.get("user_type")

    if user_type == "Receptionist":
        db=get_db()
        user_id = session.get("user_id")
        admin_id_cursor = db.execute("SELECT admin_id FROM users WHERE users_id = ?", (user_id,))
        admin_id_row = admin_id_cursor.fetchone()

        if admin_id_row:
            # Extract admin ID from the result
            admin_id = admin_id_row[0]

            # Fetch patients associated with the admin
            patients_query = db.execute("""
                SELECT patients.*
                FROM patients
                JOIN users ON patients.created_by = users.users_id
                WHERE users.admin_id = ?
            """, (admin_id,))

        if patients_query:
            patients = patients_query.fetchall()  # Fetch all patients associated with the admin
            total_patients = len(patients)

            page = request.args.get('page', 1, type=int)
            per_page = 10  # Number of patients per page
            offset = (page - 1) * per_page
            patients = patients[offset:offset + per_page]
            total_pages = (total_patients + per_page - 1) // per_page
            return render_template("patients.html", page=page ,patients=patients , total_pages = total_pages)
        else:
             return render_template("patients.html", page=page ,patients=patients , total_pages = total_pages)
    elif user_type == "admin":
        db=get_db()
        user_id = session.get("user_id")
        patients_query = """
            SELECT patients.*
            FROM patients
            JOIN users ON patients.created_by = users.users_id
            WHERE users.admin_id = ?
        """
        patients = db.execute(patients_query, (user_id,)).fetchall()
        total_patients = len(patients)

        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Number of patients per page
        offset = (page - 1) * per_page
        patients = patients[offset:offset + per_page]
        total_pages = (total_patients + per_page - 1) // per_page

        return render_template("patients.html", patients=patients, page=page, total_pages=total_pages)

    else:
        db = get_db()
        user_id = session.get("user_id")
        patients_query = """
            SELECT DISTINCT
                p.patient_id,
                p.name AS patient_name,
                p.date_of_birth AS patient_dob,
                p.gender AS patient_gender,
                p.phone AS pateint_phone,
                p.email AS patient_email

            FROM
                Appointments a
            INNER JOIN
                patients p ON a.PatientID = p.patient_id
            INNER JOIN
                doctors d ON a.DoctorID = d.doctor_id
            WHERE
                d.doctor_id = ?
        """
        patients = db.execute(patients_query, (user_id,)).fetchall()

        total_patients = len(patients)

        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Number of patients per page
        offset = (page - 1) * per_page
        patients = patients[offset:offset + per_page]
        total_pages = (total_patients + per_page - 1) // per_page

        return render_template("patients.html" , patients = patients, page = page, total_pages = total_pages)


@app.route("/details_patients", methods=["GET", "POST"])
@login_required
def details():
    user_type = session.get("user_type")
    if user_type not in ["Receptionist"]:
        return render_template("404.html"), 404

    error_message = None
    personal = []
    med = []
    EM = []
    insur = []
    patient = None  # Initialize patient variable

    if request.method == "POST":
        data = request.json
        user_id = session.get("user_id")
        patient_id = data.get("patient_id")
        dob = data.get("dob")
        gender = data.get("gender")
        address = data.get("address")
        name_emergency = data.get("name_emergency")
        relationship_emergency = data.get("relationship_emergency")
        phone_number_emergency = data.get("phone_number_emergency")
        height_medical = data.get("height_medical")
        weight_medical = data.get("weight_medical")
        blood_type_medical = data.get("blood_type_medical")
        insurance_company = data.get("insurance_company")
        policy_number = data.get("policy_number")
        group_number = data.get("group_number")
        db = get_db()

        try:
            # Check if the medical information record exists
            existing_record = db.execute("SELECT * FROM medical_information WHERE patient_id = ?", (patient_id,)).fetchone()

            if existing_record:
                # Update the existing medical information record
                db.execute("""
                    UPDATE medical_information
                    SET height_medical = ?,
                        weight_medical = ?,
                        blood_type_medical = ?
                    WHERE patient_id = ?;
                """, (height_medical, weight_medical, blood_type_medical, patient_id))
            else:
                # Insert a new medical information record
                db.execute("""
                    INSERT INTO medical_information (patient_id, height_medical, weight_medical, blood_type_medical, created_by_medical)
                    VALUES (?, ?, ?, ?, ?);
                """, (patient_id, height_medical, weight_medical, blood_type_medical, user_id))

            # Check if the insurance information record exists
            existing_record = db.execute("SELECT * FROM insurance_information WHERE patient_id_insurance = ?", (patient_id,)).fetchone()

            if existing_record:
                # Update the existing insurance information record
                db.execute("""
                    UPDATE insurance_information
                    SET insurance_company = ?,
                        policy_number = ?,
                        group_number = ?
                    WHERE patient_id_insurance = ?;
                """, (insurance_company, policy_number,group_number, patient_id))
            else:
                # Insert a new insurance information record
                db.execute("""
                    INSERT INTO insurance_information (patient_id_insurance, insurance_company, policy_number, group_number , created_by_insurance)
                    VALUES (?, ?, ?, ?, ?);
                """, (patient_id, insurance_company, policy_number,group_number ,  user_id))

            # Check if the emergency contact record exists
            existing_record = db.execute("SELECT * FROM emergency_contact WHERE patient_id_emergency = ?", (patient_id,)).fetchone()

            if existing_record:
                # Update the existing emergency contact record
                db.execute("""
                    UPDATE emergency_contact
                    SET name_emergency = ?,
                        relationship_emergency = ?,
                        phone_number_emergency = ?
                    WHERE patient_id_emergency = ?;
                """, (name_emergency, relationship_emergency, phone_number_emergency, patient_id))
            else:
                # Insert a new emergency contact record
                db.execute("""
                    INSERT INTO emergency_contact (patient_id_emergency, name_emergency, relationship_emergency, phone_number_emergency, created_by_emergency)
                    VALUES (?, ?, ?, ?, ?);
                """, (patient_id, name_emergency, relationship_emergency, phone_number_emergency, user_id))

            db.connection.commit()  # Commit the transaction after updating

        except sqlite3.Error as e:
            error_message = "Database error: " + str(e)

        if error_message:
            return render_template("view_details.html", error_message=error_message)

    else:
        db = get_db()
        patient = request.args.get("data-patient-id")  # Get patient ID from query parameters
        user_id = session.get("user_id")

        try:
            # Fetch data from various tables
            personal = db.execute("SELECT * FROM patients WHERE patient_id = ? AND created_by IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient, user_id)).fetchall()
            med = db.execute("SELECT * FROM medical_information WHERE patient_id = ? AND created_by_medical IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient, user_id)).fetchall()
            EM = db.execute("SELECT * FROM emergency_contact WHERE patient_id_emergency = ? AND created_by_emergency IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient, user_id)).fetchall()
            insur = db.execute("SELECT * FROM insurance_information WHERE patient_id_insurance = ? AND created_by_insurance IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient, user_id)).fetchall()

        except sqlite3.Error as e:
            error_message = "Database error: " + str(e)

        if error_message:
            return render_template("view_details.html", error_message=error_message)

    return render_template("view_details.html", personal=personal, med=med, EM=EM, insur=insur, patient=patient, error_message=error_message)



@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    error_message = None

    def allowed_file(filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

    if request.method == "POST":
        # Validate form input using secure validation
        validation_errors, validated_data = validate_file_upload_form()
        
        if validation_errors:
            error_message = validation_errors[0]  # Show first error for compatibility
            
        if 'document' not in request.files:
            error_message = "No file selected"
        
        file = request.files.get('document')
        if not file or file.filename == '':
            error_message = "Please select a file to upload"
        
        patient_id = request.args.get("data-patient-id")
        if not patient_id:
            error_message = "Invalid patient ID"
        
        if error_message:
            # Get patient data for template
            try:
                db = get_db()
                user_id = session.get("user_id")
                personal = db.execute("SELECT * FROM patients WHERE patient_id = ? AND created_by IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient_id, user_id)).fetchall()
                return render_template("upload.html", error_message=error_message, personal=personal)
            except:
                return render_template("upload.html", error_message=error_message)

        if file and allowed_file(file.filename):
            try:
                current_date = date.today()
                today_date = current_date.strftime("%Y-%m-%d")
                
                filename = secure_filename(file.filename)
                filename = generate_unique_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                # Store the filename, date, and user ID in the database
                db = get_db()
                user_id = session.get("user_id")
                
                # Verify patient exists and user has access
                patient_check = db.execute("""
                    SELECT patient_id FROM patients 
                    WHERE patient_id = ? AND created_by IN (
                        SELECT users_id FROM users WHERE admin_id = (
                            SELECT admin_id FROM users WHERE users_id = ?
                        )
                    )
                """, (patient_id, user_id))
                
                if not patient_check.fetchone():
                    error_message = "Patient not found or access denied"
                    return render_template("upload.html", error_message=error_message)
                
                db.execute("INSERT INTO files (filename, filepath, file_date, created_by, patient_id, date_uploaded) VALUES (?, ?, ?, ?, ?, ?)",
                        (filename, file_path, validated_data["file_date"], user_id, patient_id, today_date))
                db.connection.commit()

                personal = db.execute("SELECT * FROM patients WHERE patient_id = ? AND created_by IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient_id, user_id)).fetchall()

                flash("File uploaded successfully", "success")
                return redirect(f"/upload?data-patient-id={personal[0][0] if personal else ''}")

            except sqlite3.Error as e:
                error_message = "Database error occurred. Please try again."
                try:
                    personal = db.execute("SELECT * FROM patients WHERE patient_id = ? AND created_by IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient_id, user_id)).fetchall()
                    return render_template("upload.html", error_message=error_message, personal=personal)
                except:
                    return render_template("upload.html", error_message=error_message)
        else:
            error_message = "Invalid file type. Please upload a valid document."
            try:
                db = get_db()
                user_id = session.get("user_id")
                personal = db.execute("SELECT * FROM patients WHERE patient_id = ? AND created_by IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient_id, user_id)).fetchall()
                return render_template("upload.html", error_message=error_message, personal=personal)
            except:
                return render_template("upload.html", error_message=error_message)

    # For GET request
    db = get_db()
    patient_id = request.args.get("data-patient-id")
    user_id = session.get("user_id")

    try:
        personal = db.execute("SELECT * FROM patients WHERE patient_id = ? AND created_by IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient_id, user_id)).fetchall()

        files = db.execute("SELECT * FROM files WHERE patient_id = ? AND created_by IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient_id, user_id)).fetchall()
    except sqlite3.Error as e:
        error_message = "Database error: " + str(e)
    finally:
        db.close()

    if error_message:
        return render_template("upload.html" , personal = personal, error_message = error_message)

    else:
        total_files = len(files)
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Number of patients per page
        offset = (page - 1) * per_page
        files = files[offset:offset + per_page]
        total_pages = (total_files + per_page - 1) // per_page
        return render_template("upload.html" , personal = personal, files = files, page = page, total_pages = total_pages)




@app.route('/upload/delete_file/<int:file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    # Connect to the SQLite database
    user_id = session.get("user_id")
    db = get_db()
    patient = request.args.get("data-patient-id")
    # Retrieve file information from the database
    file = db.execute("SELECT filename, filepath FROM files WHERE id = ?", (file_id,)).fetchone()
    personal = db.execute("SELECT * FROM patients WHERE patient_id = ? AND created_by IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient, user_id)).fetchall()

    if file:
        filename, file_path = file

        # Delete the file from the directory
        if os.path.exists(file_path):
            os.remove(file_path)
        else:
            return jsonify({'error': 'File not found in directory'}), 404

        # Delete the file record from the database
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        db.connection.commit()

        flash("File has been delted sucessfully")
        return redirect(f"/upload?data-patient-id={personal[0][0] if personal else ''}")
    else:
        return jsonify({'error': 'File not found in database'}), 404

@app.route('/upload/view_file/<int:file_id>', methods=['GET'])
@login_required
def view_file(file_id):
    # Connect to the SQLite database
    db = get_db()

    # Retrieve file information from the database
    file = db.execute("SELECT filename, filepath FROM files WHERE id = ?", (file_id,)).fetchone()

    if file:
        filename, file_path = file

        # Ensure file_path is relative to UPLOAD_FOLDER
        file_path_relative = relpath(file_path, app.config['UPLOAD_FOLDER'])

        # Serve the file from the directory
        return send_from_directory(app.config['UPLOAD_FOLDER'], file_path_relative, as_attachment=True)
    else:
        return jsonify({'error': 'File not found'}), 404




@app.route ("/payments" , methods=["GET"])
@login_required
def payments():
    error_message = None
    patient = request.args.get("data-patient-id")  # Get patient ID from query parameters
    user_id = session.get("user_id")
    try:
        db = get_db()
        # Fetch data from various tables
        personal = db.execute("SELECT * FROM patients WHERE patient_id = ? AND created_by IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient, user_id)).fetchall()

        payments = db.execute("""
            SELECT *
            FROM billing
            WHERE patient_id = ?
            AND created_by IN (
                SELECT users_id
                FROM users
                WHERE admin_id = (
                    SELECT admin_id
                    FROM users
                    WHERE users_id = ?
                )
            )
        """,(patient, user_id)).fetchall()

        total_payments = len(payments)
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Number of patients per page
        offset = (page - 1) * per_page
        payments = payments[offset:offset + per_page]
        total_pages = (total_payments + per_page - 1) // per_page


    except sqlite3.Error as e:
        error_message = "Database error: " + str(e)

    if error_message:
        return render_template("upload.html", error_message = error_message)
    else:
        return render_template("payments.html" , personal=personal, payments = payments , page = page, total_pages = total_pages)

@app.route("/update_payments", methods=["POST"])
@login_required
def update_payments():
    data = request.json  # Get the JSON data sent from the frontend
    # Extract data from the JSON object
    print(data)
    payment_id = data.get('payment_id')
    payment_date = data.get('payment_date')
    payment_amount = data.get('payment_amount')
    payment_method = data.get('payment_method')
    payment_status = data.get('payment_status')
    # Update the database with the new information
    try:
        db = get_db()
        db.execute("UPDATE billing SET payment_date = ?, amount = ?, payment_method = ?, payment_status = ? WHERE invoice_id = ?",
                   (payment_date, payment_amount, payment_method, payment_status, payment_id))
        db.connection.commit()
        return jsonify({'success': True}), 200
    except Exception as e:
        print(e)
        return jsonify({'success': False, 'message': str(e)}), 500






@app.route("/prescriptions" , methods=["GET"])
def prescriptions():
    error_message = None
    patient = request.args.get("data-patient-id")  # Get patient ID from query parameters
    user_id = session.get("user_id")
    try:
        db = get_db()
        # Fetch data from various tables
        personal = db.execute("SELECT * FROM patients WHERE patient_id = ? AND created_by IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient, user_id)).fetchall()

        prescriptions = db.execute("SELECT medication, dosage, instructions, date_prescribed FROM prescriptions WHERE patient_id = ?",(patient,)).fetchall()

        history_prescriptions = db.execute("SELECT medication, dosage, instructions, date_prescribed FROM history_prescriptions WHERE patient_id = ?",(patient,)).fetchall()

        total_prescriptions = len(prescriptions)
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Number of patients per page
        offset = (page - 1) * per_page
        prescriptions = prescriptions[offset:offset + per_page]
        total_pages = (total_prescriptions + per_page - 1) // per_page

        total_history_prescriptions = len(history_prescriptions)
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Number of patients per page
        offset = (page - 1) * per_page
        history_prescriptions = history_prescriptions[offset:offset + per_page]
        total_pages = (total_history_prescriptions + per_page - 1) // per_page

    except sqlite3.Error as e:
        error_message = "Database error: " + str(e)

    if error_message:
        return render_template("prescriptions.html", error_message = error_message)
    else:
        return render_template("prescriptions.html" , personal=personal , prescriptions = prescriptions, history_prescriptions = history_prescriptions , page = page, total_pages = total_pages)




@app.route("/new_patient" , methods=["GET","POST"])
@login_required
def new_patients():
    user_type = session.get("user_type")
    if user_type is None or user_type != "Receptionist":
        return render_template("404.html"), 404

    if request.method == "POST":
        # Validate form input using secure validation
        validation_errors, validated_data = validate_patient_form()
        
        if validation_errors:
            error_message = validation_errors[0]  # Show first error for compatibility
            return render_template("new_patient.html", error_message=error_message)
        
        try:
            db = get_db()
            user_id = session.get("user_id")
            
            # Check if the patient already exists
            result = db.execute("SELECT email FROM patients WHERE LOWER(email) = ?", (validated_data["email"],))
            if result.fetchone():
                error_message = "A patient with this email address already exists"
                return render_template("new_patient.html", error_message=error_message)

            # Insert new patient into the database
            full_name = f"{validated_data['first_name']} {validated_data['last_name']}"
            
            db.execute("""
                INSERT INTO patients (name, date_of_birth, gender, address, phone, email, insurance, created_by) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                full_name, validated_data["date_of_birth"], validated_data["gender"],
                validated_data["address"], validated_data["phone"], validated_data["email"],
                validated_data["insurance"], user_id
            ))
            
            db.connection.commit()
            flash("New patient created successfully", "success")
            return redirect("/patients")

        except sqlite3.Error as e:
            error_message = "Database error occurred. Please try again."
            return render_template("new_patient.html", error_message=error_message)

    else:
        return render_template("new_patient.html")


@app.route("/doctors_rec", methods=["GET"])
@login_required
def doctors_rec():
    user_type = session.get("user_type")
    if user_type is None or user_type != "Receptionist":
        return render_template("404.html"), 404

    db = get_db()
    user_id = session.get("user_id")
    admin_id = db.execute("SELECT admin_id FROM users WHERE users_id = ?", (user_id,)).fetchone()[0]
    doctors = db.execute("SELECT last_name, phone, specialization, email,doctor_id FROM doctors WHERE admin_id = ?", (admin_id,)).fetchall()

    total_doctors = len(doctors)
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of patients per page
    offset = (page - 1) * per_page
    doctors = doctors[offset:offset + per_page]
    total_pages = (total_doctors + per_page - 1) // per_page

    return render_template("doctors_rec.html", doctors=doctors , page = page, total_pages = total_pages)






@app.route('/update_confirmation_status', methods=['POST'])
def update_confirmation_status():
    data = request.json
    appointment_id = data['appointmentId']
    new_status = data['newStatus']
    patient_id = data['patientId']
    print(patient_id)
    user_id = session.get("user_id")
    db = get_db()
    current_date = date.today()
    if new_status == "0" or new_status == "1":
        # Update the confirmation status in the database
        db.execute("UPDATE Appointments SET confirmed = ? WHERE AppointmentID = ?", (int(new_status), appointment_id))
        info = db.execute("""
            SELECT
                doctors.first_name || ' ' || doctors.last_name AS doctor_name,
                doctors.specialization AS doctor_specialization,
                Appointments.Reason AS appointment_reason
            FROM
                Appointments
            JOIN
                doctors ON Appointments.DoctorID = doctors.doctor_id
            WHERE
                Appointments.AppointmentID = ?
        """, (appointment_id,)).fetchall()

        # Check if any rows were returned
        if info:
            for row in info:
                doctor_name, doctor_specialization, appointment_reason = row
                description = f"{doctor_name}, {doctor_specialization}, {appointment_reason}"

                # Fetch insurance information
                insurance_result = db.execute("SELECT insurance_company FROM insurance_information WHERE patient_id_insurance = ?", (patient_id,))
                insurance_row = insurance_result.fetchone()
                insurance = insurance_row[0] if insurance_row else None

                # Insert into billing table
                db.execute("INSERT INTO billing (appointment_id, patient_id, invoice_date, description, insurance_provider, created_by) VALUES (?, ?, ?, ?, ?, ?)",
                    (appointment_id, patient_id, current_date, description, insurance, user_id))

        db.connection.commit()  # Commit the transaction
        return jsonify({'success': True}), 200
    else:
        return jsonify({'success': False, 'message': 'Invalid status value'}), 400





@app.route("/appointments", methods=["GET"])
@login_required
def appointments():
    return render_template("appointments.html")





@app.route("/patient_app" , methods=["GET"])
@login_required
def patient_appointments():
    patient = request.args.get("data-patient-id")

    if patient:
        db = get_db()
        user_id = session.get("user_id")

        appointments = db.execute("""
            SELECT Appointments.AppointmentDate,
                   Appointments.AppointmentID,
                   Doctors.last_name AS DoctorName,
                   Doctors.specialization AS DoctorSpecialization,
                   Appointments.StartTime,
                   Appointments.Reason,
                   Appointments.confirmed
            FROM Appointments
            INNER JOIN Patients ON Appointments.PatientID = Patients.patient_id
            INNER JOIN Doctors ON Appointments.DoctorID = Doctors.doctor_id
            WHERE Patients.patient_id = ? AND Appointments.created_by IN (
                SELECT users_id FROM users WHERE admin_id = (
                    SELECT admin_id FROM users WHERE users_id = ?
                )
            )
        """, (patient, user_id)).fetchall()

        personal = db.execute("SELECT * FROM patients WHERE patient_id = ? AND created_by IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient, user_id)).fetchall()

        total_appointments = len(appointments)
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Number of patients per page
        offset = (page - 1) * per_page
        appointments = appointments[offset:offset + per_page]
        total_pages = (total_appointments + per_page - 1) // per_page


        return render_template("patient_appointments.html" , appointments = appointments , personal = personal , page = page, total_pages = total_pages, patient = patient)




@app.route("/get_appointments", methods=["GET"])
@login_required
def get_appointments():
    user_id = session.get("user_id")
    try:
        # Get the selected day, month, and year from the request parameters
        selected_day = request.args.get('day')
        selected_month = request.args.get('month')
        selected_year = request.args.get('year')

        # Check if the selected_day, selected_month, and selected_year are None or empty
        if not selected_day or not selected_month or not selected_year:
            return jsonify({'error': 'Day, month, and year parameters are required'}), 400

        # Validate day, month, and year format
        if not selected_day.isdigit() or not selected_month.isdigit() or not selected_year.isdigit():
            return jsonify({'error': 'Invalid day, month, or year format. Please provide valid values.'}), 400

        # Construct the selected date string
        selected_date = f"{selected_year}-{selected_month.zfill(2)}-{selected_day.zfill(2)}"

        # Connect to the database
        db = get_db()

        # Execute the query to retrieve appointments for the selected date
        user_type = session.get("user_type")
        if user_type == "Receptionist":
            cursor = db.execute("""
            SELECT Appointments.AppointmentDate,
            Appointments.AppointmentID,
            Patients.name AS PatientName,
            Patients.date_of_birth AS PatientDOB,
            Doctors.last_name AS DoctorName,
            Doctors.specialization AS DoctorSpecialization,
            Appointments.StartTime,
            Appointments.Reason,
            Appointments.Notes
            FROM Appointments
            INNER JOIN Patients ON Appointments.PatientID = Patients.patient_id
            INNER JOIN Doctors ON Appointments.DoctorID = Doctors.doctor_id
            WHERE Appointments.AppointmentDate = ? AND Appointments.created_by IN (
                SELECT users_id FROM users WHERE admin_id = (
                    SELECT admin_id FROM users WHERE users_id = ?
                )
            )
        """, (selected_date, user_id))

        elif user_type == "admin":
            cursor = db.execute("""
                SELECT
                    Appointments.AppointmentID,
                    Appointments.AppointmentDate,
                    Patients.name AS PatientName,
                    Patients.date_of_birth AS PatientDOB,
                    Doctors.last_name AS DoctorName,
                    Doctors.specialization AS DoctorSpecialization,
                    Appointments.StartTime,
                    Appointments.Reason,
                    Appointments.Notes
                FROM
                    Appointments
                INNER JOIN
                    Patients ON Appointments.PatientID = Patients.patient_id
                INNER JOIN
                    Doctors ON Appointments.DoctorID = Doctors.doctor_id
                INNER JOIN
                    users ON Appointments.created_by = users.users_id
                WHERE
                    users.admin_id = ? AND Appointments.AppointmentDate = ?
            """, (user_id, selected_date))

        elif user_type == "Doctor":
            cursor = db.execute("""
                SELECT
                    Appointments.AppointmentDate,
                    patients.name AS PatientName,
                    patients.date_of_birth AS PatientDOB,
                    Appointments.StartTime,
                    Appointments.Reason,
                    Appointments.Notes
                FROM
                    Appointments
                                INNER JOIN
                    Patients ON Appointments.PatientID = Patients.patient_id
                WHERE
                    Appointments.DoctorID = ? AND Appointments.AppointmentDate = ?
            """, (user_id, selected_date))

        # Fetch and format appointments
        appointments = cursor.fetchall()
        print(appointments)

        if user_type == "Doctor":
            appointment_list = [
                {
                    'AppointmentDate': appointment[0],
                    'PatientName': appointment[1],
                    'PatientDOB': appointment[2],
                    'StartTime': appointment[3],
                    'ReasonForVisit': appointment[4],
                    'Notes': appointment[5],
                    'user_type' : "Doctor"
                } for appointment in appointments
            ]
        else:
            appointment_list = [
            {
                'AppointmentID' : appointment[0],
                'AppointmentDate': appointment[1],
                'PatientName': appointment[2],
                'PatientDOB': appointment[3],
                'DoctorName': appointment[4],
                'DoctorSpecialization': appointment[5],
                'StartTime': military_to_standard_time(appointment[6]),
                'ReasonForVisit': appointment[7],
                'Notes': appointment[8]
            } for appointment in appointments
        ]

        # Return the list of appointments or an error message if none are found
        if not appointment_list:
            return jsonify({'message': 'No appointments found for this date'}), 404

        return jsonify(appointment_list)

    except sqlite3.Error as e:
        print("Database error:", e)
        return jsonify({'error': 'Failed to retrieve appointments'}), 500





@app.route("/new_appointment", methods=["POST", "GET"])
@login_required
def new_appointment():
    user_type = session.get("user_type")
    if user_type is None or user_type != "Receptionist":
        return render_template("404.html"), 404

    if request.method == "POST":
        # Validate form input using secure validation
        validation_errors, validated_data = validate_appointment_form()
        
        if validation_errors:
            error_messages = validation_errors
        else:
            error_messages = []
            
            try:
                db = get_db()
                user_id = session.get("user_id")
                today_date = datetime.today().date()
                
                # Verify patient exists and belongs to the same admin organization
                admin_id_query = db.execute("SELECT admin_id FROM users WHERE users_id = ?", (user_id,))
                admin_id_result = admin_id_query.fetchone()
                
                if not admin_id_result:
                    error_messages.append("Invalid user session")
                else:
                    admin_id = admin_id_result[0]
                    
                    # Check if patient exists and belongs to the same organization
                    patient_check = db.execute("""
                        SELECT patient_id FROM patients 
                        WHERE patient_id = ? AND created_by IN (
                            SELECT users_id FROM users WHERE admin_id = ?
                        )
                    """, (validated_data["patient_id"], admin_id))
                    
                    if not patient_check.fetchone():
                        error_messages.append("Patient not found or access denied")
                    
                    # Verify doctor exists and belongs to the same admin organization
                    doctor_check = db.execute("""
                        SELECT doctor_id FROM doctors 
                        WHERE doctor_id = ? AND admin_id = ?
                    """, (validated_data["doctor_id"], admin_id))
                    
                    if not doctor_check.fetchone():
                        error_messages.append("Doctor not found or access denied")
                    
                    # Check doctor's working hours for the appointment day
                    appointment_date = datetime.strptime(validated_data["appointment_date"], '%Y-%m-%d')
                    weekday = appointment_date.strftime('%A')
                    
                    doc_hours = db.execute("""
                        SELECT start_working_hours, end_working_hours 
                        FROM doctor_working_hours 
                        WHERE doctor_id = ? AND day_of_week = ?
                    """, (validated_data["doctor_id"], weekday))
                    
                    working_hours = doc_hours.fetchone()
                    if not working_hours:
                        error_messages.append(f"Doctor is not available on {weekday}s")
                    else:
                        doc_start = datetime.strptime(working_hours[0], '%H:%M').time()
                        doc_end = datetime.strptime(working_hours[1], '%H:%M').time()
                        app_time = datetime.strptime(validated_data["start_time"], '%H:%M').time()
                        
                        if app_time < doc_start or app_time >= doc_end:
                            error_messages.append(f"Appointment time is outside doctor's working hours ({working_hours[0]} - {working_hours[1]})")
                    
                    # Check for appointment conflicts
                    conflict_check = db.execute("""
                        SELECT AppointmentID FROM Appointments 
                        WHERE DoctorID = ? AND AppointmentDate = ? AND StartTime = ?
                    """, (validated_data["doctor_id"], validated_data["appointment_date"], validated_data["start_time"]))
                    
                    if conflict_check.fetchone():
                        error_messages.append("Doctor already has an appointment at this time")
                
                if not error_messages:
                    # Insert the appointment into the database
                    db.execute("""
                        INSERT INTO Appointments (PatientID, AppointmentDate, StartTime, DoctorID, Reason, Notes, created_by) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        validated_data["patient_id"], validated_data["appointment_date"], 
                        validated_data["start_time"], validated_data["doctor_id"], 
                        validated_data["reason"], validated_data["notes"], user_id
                    ))
                    db.connection.commit()
                    flash("New appointment created successfully", "success")
                    return redirect("/appointments")
                    
            except sqlite3.Error as e:
                error_messages.append("Database error occurred. Please try again.")
        
        # If there are errors, render form with error messages
        if error_messages:
            try:
                user_id = session.get("user_id")
                db = get_db()
                admin_id_query = db.execute("SELECT admin_id FROM users WHERE users_id = ?", (user_id,))
                admin_id_result = admin_id_query.fetchone()
                
                if admin_id_result:
                    admin_id = admin_id_result[0]
                    doctors = db.execute("SELECT last_name, doctor_id FROM doctors WHERE admin_id = ?", (admin_id,)).fetchall()
                else:
                    doctors = []
                    
                return render_template("new_appointments.html", error_messages=error_messages, doctors=doctors)
            except:
                return render_template("new_appointments.html", error_messages=error_messages, doctors=[])

    else:
        user_id = session.get("user_id")
        db = get_db()
        admin_id = db.execute("SELECT admin_id FROM users WHERE users_id = ?", (user_id,)).fetchone()[0]
        doctors = db.execute("SELECT last_name, doctor_id FROM doctors WHERE admin_id = ?", (admin_id,)).fetchall()

        return render_template("new_appointments.html", doctors=doctors)



#fetch doctor working hours for doctor selected
@app.route("/doc_hours")
@login_required
def doc_hours():
    date_str = request.args.get("date")
    date = datetime.strptime(date_str, '%Y-%m-%d')
    weekday = date.strftime('%A')  # Get weekday as a string
    doctor_id = request.args.get('id')
    db = get_db()
    results = db.execute("SELECT start_working_hours, end_working_hours FROM doctor_working_hours WHERE doctor_id = ? AND day_of_week = ?", (doctor_id, weekday)).fetchall()
    # Convert the result to a list of dictionaries
    working_hours = [{'start_time': military_to_standard_time(result[0]), 'end_time': military_to_standard_time(result[1])} for result in results]
    return jsonify(working_hours)




#doctor------------------------------------------------


@app.route("/doctor", methods=["GET"])
@login_required
def doctor():
    user_type = session.get("user_type")
    if user_type is None or user_type != "Doctor":
        return render_template("404.html"), 404
    db = get_db()
    doc_id = session.get("user_id")
    # Fetch the last name of the doctor
    last_name = db.execute("SELECT last_name FROM doctors WHERE doctor_id = ?", (doc_id,)).fetchone()[0]
    # Get the current date
    current_date = datetime.now().date()
    # Fetch appointments for the doctor for the current day
    appointments = db.execute("""
        SELECT Appointments.AppointmentDate, Appointments.StartTime, Appointments.Reason, Appointments.Notes, patients.name
        FROM Appointments
        JOIN patients ON Appointments.PatientID = patients.patient_id
        WHERE Appointments.DoctorID = ? AND DATE(Appointments.AppointmentDate) = DATE(?)
    """, (doc_id, current_date)).fetchall()
    print (appointments)
    return render_template("doctor.html", appointments=appointments, last_name=last_name)

@app.route("/schedule/<int:doctor_id>", methods=["GET", "POST"])
@login_required
def schedule(doctor_id):
    db = get_db()
    times = db.execute("SELECT * FROM doctor_working_hours WHERE doctor_id = ?",(doctor_id,)).fetchall()

    return render_template("schedule.html" , times = times)

@app.route("/doc_prescriptions")
@login_required
def prescription():
    user_type = session.get("user_type")
    if user_type != "Doctor":
        return render_template("404.html"),404
    else:
        db = get_db()
        user_id = session.get("user_id")
        patients  = db.execute("""
            SELECT DISTINCT
                p.patient_id AS patient_id,
                p.name AS patient_name,
                p.date_of_birth AS patient_dob,
                p.gender AS patient_gender
            FROM
                Appointments a
            INNER JOIN
                patients p ON a.PatientID = p.patient_id
            INNER JOIN
                doctors d ON a.DoctorID = d.doctor_id
            WHERE
                d.doctor_id = ?
        """, (user_id,)).fetchall()
        return render_template ("doc_prescriptions.html", patients = patients)

@app.route("/doc_prescriptions/manage_prescription/<int:patient_id>" , methods=["GET" , "POST"])
@login_required
def manage_prescriptions(patient_id):
    user_type = session.get("user_type")
    if user_type != "Doctor":
        return render_template("404.html"), 404

    if request.method == "GET":
        try:
            db = get_db()
            user_id = session.get("user_id")
            
            # Verify patient exists and doctor has access to patient
            patient_check = db.execute("""
                SELECT p.patient_id FROM patients p
                INNER JOIN Appointments a ON p.patient_id = a.PatientID
                WHERE p.patient_id = ? AND a.DoctorID = ?
                LIMIT 1
            """, (patient_id, user_id))
            
            if not patient_check.fetchone():
                return render_template("404.html"), 404
            
            prescriptions = db.execute("""
                SELECT medication, dosage, instructions, date_prescribed, prescription_id 
                FROM prescriptions 
                WHERE patient_id = ? AND doctor_id = ?
            """, (patient_id, user_id)).fetchall()

            total_prescriptions = len(prescriptions)
            page = request.args.get('page', 1, type=int)
            per_page = 10
            offset = (page - 1) * per_page
            prescriptions = prescriptions[offset:offset + per_page]
            total_pages = (total_prescriptions + per_page - 1) // per_page

            history_prescriptions = db.execute("""
                SELECT medication, dosage, instructions, date_prescribed, prescription_id 
                FROM history_prescriptions 
                WHERE patient_id = ? AND doctor_id = ?
            """, (patient_id, user_id)).fetchall()

            total_history_prescriptions = len(history_prescriptions)
            history_prescriptions = history_prescriptions[offset:offset + per_page]

            return render_template("manage_prescriptions.html", 
                                prescriptions=prescriptions, 
                                page=page, 
                                total_pages=total_pages, 
                                history_prescriptions=history_prescriptions)
                                
        except sqlite3.Error as e:
            return render_template("manage_prescriptions.html", error_messages=["Database error occurred"])

    else:
        # Validate form input using secure validation
        validation_errors, validated_data = validate_prescription_form()
        
        if validation_errors:
            error_messages = validation_errors
        else:
            error_messages = []
            
            try:
                db = get_db()
                user_id = session.get("user_id")
                
                # Verify patient exists and doctor has access
                patient_check = db.execute("""
                    SELECT p.patient_id FROM patients p
                    INNER JOIN Appointments a ON p.patient_id = a.PatientID
                    WHERE p.patient_id = ? AND a.DoctorID = ?
                    LIMIT 1
                """, (patient_id, user_id))
                
                if not patient_check.fetchone():
                    error_messages.append("Access denied to this patient")
                
                if not error_messages:
                    current_date = date.today()
                    
                    # Insert prescription into both tables
                    db.execute("""
                        INSERT INTO prescriptions (patient_id, doctor_id, medication, dosage, instructions, date_prescribed) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (patient_id, user_id, validated_data["medication"], 
                         validated_data["dosage"], validated_data["instructions"], current_date))
                    
                    db.execute("""
                        INSERT INTO history_prescriptions (patient_id, doctor_id, medication, dosage, instructions, date_prescribed) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (patient_id, user_id, validated_data["medication"], 
                         validated_data["dosage"], validated_data["instructions"], current_date))
                    
                    db.connection.commit()
                    flash("Successfully added a new prescription", "success")
                    return redirect(url_for("manage_prescriptions", patient_id=patient_id))
                    
            except sqlite3.Error as e:
                error_messages.append("Database error occurred. Please try again.")

        # If there are errors, render form with error messages
        if error_messages:
            try:
                db = get_db()
                user_id = session.get("user_id")
                
                prescriptions = db.execute("""
                    SELECT medication, dosage, instructions, date_prescribed, prescription_id 
                    FROM prescriptions 
                    WHERE patient_id = ? AND doctor_id = ?
                """, (patient_id, user_id)).fetchall()

                history_prescriptions = db.execute("""
                    SELECT medication, dosage, instructions, date_prescribed, prescription_id 
                    FROM history_prescriptions 
                    WHERE patient_id = ? AND doctor_id = ?
                """, (patient_id, user_id)).fetchall()

                return render_template("manage_prescriptions.html", 
                                    error_messages=error_messages,
                                    prescriptions=prescriptions,
                                    history_prescriptions=history_prescriptions,
                                    page=1, total_pages=1)
            except:
                return render_template("manage_prescriptions.html", error_messages=error_messages)

@app.route("/delete_prescription/<int:prescription_id>", methods=["DELETE"])
@login_required
def delete_prescription(prescription_id):
    db = get_db()
    user_id = session.get("user_id")
    doc_id = db.execute("SELECT doctor_id FROM prescriptions WHERE prescription_id = ?",(prescription_id,)).fetchone()[0]
    patient_id = db.execute("SELECT patient_id FROM prescriptions WHERE prescription_id = ?", (prescription_id,)).fetchone()[0]

    if user_id != doc_id:
        return render_template("404.html"),404

    error_message = None
    try:
        db.execute("DELETE FROM prescriptions WHERE prescription_id = ?", (prescription_id,))
        db.connection.commit()
        db.close
        flash("Prescription deleted successfully", "success")
        return redirect(f"/doc_prescriptions/manage_prescription/{patient_id}")  # Redirect to homepage or any other page
    except sqlite3.Error as e:
        error_message = "Database error: " + str(e)
        flash(error_message, "error")
        return redirect(f"/doc_prescriptions/manage_prescription/{patient_id}")



@app.route("/doc_records", methods=["GET"])
@login_required
def doc_records():
    user_type = session.get("user_type")
    if user_type != "Doctor":
        return render_template("404.html"), 404
    else:
        if request.method == "GET":
            user_id = session.get("user_id")
            db = get_db()
            db.row_factory = sqlite3.Row
            patients = db.execute("""
                SELECT DISTINCT
                    p.patient_id AS patient_id,
                    p.name AS patient_name,
                    p.date_of_birth AS patient_dob,
                    p.gender AS patient_gender
                FROM
                    Appointments a
                INNER JOIN
                    patients p ON a.PatientID = p.patient_id
                INNER JOIN
                    doctors d ON a.DoctorID = d.doctor_id
                WHERE
                    d.doctor_id = ?
            """, (user_id,)).fetchall()

            patients_with_med_info = []
            for patient in patients:
                patient_id = patient['patient_id']
                med_info = db.execute("""
                    SELECT height_medical, weight_medical, blood_type_medical
                    FROM medical_information
                    WHERE patient_id = ?
                """, (patient_id,)).fetchone()

                # Convert sqlite3.Row object to dictionary
                patient_dict = dict(patient)

                # Add medical information to patient data
                if med_info is not None:
                    patient_dict['height_medical'] = med_info['height_medical']
                    patient_dict['weight_medical'] = med_info['weight_medical']
                    patient_dict['blood_type_medical'] = med_info['blood_type_medical']
                else:
                    # Handle the case where there's no medical information for the patient
                    # You can set default values or handle it based on your application's logic
                    patient_dict['height_medical'] = None
                    patient_dict['weight_medical'] = None
                    patient_dict['blood_type_medical'] = None

                patients_with_med_info.append(patient_dict)

            total_patients = len(patients_with_med_info)
            page = request.args.get('page', 1, type=int)
            per_page = 10  # Number of patients per page
            offset = (page - 1) * per_page
            patients_to_display = patients_with_med_info[offset:offset + per_page]
            total_pages = (total_patients + per_page - 1) // per_page

            return render_template("doc_records.html", page=page, total_pages=total_pages, patients=patients_to_display)



@app.route("/doc_records/manage_records/<int:patient_id>", methods=["GET", "POST"])
@login_required
def manage_records(patient_id):
    user_type = session.get("user_type")
    if user_type != "Doctor":
        return render_template("404.html"), 404
    else:
        if request.method == "GET":
            user_id = session.get("user_id")
            db = get_db()
            appointment = db.execute("""
                SELECT a.AppointmentID
                FROM Appointments a
                INNER JOIN patients p ON a.PatientID = p.patient_id
                INNER JOIN doctors d ON a.DoctorID = d.doctor_id
                WHERE d.doctor_id = ? AND p.patient_id = ?
                LIMIT 1
            """, (user_id, patient_id)).fetchone()

            if not appointment:
                return render_template("404.html"), 404

            medical_records = db.execute("""
                SELECT visit_date, diagnosis, test_name, test_result, reference_range, test_date, follow_up_instructions
                FROM medical_records
                WHERE patient_id = ?
            """, (patient_id,)).fetchall()

            total_medical_records = len(medical_records)
            page = request.args.get('page', 1, type=int)
            per_page = 10  # Number of patients per page
            offset = (page - 1) * per_page
            medical_records = medical_records[offset:offset + per_page]
            total_pages = (total_medical_records + per_page - 1) // per_page

            return render_template("manage_patient_rec.html", medical_records=medical_records, page = page, total_pages = total_pages)
        else:
            # Validate form input using secure validation
            validation_errors, validated_data = validate_medical_record_form()
            
            if validation_errors:
                error_messages = validation_errors
            else:
                error_messages = []
                
                try:
                    db = get_db()
                    user_id = session.get("user_id")
                    
                    # Verify patient exists and doctor has access
                    patient_check = db.execute("""
                        SELECT p.patient_id FROM patients p
                        INNER JOIN Appointments a ON p.patient_id = a.PatientID
                        WHERE p.patient_id = ? AND a.DoctorID = ?
                        LIMIT 1
                    """, (patient_id, user_id))
                    
                    if not patient_check.fetchone():
                        error_messages.append("Access denied to this patient")
                    
                    if not error_messages:
                        today = date.today()
                        
                        # Insert medical record into database
                        db.execute("""
                            INSERT INTO medical_records (patient_id, doctor_id, visit_date,
                            diagnosis, test_name, test_result, reference_range, test_date, follow_up_instructions)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (patient_id, user_id, today, validated_data["diagnosis"], 
                             validated_data["test_name"], validated_data["test_result"], 
                             validated_data["reference_range"], validated_data["test_date"], 
                             validated_data["instructions"]))
                        
                        db.connection.commit()
                        flash("Successfully added a new medical record", "success")
                        return redirect(url_for("manage_records", patient_id=patient_id))
                        
                except sqlite3.Error as e:
                    error_messages.append("Database error occurred. Please try again.")

            # If there are errors, render form with error messages
            if error_messages:
                try:
                    db = get_db()
                    medical_records = db.execute("""
                        SELECT visit_date, diagnosis, test_name, test_result, reference_range, test_date, follow_up_instructions
                        FROM medical_records
                        WHERE patient_id = ?
                    """, (patient_id,)).fetchall()

                    return render_template("manage_patient_rec.html", 
                                        error_messages=error_messages,
                                        medical_records=medical_records,
                                        page=1, total_pages=1)
                except:
                    return render_template("manage_patient_rec.html", error_messages=error_messages)

@app.route("/expenses", methods=["GET" , "POST"])
@login_required
def expenses():
    user_type = session.get("user_type")
    if user_type != "admin":
        return render_template("404.html"),404

    admin_id = session.get("user_id")
    db = get_db()
    total_amount_supps = db.execute("SELECT SUM(amount) FROM medical_supplies WHERE admin_id = ?", (admin_id,)).fetchone()[0]
    total_payroll = db.execute("SELECT SUM(payroll) AS TotalPayroll FROM users WHERE admin_id = ?", (admin_id,)).fetchone()[0]
    total_utility_amount = db.execute("SELECT SUM(amount) AS TotalUtilityAmount FROM utilities WHERE admin_id = ?", (admin_id,)).fetchone()[0]
    total_amount_equs = db.execute("SELECT SUM(amount) AS total_amount FROM equipments WHERE admin_id = ?", (admin_id,)).fetchone()[0]
    total_marketing = db.execute("SELECT SUM(amount) AS total_amount FROM marketing WHERE admin_id = ?", (admin_id,)).fetchone()[0]
    total_other = db.execute("SELECT SUM(amount) AS total_amount FROM other_expenses WHERE admin_id = ?", (admin_id,)).fetchone()[0]


    return render_template("expenses.html" , total_amount_supps = total_amount_supps , total_payroll = total_payroll , total_utility_amount = total_utility_amount , total_amount_equs =  total_amount_equs, total_marketing = total_marketing , total_other = total_other)

@app.route("/expenses/medical_supp", methods=["GET", "POST"])
@login_required
def medical_supplies():
    user_type = session.get("user_type")
    if user_type != "admin":
        return render_template("404.html"), 404

    if request.method == "GET":
        db = get_db()
        admin_id = session.get("user_id")
        medical_supps = db.execute("SELECT amount, description FROM medical_supplies WHERE admin_id = ?", (admin_id,)).fetchall()

        total_medical_supps = len(medical_supps)
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Number of patients per page
        offset = (page - 1) * per_page
        medical_supps = medical_supps[offset:offset + per_page]
        total_pages = (total_medical_supps + per_page - 1) // per_page
        return render_template("medical_supp.html", medical_supps=medical_supps , page = page, total_pages = total_pages)

    else:
        # Validate form input using secure validation
        validation_errors, validated_data = validate_expense_form()
        
        if validation_errors:
            # Get medical supplies data for template rendering
            db = get_db()
            admin_id = session.get("user_id")
            medical_supps = db.execute("SELECT amount, description FROM medical_supplies WHERE admin_id = ?", (admin_id,)).fetchall()
            
            total_medical_supps = len(medical_supps)
            page = request.args.get('page', 1, type=int)
            per_page = 10
            offset = (page - 1) * per_page
            medical_supps = medical_supps[offset:offset + per_page]
            total_pages = (total_medical_supps + per_page - 1) // per_page
            
            error_messages = validation_errors
            return render_template("medical_supp.html", error_messages=error_messages,
                                 medical_supps=medical_supps, page=page, total_pages=total_pages)

        admin_id = session.get("user_id")

        try:
            db = get_db()
            td = datetime.today()
            db.execute("INSERT INTO medical_supplies (amount, description, admin_id, date) VALUES (?, ?, ?, ?)", 
                      (validated_data["amount"], validated_data["description"], admin_id, td))
            db.connection.commit()
            flash("Medical supply added successfully.", "success")
            return redirect(url_for("medical_supplies"))

        except sqlite3.Error as e:
            # Get medical supplies data for template rendering
            db = get_db()
            admin_id = session.get("user_id")
            medical_supps = db.execute("SELECT amount, description FROM medical_supplies WHERE admin_id = ?", (admin_id,)).fetchall()
            
            total_medical_supps = len(medical_supps)
            page = request.args.get('page', 1, type=int)
            per_page = 10
            offset = (page - 1) * per_page
            medical_supps = medical_supps[offset:offset + per_page]
            total_pages = (total_medical_supps + per_page - 1) // per_page
            
            error_messages = ["Database error occurred. Please try again."]
            return render_template("medical_supp.html", error_messages=error_messages,
                                 medical_supps=medical_supps, page=page, total_pages=total_pages)

@app.route("/expenses/salaries", methods=["GET"])
@login_required
def salaries():
    user_type = session.get("user_type")
    if user_type != "admin":
        return render_template("404.html"),404

    db = get_db()
    admin_id = session.get("user_id")
    salaries = db.execute("""
                SELECT u.first_name || ' ' || u.last_name AS UserName,
                       u.payroll AS Salary,
                       u.usertype AS Position
                FROM users u
                WHERE u.admin_id = ?
                GROUP BY u.first_name, u.last_name, u.payroll, u.usertype
            """, (admin_id,)).fetchall()
    total_salaries = len(salaries)
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of patients per page
    offset = (page - 1) * per_page
    salaries = salaries[offset:offset + per_page]
    total_pages = (total_salaries + per_page - 1) // per_page

    return render_template("salaries.html" , page = page, total_pages = total_pages , salaries = salaries)



@app.route("/expenses/utilities", methods=["GET", "POST"])
@login_required
def utilities():
    user_type = session.get("user_type")
    if user_type != "admin":
        return render_template("404.html"), 404

    if request.method == "GET":
        db = get_db()
        admin_id = session.get("user_id")
        utilities = db.execute("SELECT amount, description FROM utilities WHERE admin_id = ?", (admin_id,)).fetchall()        
        total_utilities = len(utilities)
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Number of patients per page
        offset = (page - 1) * per_page
        utilities = utilities[offset:offset + per_page]
        total_pages = (total_utilities + per_page - 1) // per_page
        return render_template("utilities.html", utilities=utilities, page=page, total_pages=total_pages)
    
    else:
        # Validate form input using secure validation
        validation_errors, validated_data = validate_expense_form()
        
        if validation_errors:
            # Get utilities data for template rendering
            db = get_db()
            admin_id = session.get("user_id")
            utilities = db.execute("SELECT amount, description FROM utilities WHERE admin_id = ?", (admin_id,)).fetchall()
            
            total_utilities = len(utilities)
            page = request.args.get('page', 1, type=int)
            per_page = 10
            offset = (page - 1) * per_page
            utilities = utilities[offset:offset + per_page]
            total_pages = (total_utilities + per_page - 1) // per_page
            
            error_messages = validation_errors
            return render_template("utilities.html", error_messages=error_messages, 
                                 utilities=utilities, page=page, total_pages=total_pages)

        admin_id = session.get("user_id")

        try:
            db = get_db()
            td = datetime.today()            
            db.execute("INSERT INTO utilities (amount, description, admin_id, date) VALUES (?, ?, ?, ?)", 
                      (validated_data["amount"], validated_data["description"], admin_id, td))
            db.connection.commit()
            flash("Utility bill added successfully.", "success")
            return redirect(url_for("utilities"))
            
        except sqlite3.Error as e:
            # Get utilities data for template rendering
            db = get_db()
            admin_id = session.get("user_id")
            utilities = db.execute("SELECT amount, description FROM utilities WHERE admin_id = ?", (admin_id,)).fetchall()
            
            total_utilities = len(utilities)
            page = request.args.get('page', 1, type=int)
            per_page = 10
            offset = (page - 1) * per_page
            utilities = utilities[offset:offset + per_page]
            total_pages = (total_utilities + per_page - 1) // per_page
            
            error_messages = ["Database error occurred. Please try again."]
            return render_template("utilities.html", error_messages=error_messages,
                                 utilities=utilities, page=page, total_pages=total_pages)

@app.route("/expenses/equipment", methods=["GET", "POST"])
@login_required
def equipment():
    user_type = session.get("user_type")
    if user_type != "admin":
        return render_template("404.html"), 404

    if request.method == "GET":
        db = get_db()
        admin_id = session.get("user_id")
        equipments = db.execute("SELECT description, amount FROM equipments WHERE admin_id = ?", (admin_id,)).fetchall()

        total_equipment = len(equipments)
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Number of patients per page
        offset = (page - 1) * per_page
        equipments = equipments[offset:offset + per_page]
        total_pages = (total_equipment + per_page - 1) // per_page

        return render_template("equipments.html", equipments = equipments , page = page, total_pages = total_pages)

    else:
        # Validate form input using secure validation
        validation_errors, validated_data = validate_expense_form()
        
        if validation_errors:
            # Get equipment data for template rendering
            db = get_db()
            admin_id = session.get("user_id")
            equipments = db.execute("SELECT description, amount FROM equipments WHERE admin_id = ?", (admin_id,)).fetchall()
            
            total_equipment = len(equipments)
            page = request.args.get('page', 1, type=int)
            per_page = 10
            offset = (page - 1) * per_page
            equipments = equipments[offset:offset + per_page]
            total_pages = (total_equipment + per_page - 1) // per_page
            
            error_messages = validation_errors
            return render_template("equipments.html", error_messages=error_messages,
                                 equipments=equipments, page=page, total_pages=total_pages)

        admin_id = session.get("user_id")

        try:
            db = get_db()
            td = datetime.today()
            db.execute("INSERT INTO equipments (amount, description, admin_id, date) VALUES (?, ?, ?, ?)", 
                      (validated_data["amount"], validated_data["description"], admin_id, td))
            db.connection.commit()
            flash("Equipment bill added successfully.", "success")
            return redirect(url_for("equipment"))

        except sqlite3.Error as e:
            # Get equipment data for template rendering
            db = get_db()
            admin_id = session.get("user_id")
            equipments = db.execute("SELECT description, amount FROM equipments WHERE admin_id = ?", (admin_id,)).fetchall()
            
            total_equipment = len(equipments)
            page = request.args.get('page', 1, type=int)
            per_page = 10
            offset = (page - 1) * per_page
            equipments = equipments[offset:offset + per_page]
            total_pages = (total_equipment + per_page - 1) // per_page
            
            error_messages = ["Database error occurred. Please try again."]
            return render_template("equipments.html", error_messages=error_messages,
                                 equipments=equipments, page=page, total_pages=total_pages)


@app.route("/expenses/marketing", methods=["GET", "POST"])
@login_required
def marketing():
    user_type = session.get("user_type")
    if user_type != "admin":
        return render_template("404.html"), 404

    if request.method == "GET":
        db = get_db()
        admin_id = session.get("user_id")

        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Number of marketing expenses per page
        offset = (page - 1) * per_page

        # Fetch marketing expenses for the current admin with pagination
        marketings = db.execute("""
            SELECT description, amount
            FROM marketing
            WHERE admin_id = ?
            LIMIT ? OFFSET ?
        """, (admin_id, per_page, offset)).fetchall()

        # Total number of marketing expenses for pagination
        total_marketing = db.execute("""
            SELECT COUNT(*) FROM marketing WHERE admin_id = ?
        """, (admin_id,)).fetchone()[0]

        # Calculate total pages for pagination
        total_pages = (total_marketing + per_page - 1) // per_page

        return render_template("marketing.html", marketings=marketings, page=page, total_pages=total_pages)

    else:        # Validate form input using secure validation
        validation_errors, validated_data = validate_expense_form()
        
        if validation_errors:
            # Get marketing data for template rendering
            db = get_db()
            admin_id = session.get("user_id")
            page = request.args.get('page', 1, type=int)
            per_page = 10
            offset = (page - 1) * per_page
            
            marketings = db.execute("""
                SELECT description, amount
                FROM marketing
                WHERE admin_id = ?
                LIMIT ? OFFSET ?
            """, (admin_id, per_page, offset)).fetchall()
            
            total_marketing = db.execute("""
                SELECT COUNT(*) FROM marketing WHERE admin_id = ?
            """, (admin_id,)).fetchone()[0]
            
            total_pages = (total_marketing + per_page - 1) // per_page
            
            error_messages = validation_errors
            return render_template("marketing.html", error_messages=error_messages,
                                 marketings=marketings, page=page, total_pages=total_pages)

        admin_id = session.get("user_id")

        try:
            db = get_db()
            td = datetime.today()
            db.execute("INSERT INTO marketing (amount, description, admin_id, date) VALUES (?, ?, ?, ?)", 
                      (validated_data["amount"], validated_data["description"], admin_id, td))
            db.connection.commit()
            flash("Marketing bill added successfully.", "success")
            return redirect(url_for("marketing"))

        except sqlite3.Error as e:
            # Get marketing data for template rendering
            db = get_db()
            admin_id = session.get("user_id")
            page = request.args.get('page', 1, type=int)
            per_page = 10
            offset = (page - 1) * per_page
            
            marketings = db.execute("""
                SELECT description, amount
                FROM marketing
                WHERE admin_id = ?
                LIMIT ? OFFSET ?
            """, (admin_id, per_page, offset)).fetchall()
            
            total_marketing = db.execute("""
                SELECT COUNT(*) FROM marketing WHERE admin_id = ?
            """, (admin_id,)).fetchone()[0]
            
            total_pages = (total_marketing + per_page - 1) // per_page
            
            error_messages = ["Database error occurred. Please try again."]
            return render_template("marketing.html", error_messages=error_messages,
                                 marketings=marketings, page=page, total_pages=total_pages)



@app.route("/expenses/other_expenses", methods=["GET", "POST"])
@login_required
def other_expenses():
    user_type = session.get("user_type")
    if user_type != "admin":
        return render_template("404.html"), 404

    if request.method == "GET":
        db = get_db()
        admin_id = session.get("user_id")
        other_expenses = db.execute("SELECT description, amount FROM other_expenses WHERE admin_id = ?", (admin_id,)).fetchall()

        total_other_expenses = len(other_expenses)
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Number of patients per page
        offset = (page - 1) * per_page
        other_expenses = other_expenses[offset:offset + per_page]
        total_pages = (total_other_expenses + per_page - 1) // per_page

        return render_template("other_expenses.html", other_expenses = other_expenses , page = page, total_pages = total_pages)    
    else:
        # Validate form input using secure validation
        validation_errors, validated_data = validate_expense_form()
        
        if validation_errors:
            # Get other expenses data for template rendering
            db = get_db()
            admin_id = session.get("user_id")
            other_expenses = db.execute("SELECT description, amount FROM other_expenses WHERE admin_id = ?", (admin_id,)).fetchall()
            
            total_other_expenses = len(other_expenses)
            page = request.args.get('page', 1, type=int)
            per_page = 10
            offset = (page - 1) * per_page
            other_expenses = other_expenses[offset:offset + per_page]
            total_pages = (total_other_expenses + per_page - 1) // per_page
            
            error_messages = validation_errors
            return render_template("other_expenses.html", error_messages=error_messages,
                                 other_expenses=other_expenses, page=page, total_pages=total_pages)

        admin_id = session.get("user_id")

        try:
            db = get_db()
            td = datetime.today()
            db.execute("INSERT INTO other_expenses (amount, description, admin_id, date) VALUES (?, ?, ?, ?)", 
                      (validated_data["amount"], validated_data["description"], admin_id, td))
            db.connection.commit()
            flash("Other Expenses bill added successfully.", "success")
            return redirect(url_for("other_expenses"))

        except sqlite3.Error as e:
            # Get other expenses data for template rendering
            db = get_db()
            admin_id = session.get("user_id")
            other_expenses = db.execute("SELECT description, amount FROM other_expenses WHERE admin_id = ?", (admin_id,)).fetchall()
            
            total_other_expenses = len(other_expenses)
            page = request.args.get('page', 1, type=int)
            per_page = 10
            offset = (page - 1) * per_page
            other_expenses = other_expenses[offset:offset + per_page]
            total_pages = (total_other_expenses + per_page - 1) // per_page
            
            error_messages = ["Database error occurred. Please try again."]
            return render_template("other_expenses.html", error_messages=error_messages,
                                 other_expenses=other_expenses, page=page, total_pages=total_pages)

@app.route("/get_expenses", methods=["GET"])
@login_required
def get_expenses():
    user_type = session.get("user_type")
    if user_type != "admin":
        return render_template("404.html"), 404

    admin_id = session.get("user_id")
    db = get_db()

    # Fetch total expenses with dates
    medical_expenses_by_date = db.execute("SELECT strftime('%Y-%m-%d', date) AS date, SUM(amount) FROM medical_supplies WHERE admin_id = ? GROUP BY date", (admin_id,)).fetchall()
    utilities_expenses_by_date = db.execute("SELECT strftime('%Y-%m-%d', date) AS date, SUM(amount) FROM utilities WHERE admin_id = ? GROUP BY date", (admin_id,)).fetchall()
    equipments_expenses_by_date = db.execute("SELECT strftime('%Y-%m-%d', date) AS date, SUM(amount) FROM equipments WHERE admin_id = ? GROUP BY date", (admin_id,)).fetchall()
    marketing_expenses_by_date = db.execute("SELECT strftime('%Y-%m-%d', date) AS date, SUM(amount) FROM marketing WHERE admin_id = ? GROUP BY date", (admin_id,)).fetchall()
    other_expenses_by_date = db.execute("SELECT strftime('%Y-%m-%d', date) AS date, SUM(amount) FROM other_expenses WHERE admin_id = ? GROUP BY date", (admin_id,)).fetchall()

    # Combine all fetched data
    expenses_data = {
        "medical": medical_expenses_by_date,
        "utilities": utilities_expenses_by_date,
        "equipments": equipments_expenses_by_date,
        "marketing": marketing_expenses_by_date,
        "other": other_expenses_by_date
    }

    return jsonify(expenses_data)


@app.route("/delete_doctor/<int:doc_id>", methods=["DELETE"])
@login_required
def delete_doc(doc_id):
    error_message = None
    user_type = session.get("user_type")
    if user_type != "admin":
        return render_template("404.html"), 404

    admin_id = session.get("user_id")
    db = get_db()

    # Check if the current admin is authorized to delete the doctor
    con = db.execute("SELECT admin_id FROM doctors WHERE doctor_id = ?", (doc_id,))
    row = con.fetchone()
    if not row or admin_id != row[0]:
        return render_template("404.html"), 404

    try:
        # Delete the doctor from the database
        db.execute("DELETE FROM doctors WHERE doctor_id = ?", (doc_id,))
        db.connection.commit()
        flash("Doctor was deleted successfully", "success")
        return redirect("/view_doctors")
    except sqlite3.Error as e:
        error_message = "Database error: " + str(e)
        flash("Failed to delete doctor. Please try again later.", "error")
        return jsonify({'error': error_message}), 500

@app.route("/delete_user/<int:user_id>", methods=["DELETE"])
@login_required
def delete_user(user_id):
    error_message = None
    user_type = session.get("user_type")
    if user_type != "admin":
        return render_template("404.html"), 404
    db = get_db()
    admin_id = session.get("user_id")
    con = db.execute("SELECT admin_id FROM users WHERE users_id = ?", (user_id,))
    row = con.fetchone()
    if not row or admin_id != row[0]:
        return render_template("404.html"), 404
    else:
        try:
            # Delete the user from the database
            db.execute("DELETE FROM users WHERE users_id = ?", (user_id,))
            db.connection.commit()
            flash("User was deleted successfully", "success")
            return redirect("/users")
        except sqlite3.Error as e:
            error_message = "Database error: " + str(e)
            flash("Failed to delete user. Please try again later.", "error")
            return jsonify({'error': error_message}), 500

@app.route("/delete_patient/<int:patient_id>", methods=["DELETE"])
@login_required
def delete_patient(patient_id):
    user_type = session.get("user_type")
    if user_type != "Receptionist":
        return render_template("404.html"), 404

    try:
        db = get_db()
        # Delete the patient record
        db.execute("DELETE FROM patients WHERE patient_id = ?", (patient_id,))
        db.connection.commit()
        flash("Patient was deleted successfully", "success")
        return redirect("/patients")
    except sqlite3.Error as e:
        error_message = "Database error: " + str(e)
        print(error_message)
        flash("Failed to delete patient. Please try again later.", "error")
        return jsonify({'error': 'Error message here'})

if __name__ == "__main__":
    # Check if database exists before starting the application
    if not os.path.exists(DATABASE):
        print(f"❌ Database file '{DATABASE}' does not exist!")
        print("📋 Please run one of the following commands to create the database:")
        print("   python init_database.py          # Create both databases")
        print("   python init_database.py development  # Create development database only")
        print("   python init_database.py production   # Create production database only")
        sys.exit(1)
    
    # Get configuration from environment variables
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 5000))
    debug_mode = os.getenv('DEBUG', 'True').lower() == 'true'
    
    # Production vs Development configuration
    if os.getenv('FLASK_ENV') == 'production':
        print("🚀 Starting MediFlow in PRODUCTION mode...")
        print(f"📊 Database: {DATABASE}")
        print(f"🔒 Security headers: ENABLED")
        print(f"🌐 Host: {host}:{port}")
        socketio.run(app, host=host, port=port, debug=False)
    else:
        print("🔧 Starting MediFlow in DEVELOPMENT mode...")
        print(f"📊 Database: {DATABASE}")
        print(f"🌐 Host: {host}:{port}")
        socketio.run(app, host=host, port=port, debug=debug_mode, allow_unsafe_werkzeug=True)