import os
from os.path import relpath
from flask import Flask, flash, g, render_template, request, session, url_for, redirect , jsonify , send_from_directory
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from helpers import login_required, generate_token , verify_token, validate_email , encrypt_message , decrypt_message, generate_unique_filename
import sqlite3
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, date, timedelta
import re
import calendar
from collections import defaultdict
from flask_socketio import SocketIO, emit , join_room, leave_room



app = Flask(__name__)
socketio = SocketIO(app)





# Configuration for session

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg'}
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configuration for database
DATABASE = 'mediflow.db'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db.cursor()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

def format_phone_number(phone_number):
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
    error_message = None

    # Get form data
    if request.method == "POST":
        email = request.form.get("email").lower()
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")
        first_name = request.form.get("first_name").capitalize()
        last_name = request.form.get("last_name").capitalize()

        # Validate form data
        if not email:
            error_message = "Please enter a valid email address"
        elif validate_email(email) is False:
            error_message = "Email is invalid"
        elif not password:
            error_message = "Password cannot be blank"
        elif not confirm:
            error_message = "Confirmation cannot be blank"
        elif not first_name:
            error_message = "First name cannot be blank"
        elif not last_name:
            error_message = "Last name cannot be blank"
        elif len(first_name) > 10:
            error_message = "First name cannot exceed 10 characters"
        elif len(last_name) > 10:
            error_message = "Last name cannot exceed 10 characters"
        elif not re.match("^[a-zA-Z]+$", first_name):
            error_message = "First name can only include letters"
        elif not re.match("^[a-zA-Z]+$", last_name):
            error_message = "Last name can only include letters"
        elif password != confirm:
            error_message = "Passwords must match"
        elif len(password) < 8 or len(password) > 20:
            error_message = "Password must be between 8-20 characters"
        elif not any(char.isdigit() for char in password):
            error_message = "Password must include at least one number"
        elif not any(char.isalpha() for char in password):
            error_message = "Password must include letters"
        elif not any(char in "!$@%" for char in password):
            error_message = "Password must include at least one of these special characters: !$@%"

        if error_message:
            return render_template("register.html", error_message=error_message)

        try:
            db = get_db()
            db.execute("SELECT id FROM admins WHERE LOWER(email) = ?", (email,))
            if db.fetchone():
                error_message = "Email is already in use"
            else:
                hashed_password = generate_password_hash(password)
                db.execute("INSERT INTO admins (email, hash, first_name, last_name) VALUES (?, ?, ?, ?)",
                            (email, hashed_password, first_name, last_name))
                db.connection.commit()
                flash("Successfully registered you can login into your account now")
                return redirect("/login")  # or any success redirection
        except sqlite3.Error as e:
            error_message = "Database error: " + str(e)
            if error_message:
                return render_template("register.html", error_message=error_message)
    else:
        return render_template("register.html")


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

    if request.method == "POST":
        token = request.args.get("token")
        email = request.args.get("email")
        new_password = request.form.get("new_password")
        confirm = request.form.get("confirm")

        try:
            db = get_db()
            admin_token = db.execute("SELECT reset_token FROM admins WHERE email = ?", (email,)).fetchone()
            user_token = db.execute("SELECT reset_token FROM users WHERE email = ?", (email,)).fetchone()
            doctor_token = db.execute("SELECT reset_token FROM doctors WHERE email = ?", (email,)).fetchone()

            if (admin_token is not None and token != admin_token[0]) or \
                (user_token is not None and token != user_token[0]) or \
                (doctor_token is not None and token != doctor_token[0]):
                    error_message = "Invalid or expired token"
                    return render_template("reset.html", error_message=error_message)

            if not verify_token(token):
                flash("Link has expired. Please enter your email address to get another one")
                return redirect("/forgotten")

            if not email:
                error_message = "Please enter an email address"
                return render_template("reset.html", error_message=error_message)

            # Password validation
            if not new_password:
                error_message = "New password cannot be blank"
            elif new_password != confirm:
                error_message = "Passwords must match"
            elif len(new_password) < 8 or len(new_password) > 20:
                error_message = "Password must be between 8-20 characters"
            elif not any(char.isdigit() for char in new_password):
                error_message = "Password must include at least one number"
            elif not any(char.isalpha() for char in new_password):
                error_message = "Password must include letters"
            elif not any(char in "!$@%" for char in new_password):
                error_message = "Password must include at least one of these special characters: !$@%"

            if not error_message:
                hashed_password = generate_password_hash(new_password)

                if admin_token:
                    db.execute("UPDATE admins SET hash = ? WHERE email = ?", (hashed_password, email))
                elif user_token:
                    db.execute("UPDATE users SET hash = ? WHERE email = ?", (hashed_password, email))
                elif doctor_token:
                    db.execute("UPDATE doctors SET hash = ? WHERE email = ?", (hashed_password, email))

                db.connection.commit()
                flash("Successfully changed password")
                return redirect("/login")

        except sqlite3.Error as e:
            error_message = "Database error: " + str(e)

    token = request.args.get("token")
    if not token:
        return redirect("/login")
    return render_template("reset.html", error_message=error_message)



@app.route("/login", methods=["GET", "POST"])
def login():
    error_message = None

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email:
            error_message = "Must provide email"
        elif not password:
            error_message = "Must provide password"
        else:
            db = get_db()
            admin = db.execute("SELECT * FROM admins WHERE email = ?", (email,)).fetchone()
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            doctor = db.execute("SELECT * FROM doctors WHERE email =?",(email,)).fetchone()

            if admin and check_password_hash(admin[4], password):  # Access hash using index 4
                session["user_id"] = admin[0]  # Access id using index 0
                session["user_type"] = "admin"
                if session ["user_type"] == "admin":
                    return redirect("/")
            elif user and check_password_hash(user[2], password):  # Access hash using index 2
                session["user_id"] = user[0]  # Access users_id using index 0
                session["user_type"] = user[5]
                if session["user_type"] == "Receptionist":
                    return redirect("/receptionist")
            elif doctor and check_password_hash(doctor[10], password):
                session["user_id"] = doctor[0]
                session["user_type"] = doctor[11]
                if session["user_type"] == "Doctor":

                    return redirect("/doctor")
            else:
                error_message = "Invalid email and/or password"

    if error_message:
        return render_template("login.html", error_message=error_message)
    else:
        return render_template("login.html")


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
    end_date_current_week = start_date_current_week + timedelta(days=6)

    # Convert dates to string format for SQL query
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
    start_date_previous_week = end_date_previous_week - timedelta(days=6)

    # Convert dates to string format for SQL query
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
        db = get_db()
        email = request.form.get("email").lower()  # Call lower as a method
        password = request.form.get("password")
        confirm = request.form.get("confirmation")
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        position = request.form.get("position")
        payroll = request.form.get("payroll")
        phone = request.form.get("phone")


        admin_id = session.get("user_id")

        result = db.execute("SELECT * FROM users WHERE LOWER(email) = ?", (email,))
        result2 = db.execute("SELECT * FROM admins WHERE LOWER(email) = ?", (email,))
        result3 = db.execute("SELECT * FROM doctors WHERE LOWER(email) = ?",(email,))

        if result.fetchone():
            error_messages.append("A user with this email address already exists")

        if result2.fetchone():
            error_messages.append("A user with this email address already exists")

        if result3.fetchone():
            error_messages.append("A user with this email address already exists")
        if not phone:
            error_messages.append("Phone number can't be empty")


        if password != confirm:
            error_messages.append("Passwords must match")

        if len(password) < 8 or len(password) > 20:
            error_messages.append("Password must be between 8-20 characters")

        if not any(char.isdigit() for char in password):
            error_messages.append("Password must include at least one number")

        if not any(char.isalpha() for char in password):
            error_messages.append("Password must include letters")

        allowed_special_char = "!$@%"
        if not any(char in allowed_special_char for char in password):
            error_messages.append("Password must include at least one of these special characters: "
                                  "!$@%")

        if firstname is not None and len(firstname) > 10:
            error_messages.append("First name cannot exceed 10 characters")
        if not re.match("^[a-zA-Z]+$", lastname):
            error_messages.append = ("Last name can only include letters")
        if not re.match("^[a-zA-Z]+$", firstname):
            error_messages.append ("First name can only include letters")
        if lastname is not None and len(lastname) > 10:
            error_messages.append("Last name cannot exceed 10 characters")

        if error_messages:  # If there are any error messages, render the template with error messages
            return render_template("users.html", error_messages=error_messages)
        else:

            hashed_password = generate_password_hash(password)
            db.execute("INSERT INTO users (email, hash, first_name, last_name, usertype, payroll, admin_id , phone_number) VALUES (?, ?, ?, ?, ?, ? ,? , ?)",
                       (email, hashed_password, firstname, lastname, position, payroll, admin_id, phone))
            db.connection.commit()# Commit the transaction

            flash("Sucessfully created a new user !")
            return redirect("/users")
    else:
        return render_template("add_users.html")


@app.route("/add_doctors", methods=["GET", "POST"])
@login_required
def add_doctors():
    error_messages = []
    user_type = session.get("user_type")

    # Check if the user is an admin
    if user_type is None or user_type != "admin":
        return render_template("404.html"), 404

    if request.method == "POST":
        db = get_db()
        email = request.form.get("new_email").lower()
        password = request.form.get("doc_password")
        confirm = request.form.get("confirm_doc")
        firstname = request.form.get("new_first").capitalize()
        lastname = request.form.get("new_last").capitalize()
        specialization = request.form.get("new_special").capitalize()
        payroll = request.form.get("new_pay")
        docexp = request.form.get("doc_exp")
        address = request.form.get("new_address")
        phone = request.form.get("new_phone")
        usertype = "Doctor"
        admin_id = session.get("user_id")
        monday_start = request.form.get("monday_start")
        monday_end = request.form.get("monday_end")
        tuesday_start = request.form.get("tuesday_start")
        tuesday_end = request.form.get("tuesday_end")
        wednesday_start = request.form.get("wednesday_start")
        wednesday_end = request.form.get("wednesday_end")
        thursday_start = request.form.get("thursday_start")
        thursday_end = request.form.get("thursday_end")
        friday_start = request.form.get("friday_start")
        friday_end = request.form.get("friday_end")
        saturday_start = request.form.get("saturday_start")
        saturday_end = request.form.get("saturday_end")
        sunday_start = request.form.get("sunday_start")
        sunday_end = request.form.get("sunday_end")

        try:
            result3 = db.execute("SELECT * FROM doctors WHERE LOWER(email) = ?", (email,))
            result = db.execute("SELECT * FROM users WHERE LOWER(email) = ?", (email,))
            result2 = db.execute("SELECT * FROM admins WHERE LOWER(email) = ?", (email,))

        except sqlite3.Error as e:
            error_messages.append("Database error: " + str(e))

        # Check if the email already exists in the database
        if result3.fetchone():
            error_messages.append("A doctor with this email already exists")

        if result.fetchone():
            error_messages.append("A user with this email address already exists")

        if result2.fetchone():
            error_messages.append("An admin with this email address already exists")

        # Validate email format
        if not validate_email(email):
            error_messages.append("Invalid email format")

        # Validate password
        if password != confirm:
            error_messages.append("Passwords must match")

        if len(password) < 8 or len(password) > 20:
            error_messages.append("Password must be between 8-20 characters")

        if not any(char.isdigit() for char in password):
            error_messages.append("Password must include at least one number")

        if not any(char.isalpha() for char in password):
            error_messages.append("Password must include letters")

        if not any(char in "!$@%" for char in password):
            error_messages.append("Password must include at least one of these special characters: !$@%")

        # Validate first and last name
        if len(firstname) > 10:
            error_messages.append("First name cannot exceed 10 characters")

        if not re.match("^[a-zA-Z]+$", lastname):
            error_messages.append("Last name can only include letters")

        if not re.match("^[a-zA-Z]+$", firstname):
            error_messages.append("First name can only include letters")

        if len(lastname) > 10:
            error_messages.append("Last name cannot exceed 10 characters")

        # Validate years of experience
        if not docexp:
            error_messages.append("Please enter a value for doctor experience")
        if error_messages:
            return render_template("add_doctors.html", error_messages=error_messages)
        docexp_int = int(docexp)
        if docexp_int <= 0 :
            error_messages.append("Enter a valid number for experience")

        # If there are any errors, render the template with error messages
        if error_messages:
            return render_template("add_doctors.html", error_messages=error_messages)

        else:
            # Insert doctor into the database
            hashed_password = generate_password_hash(password)
            try:
                db.execute("INSERT INTO doctors (email, phone, years_of_experience, hash, first_name, last_name, specialization, usertype, address, payroll, admin_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (email, phone, int(docexp), hashed_password, firstname, lastname, specialization, usertype, address, payroll, admin_id))
                doc_id_cursor = db.execute("SELECT doctor_id FROM doctors WHERE email = ?", (email,))
                doc_id = doc_id_cursor.fetchone()[0]  # Fetch the doctor ID from the cursor

                # Define the values
                values = [
                    (doc_id, "Monday", monday_start, monday_end),
                    (doc_id, "Tuesday", tuesday_start, tuesday_end),
                    (doc_id, "Wednesday", wednesday_start, wednesday_end),
                    (doc_id, "Thursday", thursday_start, thursday_end),
                    (doc_id, "Friday", friday_start, friday_end),
                    (doc_id, "Saturday", saturday_start, saturday_end),
                    (doc_id, "Sunday", sunday_start, sunday_end)
                ]

                # Insert values into the doctor_working_hours table
                for value in values:
                    db.execute("INSERT INTO doctor_working_hours (doctor_id, day_of_week, start_working_hours, end_working_hours) VALUES (?, ?, ?, ?);", value)
                db.connection.commit()  # Commit the transaction
                flash("Successfully created a new doctor!")
                return redirect("/view_doctors")
            except sqlite3.Error as e:
                error_messages.append("Database error: " + str(e))
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
        file_date = request.form.get("date")
        if not file_date:
            error_message = "Please enter a date"

        if 'document' not in request.files:
            flash('No file part')
            return redirect("/upload")

        file = request.files['document']
        if file.filename == '':
            flash('No selected file')
            return redirect("/upload")

        try:
            current_date = date.today()
            today_date = current_date.strftime("%Y-%m-%d")
            # You can now use today_date as needed in your code
        except Exception as e:
            print("An error occurred:", e)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename = generate_unique_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Store the filename, date, and user ID in the database
            try:
                db = get_db()
                user_id = session.get("user_id")
                patient = request.args.get("data-patient-id")
                db.execute("INSERT INTO files (filename, filepath, file_date, created_by , patient_id , date_uploaded) VALUES (?, ?, ?, ?, ? , ?)",
                        (filename, file_path, file_date, user_id, patient , today_date))
                db.connection.commit()

                personal = db.execute("SELECT * FROM patients WHERE patient_id = ? AND created_by IN (SELECT users_id FROM users WHERE admin_id = (SELECT admin_id FROM users WHERE users_id = ?))", (patient, user_id)).fetchall()

            except sqlite3.Error as e:
                error_message = "Database error: " + str(e)

            if error_message:
                return render_template("upload.html" , error_message = error_message)
            else:
                flash("File Uploaded Successfully")
                return redirect(f"/upload?data-patient-id={personal[0][0] if personal else ''}")

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
    error_message = None

    if request.method == "POST":

        db = get_db()
        first_name = request.form.get("newFirstName").capitalize()
        last_name = request.form.get("newLastName").capitalize()
        date = request.form.get("newDOB")
        gender = request.form.get("newGender")
        address = request.form.get("newAddress")
        email = request.form.get("newEmail").lower()
        phone = request.form.get("newPhone")
        insurance = request.form.get("newInsurance").capitalize()
        user_id = session.get("user_id")

         # Input Validation
        error_message = None
        if len(first_name) > 10:
            error_message = "First name cannot exceed 10 characters"
        elif len(last_name) > 10:
            error_message = "Last name cannot exceed 10 characters"
        elif len(phone) > 15:
            error_message = "Invalid phone number"
        elif not re.match("^[a-zA-Z]+$", first_name):
            error_message = "First name can only include letters"
        elif not re.match("^[a-zA-Z]+$", last_name):
            error_message = "Last name can only include letters"

        if error_message:
            return render_template("new_patient.html", error_message=error_message)

        try:
            # Check if the patient already exists
            result = db.execute("SELECT * FROM patients WHERE LOWER(email) = ?", (email,))
            if result.fetchone():
                error_message = "A patient with this email address already exists"
                return render_template("new_patient.html", error_message=error_message)

            # Insert new patient into the database
            name = first_name +" "+last_name
            db.execute("INSERT INTO patients (name , date_of_birth, gender, address, phone, email, insurance, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       (name, date, gender, address, phone, email, insurance, user_id))
            db.connection.commit()
            flash("New patient created successfully")
            return redirect("/patients")

        except sqlite3.Error as e:
            error_message = "Database error: " + str(e)
        if error_message :
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
        error_message = None
        db = get_db()

        app_id = request.form.get("app_ID")
        app_date = request.form.get("app_date")
        app_doc = request.form.get("app_doctor")
        app_start = request.form.get("app_start")
        today_date = datetime.today().date()
        reason = request.form.get("app_reason")
        notes = request.form.get("app_notes")
        created_by = session.get("user_id")

        # Fetch the doctor based on the provided doctor ID
        doctor = db.execute("SELECT doctor_id FROM doctors WHERE doctor_id = ?", (app_doc,)).fetchone()

        if not doctor:
            error_message = "Doctor does not exist"
        else:
            # Fetch doctor's working hours
            date = datetime.strptime(app_date, '%Y-%m-%d')
            weekday = date.strftime('%A')
            doc_time = db.execute("SELECT start_working_hours, end_working_hours FROM doctor_working_hours WHERE doctor_id = ? AND day_of_week = ?", (app_doc, weekday)).fetchone()

            if not doc_time:
                error_message = "Doctor working hours not found"
            else:
                doc_start_time = datetime.strptime(doc_time[0], '%H:%M').time()

                app_start_time = datetime.strptime(app_start, '%H:%M').time()

                if app_start_time < doc_start_time:
                    error_message = "Doctor won't be available during this time"

            # Check if the patient exists
            result = db.execute("SELECT * FROM patients WHERE patient_id = ?", (app_id,)).fetchone()

            if not result:
                error_message = "Patient does not exist"

            elif app_date is None:
                error_message = "Appointment Date is required"

            elif today_date > datetime.strptime(app_date, '%Y-%m-%d').date():
                error_message = "Invalid Date"

        if error_message:
            # Pass error_message to the template for displaying the error
            user_id = session.get("user_id")
            admin_id = db.execute("SELECT admin_id FROM users WHERE users_id = ?", (user_id,)).fetchone()[0]
            doctors = db.execute("SELECT last_name, doctor_id FROM doctors WHERE admin_id = ?", (admin_id,)).fetchall()
            return render_template("new_appointments.html", error_message=error_message, doctors = doctors)

        try:
            # Insert the appointment into the database
            db.execute("INSERT INTO Appointments (PatientID, AppointmentDate, StartTime, DoctorID, Reason, Notes , created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (app_id, app_date, app_start, app_doc, reason, notes , created_by))
            db.connection.commit()
            flash("New appointment created successfully")
            return redirect("/appointments")

        except sqlite3.Error as e:
            # Handle database errors
            error_message = "Database error: " + str(e)
            return render_template("new_appointments.html", error_message=error_message, doctors = doctors)

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
    error_message = None
    user_type = session.get("user_type")
    if user_type != "Doctor":
        return render_template("404.html"), 404
    else:
        if request.method == "GET":
            db = get_db()
            prescriptions = db.execute("SELECT medication, dosage, instructions, date_prescribed, prescription_id FROM prescriptions WHERE patient_id = ?", (patient_id,)).fetchall()

            total_prescriptions = len(prescriptions)
            page = request.args.get('page', 1, type=int)
            per_page = 10  # Number of patients per page
            offset = (page - 1) * per_page
            prescriptions = prescriptions[offset:offset + per_page]
            total_pages = (total_prescriptions + per_page - 1) // per_page

            history_prescriptions = db.execute("SELECT medication, dosage, instructions, date_prescribed, prescription_id FROM history_prescriptions WHERE patient_id = ?", (patient_id,)).fetchall()

            total_history_prescriptions  = len(history_prescriptions)
            page = request.args.get('page', 1, type=int)
            per_page = 10  # Number of patients per page
            offset = (page - 1) * per_page
            history_prescriptions = history_prescriptions[offset:offset + per_page]
            total_pages = (total_history_prescriptions + per_page - 1) // per_page

            return render_template("manage_prescriptions.html" , prescriptions=prescriptions, page = page , total_pages = total_pages , history_prescriptions = history_prescriptions)

        else:
            user_id = session.get("user_id")
            medication = request.form.get("medication")
            dosage = request.form.get("dosage")
            instructions = request.form.get("instructions")
            date_td = date.today()
            if not (medication and dosage and instructions):
                error_message = "Please fill in all the fields"
            else:
                try:
                    db = get_db()
                    db.execute("INSERT INTO prescriptions (patient_id, doctor_id, medication, dosage, instructions, date_prescribed) VALUES (?, ?, ?, ?, ?, ?)", (patient_id, user_id, medication, dosage, instructions, date_td))
                    db.execute("INSERT INTO history_prescriptions (patient_id, doctor_id, medication, dosage, instructions, date_prescribed) VALUES (?, ?, ?, ?, ?, ?)", (patient_id, user_id, medication, dosage, instructions, date_td))
                    db.connection.commit()
                except sqlite3.Error as e:
                    error_message = "Database error: " + str(e)

            if error_message:
                return render_template("manage_prescriptions.html", error_message=error_message,)
            else:
                flash("Successfully added a new prescription")
                return redirect(url_for("manage_prescriptions", patient_id=patient_id))

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
            db = get_db()
            error_message = None
            diagnosis = request.form.get("diagnosis")
            instructions = request.form.get("instructions")

            if not (diagnosis and instructions):
                error_message = "Please fill in both Diagnosis and Instructions fields"

            if error_message:
                medical_records = db.execute("""
                    SELECT visit_date, diagnosis, test_name, test_result, reference_range, test_date , follow_up_instructions
                    FROM medical_records
                    WHERE patient_id = ?
                """, (patient_id,)).fetchall()
                return render_template("manage_patient_rec.html", medical_records=medical_records, error_message=error_message)

            test_name = request.form.get("test_name")
            test_result = request.form.get("result")
            reference_range = request.form.get("reference_range")
            test_date = request.form.get("date")

            today = date.today()
            doc_id = session.get("user_id")

            try:
                db.execute("""
                    INSERT INTO medical_records (patient_id, doctor_id, visit_date,
                    diagnosis, test_name, test_result, reference_range, test_date, follow_up_instructions)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (patient_id, doc_id, today, diagnosis, test_name, test_result, reference_range, test_date,  instructions))
                db.connection.commit()

            except sqlite3.Error as e:
                error_message = f"Database error {e}"
                print(error_message)
                medical_records = db.execute("""
                    SELECT visit_date, diagnosis, test_name, test_result, reference_range, test_date, follow_up_instructions
                    FROM medical_records
                    WHERE patient_id = ?
                """, (patient_id,)).fetchall()
                return render_template("manage_patient_rec.html", medical_records=medical_records, error_message=error_message)

            flash("Successfully added a new record")
            return redirect(url_for("manage_records", patient_id=patient_id))

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
        error_message = None
        amount = request.form.get("amount")
        description = request.form.get("description")

        if not amount or not description:
            error_message = "Please fill in all the required fields."

        if error_message:
            return render_template("medical_supp.html", error_message=error_message)

        admin_id = session.get("user_id")

        try:
            db = get_db()
            td = datetime.today()
            db.execute("INSERT INTO medical_supplies (amount, description, admin_id, date) VALUES (?, ?, ?, ?)", (amount, description, admin_id, td))
            db.connection.commit()
            flash("Medical supply added successfully.")
            return redirect(url_for("medical_supplies"))

        except sqlite3.Error as e:
            error_message = "Database error: " + str(e)
            return render_template("medical_supp.html", error_message=error_message)

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
        return render_template("utilities.html", utilities = utilities , page = page, total_pages = total_pages)

    else:
        error_message = None
        amount = request.form.get("amount")
        description = request.form.get("description")

        if not amount or not description:
            error_message = "Please fill in all the required fields."

        if error_message:
            return render_template("utilities.html", error_message=error_message)

        admin_id = session.get("user_id")

        try:
            db = get_db()
            td = datetime.today()
            db.execute("INSERT INTO utilities (amount, description, admin_id, date) VALUES (?, ?, ?, ?)", (amount, description, admin_id, td))
            db.connection.commit()
            flash("Utility bill added successfully.")
            return redirect(url_for("utilities"))

        except sqlite3.Error as e:
            error_message = "Database error: " + str(e)
            return render_template("utilities.html", error_message=error_message)

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
        marketing = equipments[offset:offset + per_page]
        total_pages = (total_equipment + per_page - 1) // per_page

        return render_template("equipments.html", equipments = equipments , page = page, total_pages = total_pages)

    else:
        error_message = None
        amount = request.form.get("amount")
        description = request.form.get("description")

        if not amount or not description:
            error_message = "Please fill in all the required fields."

        if error_message:
            return render_template("equipments.html", error_message=error_message)

        admin_id = session.get("user_id")

        try:
            db = get_db()
            td = datetime.today()
            db.execute("INSERT INTO equipments (amount, description, admin_id, date) VALUES (?, ?, ?, ?)", (amount, description, admin_id, td))
            db.connection.commit()
            flash("Equipment bill added successfully.")
            return redirect(url_for("equipment"))

        except sqlite3.Error as e:
            error_message = "Database error: " + str(e)
            return render_template("equipments.html", error_message=error_message)


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

    else:
        # Handling form submission for adding new marketing expense
        error_message = None
        amount = request.form.get("amount")
        description = request.form.get("description")

        if not amount or not description:
            error_message = "Please fill in all the required fields."

        if error_message:
            return render_template("marketing.html", error_message=error_message)

        admin_id = session.get("user_id")

        try:
            db = get_db()
            td = datetime.today()
            db.execute("INSERT INTO marketing (amount, description, admin_id, date) VALUES (?, ?, ?, ?)", (amount, description, admin_id, td))
            db.connection.commit()
            flash("Marketing bill added successfully.")
            return redirect(url_for("marketing"))

        except sqlite3.Error as e:
            error_message = "Database error: " + str(e)
            return render_template("marketing.html", error_message=error_message)



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
        error_message = None
        amount = request.form.get("amount")
        description = request.form.get("description")

        if not amount or not description:
            error_message = "Please fill in all the required fields."

        if error_message:
            return render_template("equipments.html", error_message=error_message)

        admin_id = session.get("user_id")

        try:
            db = get_db()
            td = datetime.today()
            db.execute("INSERT INTO other_expenses (amount, description, admin_id, date) VALUES (?, ?, ?, ?)", (amount, description, admin_id, td))
            db.connection.commit()
            flash("Other Expenses bill added successfully.")
            return redirect(url_for("other_expenses"))

        except sqlite3.Error as e:
            error_message = "Database error: " + str(e)
            return render_template("other_expenses.html", error_message=error_message)

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
