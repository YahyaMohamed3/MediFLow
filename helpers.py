from flask import redirect, render_template, session
from functools import wraps
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import jwt
from jwt.exceptions import ExpiredSignatureError
from datetime import datetime, timedelta
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import os
import logging
from datetime import datetime, timedelta
import sqlite3
import uuid



def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function

def generate_token(email):
    # Set token expiration to 1 hour from now
    expiration_time = datetime.utcnow() + timedelta(hours=1)
    payload = {'email': email, 'exp': expiration_time}
    token = jwt.encode(payload, 'lDJb00kAG8RoAsRhIA^2rO4WAI)_PqhW', algorithm='HS256')
    return token


def verify_token(token):
    try:
        payload = jwt.decode(token, 'lDJb00kAG8RoAsRhIA^2rO4WAI)_PqhW', algorithms=['HS256'])
        # Check if the token has expired
        if datetime.utcnow() > datetime.fromtimestamp(payload['exp']):
            return False  # Token has expired
        return True  # Token is valid
    except ExpiredSignatureError:
        return False  # Token has expired
    except Exception:
        return False


def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def encrypt_message(key, message):
    # Ensure that the message is encoded as bytes
    if not isinstance(message, bytes):
        message = message.encode()

    # Pad the message to meet AES block size requirements
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()

    # Generate a random initialization vector
    iv = os.urandom(16)

    # Create an AES cipher with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Encrypt the data
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()

    # Return the encrypted data and initialization vector
    return cipher_text, iv

def decrypt_message(key, cipher_text, iv):
    # Create an AES cipher with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Decrypt the data
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(cipher_text) + decryptor.finalize()

    logging.debug("Padded data after decryption: %s", padded_data)

    # Remove padding from the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    try:
        unpadded_data = unpadder.update(padded_data) + unpadder.finalize()
    except ValueError:
        # Handle the case where padding is invalid
        logging.error("Invalid padding bytes detected.")
        raise ValueError("Invalid padding bytes.")

    logging.info("Message decrypted successfully.")

    # Decode the decrypted byte string to a UTF-8 encoded string
    decrypted_message = unpadded_data.decode('utf-8')

    # Return the decrypted message
    return decrypted_message





def format_message_timestamp(timestamp_str):
    # Truncate microseconds from the timestamp string
    timestamp_str = timestamp_str.split('.')[0]

    # Convert the truncated timestamp string to a datetime object
    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')

    # Get the current date and time
    current_time = datetime.now()

    # Calculate the difference between the current time and the message timestamp
    time_difference = current_time - timestamp

    # If more than a week has passed, display the date
    if time_difference.days >= 7:
        return timestamp.strftime('%Y-%m-%d')

    # If the message is from the same week
    elif current_time.strftime('%W') == timestamp.strftime('%W'):
        # If the message is from today, display the time
        if current_time.date() == timestamp.date():
            return timestamp.strftime('%H:%M')
        # Otherwise, display the day name
        else:
            return timestamp.strftime('%A')

    # If the message is from a different week, display the date
    else:
        return timestamp.strftime('%Y-%m-%d')


def generate_unique_filename(filename):
    # Generate a unique identifier
    unique_identifier = uuid.uuid4().hex

    # Split the filename and its extension
    name, extension = os.path.splitext(filename)

    # Remove any leading or trailing whitespaces in the filename
    name = name.strip()

    # Concatenate the original filename, unique identifier, and file extension
    new_filename = f"{name}_{unique_identifier}{extension}"

    return new_filename

