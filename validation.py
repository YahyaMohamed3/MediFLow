"""
Input Validation and Sanitization Module for MediFlow
Comprehensive security validation without external dependencies
"""

import re
import sqlite3
from datetime import datetime, date
from flask import request, flash
from markupsafe import escape
import html


class InputValidator:
    """Comprehensive input validation class"""
    
    @staticmethod
    def sanitize_input(input_string):
        """Sanitize user input to prevent XSS and injection attacks"""
        if not input_string:
            return ""
        
        # Remove any script tags and dangerous content
        input_string = re.sub(r'<script.*?</script>', '', str(input_string), flags=re.IGNORECASE | re.DOTALL)
        input_string = re.sub(r'<.*?>', '', input_string)  # Remove all HTML tags
        input_string = html.escape(input_string)  # Escape HTML entities
        input_string = input_string.strip()  # Remove leading/trailing whitespace
        
        return input_string
    
    @staticmethod
    def validate_email(email):
        """Validate email format and security"""
        if not email:
            return False, "Email is required"
        
        email = InputValidator.sanitize_input(email)
        
        # Basic email regex pattern
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, email):
            return False, "Please provide a valid email address"
        
        if len(email) > 254:  # RFC 5321 limit
            return False, "Email address is too long"
            
        return True, email.lower()
    
    @staticmethod
    def validate_password(password):
        """Validate password strength and security"""
        if not password:
            return False, "Password is required"
        
        errors = []
        
        # Length check
        if len(password) < 8 or len(password) > 20:
            errors.append("Password must be between 8-20 characters")
        
        # Check for at least one digit
        if not any(char.isdigit() for char in password):
            errors.append("Password must include at least one number")
        
        # Check for at least one letter
        if not any(char.isalpha() for char in password):
            errors.append("Password must include letters")
        
        # Check for required special characters
        allowed_special_chars = "!$@%"
        if not any(char in allowed_special_chars for char in password):
            errors.append("Password must include at least one of these special characters: !$@%")
        
        # Check for common patterns to avoid
        if password.lower() in ['password', '12345678', 'qwerty123', 'admin123']:
            errors.append("Password is too common")
        
        if errors:
            return False, "; ".join(errors)
        
        return True, password
    
    @staticmethod
    def validate_name(name, field_name="Name", min_length=1, max_length=50):
        """Validate name fields"""
        if not name:
            return False, f"{field_name} is required"
        
        name = InputValidator.sanitize_input(name)
        
        if len(name) < min_length or len(name) > max_length:
            return False, f"{field_name} must be between {min_length}-{max_length} characters"
        
        # Allow letters, spaces, apostrophes, and hyphens for names
        if not re.match(r"^[a-zA-Z\s'-]+$", name):
            return False, f"{field_name} can only include letters, spaces, apostrophes, and hyphens"
        
        return True, name.strip().title()
    
    @staticmethod
    def validate_phone(phone):
        """Validate phone number"""
        if not phone:
            return False, "Phone number is required"
        
        phone = InputValidator.sanitize_input(phone)
        
        # Remove all non-digit characters
        digits_only = re.sub(r'[^\d]', '', phone)
        
        # Check if it's between 10-15 digits
        if not (10 <= len(digits_only) <= 15):
            return False, "Phone number must be between 10-15 digits"
        
        return True, phone
    @staticmethod
    def validate_unique_email(email, user_id=None):
        """Check if email is unique in database"""
        try:
            db = sqlite3.connect('mediflow.db')
            cursor = db.cursor()
            
            # Check in all user tables with their specific ID column names
            tables_and_ids = [
                ('users', 'users_id'),
                ('doctors', 'doctor_id'), 
                ('admins', 'id')
            ]
            
            for table, id_column in tables_and_ids:
                if user_id:
                    cursor.execute(f"SELECT email FROM {table} WHERE email = ? AND {id_column} != ?", (email, user_id))
                else:
                    cursor.execute(f"SELECT email FROM {table} WHERE email = ?", (email,))
                
                if cursor.fetchone():
                    db.close()
                    return False, "A user with this email address already exists"
            
            db.close()
            return True, email
            
        except sqlite3.Error as e:
            return False, f"Database error: {str(e)}"
    
    @staticmethod
    def validate_date(date_string, field_name="Date"):
        """Validate date input"""
        if not date_string:
            return False, f"{field_name} is required"
        
        try:
            # Try to parse the date
            parsed_date = datetime.strptime(date_string, '%Y-%m-%d').date()
            return True, parsed_date
        except ValueError:
            return False, f"Please provide a valid {field_name.lower()} in YYYY-MM-DD format"
    
    @staticmethod
    def validate_appointment_date(date_string):
        """Validate appointment date (cannot be in the past)"""
        is_valid, result = InputValidator.validate_date(date_string, "Appointment date")
        
        if not is_valid:
            return is_valid, result
        
        # Check if date is not in the past
        if result < date.today():
            return False, "Appointment date cannot be in the past"
        
        return True, result
    
    @staticmethod
    def validate_text_area(text, field_name="Text", min_length=5, max_length=500):
        """Validate text area input"""
        if not text:
            return False, f"{field_name} is required"
        
        text = InputValidator.sanitize_input(text)
        
        if len(text) < min_length or len(text) > max_length:
            return False, f"{field_name} must be between {min_length}-{max_length} characters"
        
        return True, text
    
    @staticmethod
    def validate_number(number_string, field_name="Number", min_val=0, max_val=None):
        """Validate numeric input"""
        if not number_string:
            return True, None  # Optional field
        
        try:
            number = float(number_string)
            
            if number < min_val:
                return False, f"{field_name} must be at least {min_val}"
            
            if max_val is not None and number > max_val:
                return False, f"{field_name} cannot exceed {max_val}"
            
            return True, number
            
        except ValueError:
            return False, f"Please provide a valid {field_name.lower()}"
    
    @staticmethod
    def validate_select_field(value, field_name="Selection", allowed_values=None):
        """Validate select field input"""
        if not value:
            return False, f"Please select a {field_name.lower()}"
        
        value = InputValidator.sanitize_input(value)
        
        if allowed_values and value not in allowed_values:
            return False, f"Invalid {field_name.lower()} selected"
        
        return True, value


class CSRFTokenGenerator:
    """Simple CSRF token generator for enhanced security"""
    
    @staticmethod
    def generate_token():
        """Generate a simple CSRF token using session"""
        import secrets
        from flask import session
        
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
        return token
    
    @staticmethod
    def validate_token(token):
        """Validate CSRF token"""
        from flask import session
        
        stored_token = session.get('csrf_token')
        if not stored_token or not token or stored_token != token:
            return False
        return True
    
    @staticmethod
    def require_csrf(f):
        """Decorator to require CSRF token for POST requests"""
        from functools import wraps
        from flask import request, abort
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method == "POST":
                token = request.form.get('csrf_token')
                if not CSRFTokenGenerator.validate_token(token):
                    abort(400, description="CSRF token missing or invalid")
            return f(*args, **kwargs)
        return decorated_function


def validate_login_form():
    """Validate login form data"""
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    
    errors = []
    
    # Validate email
    is_valid, result = InputValidator.validate_email(email)
    if not is_valid:
        errors.append(result)
    else:
        email = result
    
    # Validate password presence (not strength for login)
    if not password:
        errors.append("Password is required")
    
    return errors, {"email": email, "password": password}


def validate_registration_form():
    """Validate registration form data"""
    email = request.form.get("email", "").strip()
    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    
    errors = []
    validated_data = {}
    
    # Validate email
    is_valid, result = InputValidator.validate_email(email)
    if not is_valid:
        errors.append(result)
    else:
        # Check if email is unique
        is_unique, unique_result = InputValidator.validate_unique_email(result)
        if not is_unique:
            errors.append(unique_result)
        else:
            validated_data["email"] = result
    
    # Validate first name
    is_valid, result = InputValidator.validate_name(first_name, "First name", max_length=10)
    if not is_valid:
        errors.append(result)
    else:
        validated_data["first_name"] = result
    
    # Validate last name  
    is_valid, result = InputValidator.validate_name(last_name, "Last name", max_length=10)
    if not is_valid:
        errors.append(result)
    else:
        validated_data["last_name"] = result
    
    # Validate password
    is_valid, result = InputValidator.validate_password(password)
    if not is_valid:
        errors.append(result)
    else:
        validated_data["password"] = result
    
    # Validate password confirmation
    if password != confirm_password:
        errors.append("Passwords must match")
    
    return errors, validated_data


def validate_user_form():
    """Validate add user form data"""
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    password = request.form.get("password", "")
    confirmation = request.form.get("confirmation", "")
    position = request.form.get("position", "").strip()
    payroll = request.form.get("payroll", "").strip()
    
    errors = []
    validated_data = {}
    
    # Validate email
    is_valid, result = InputValidator.validate_email(email)
    if not is_valid:
        errors.append(result)
    else:
        is_unique, unique_result = InputValidator.validate_unique_email(result)
        if not is_unique:
            errors.append(unique_result)
        else:
            validated_data["email"] = result
    
    # Validate phone
    is_valid, result = InputValidator.validate_phone(phone)
    if not is_valid:
        errors.append(result)
    else:
        validated_data["phone"] = result
    
    # Validate names
    is_valid, result = InputValidator.validate_name(first_name, "First name", max_length=10)
    if not is_valid:
        errors.append(result)
    else:
        validated_data["first_name"] = result
    
    is_valid, result = InputValidator.validate_name(last_name, "Last name", max_length=10)
    if not is_valid:
        errors.append(result)
    else:
        validated_data["last_name"] = result
    
    # Validate password
    is_valid, result = InputValidator.validate_password(password)
    if not is_valid:
        errors.append(result)
    else:
        validated_data["password"] = result
    
    # Validate password confirmation
    if password != confirmation:
        errors.append("Passwords must match")
    
    # Validate position
    allowed_positions = ['Receptionist', 'Nurse', 'Medical Assistant']
    is_valid, result = InputValidator.validate_select_field(position, "Position", allowed_positions)
    if not is_valid:
        errors.append(result)
    else:
        validated_data["position"] = result
    
    # Validate payroll (optional)
    if payroll:
        is_valid, result = InputValidator.validate_number(payroll, "Payroll", min_val=0)
        if not is_valid:
            errors.append(result)
        else:
            validated_data["payroll"] = result
    else:
        validated_data["payroll"] = None
    
    return errors, validated_data


def validate_doctor_form():
    """Validate doctor registration form with comprehensive security checks"""
    from flask import request
    
    errors = []
    data = {}
    
    # Sanitize and validate basic fields
    email = request.form.get("new_email", "").strip().lower()
    password = request.form.get("doc_password", "")
    confirm_password = request.form.get("confirm_doc", "")
    first_name = request.form.get("new_first", "").strip()
    last_name = request.form.get("new_last", "").strip()
    specialization = request.form.get("new_special", "").strip()
    address = request.form.get("new_address", "").strip()
    phone = request.form.get("new_phone", "").strip()
    payroll = request.form.get("new_pay", "").strip()
    doc_exp = request.form.get("doc_exp", "").strip()
    
    # Working hours
    working_hours = {}
    days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
    for day in days:
        start = request.form.get(f"{day}_start", "")
        end = request.form.get(f"{day}_end", "")
        working_hours[f"{day}_start"] = start
        working_hours[f"{day}_end"] = end
    
    # Email validation
    is_valid, email_result = InputValidator.validate_email(email)
    if not is_valid:
        errors.append(email_result)
    else:
        data["email"] = email_result
    
    # Password validation
    is_valid, password_result = InputValidator.validate_password(password)
    if not is_valid:
        errors.append(password_result)
    else:
        if password != confirm_password:
            errors.append("Passwords must match")
        else:
            data["password"] = password_result
    
    # Name validation
    is_valid, fname_result = InputValidator.validate_name(first_name, "First name")
    if not is_valid:
        errors.append(fname_result)
    else:
        data["first_name"] = fname_result.title()
    
    is_valid, lname_result = InputValidator.validate_name(last_name, "Last name")
    if not is_valid:
        errors.append(lname_result)
    else:
        data["last_name"] = lname_result.title()
    
    # Phone validation
    is_valid, phone_result = InputValidator.validate_phone(phone)
    if not is_valid:
        errors.append(phone_result)
    else:
        data["phone"] = phone_result
    
    # Specialization validation
    is_valid, spec_result = InputValidator.validate_name(specialization, "Specialization")
    if not is_valid:
        errors.append(spec_result)
    else:
        data["specialization"] = spec_result.title()
    
    # Address validation
    is_valid, addr_result = InputValidator.validate_text_area(address, "Address", max_length=200)
    if not is_valid:
        errors.append(addr_result)
    else:
        data["address"] = addr_result
    
    # Payroll validation
    try:
        payroll_value = float(payroll) if payroll else 0
        if payroll_value < 0:
            errors.append("Payroll must be a positive number")
        else:
            data["payroll"] = payroll_value
    except ValueError:
        errors.append("Please provide a valid payroll amount")
    
    # Experience validation
    try:
        exp_value = int(doc_exp) if doc_exp else 0
        if exp_value < 0 or exp_value > 50:
            errors.append("Years of experience must be between 0 and 50")
        else:
            data["experience"] = exp_value
    except ValueError:
        errors.append("Please provide a valid number for years of experience")
    
    # Working hours validation (basic)
    data["working_hours"] = working_hours
    
    return errors, data if not errors else None


def validate_patient_form():
    """Validate patient creation form with comprehensive security checks"""
    from flask import request
    
    errors = []
    data = {}
    
    # Sanitize and validate basic fields
    first_name = request.form.get("newFirstName", "").strip()
    last_name = request.form.get("newLastName", "").strip()
    dob = request.form.get("newDOB", "").strip()
    gender = request.form.get("newGender", "").strip()
    address = request.form.get("newAddress", "").strip()
    email = request.form.get("newEmail", "").strip().lower()
    phone = request.form.get("newPhone", "").strip()
    insurance = request.form.get("newInsurance", "").strip()
    
    # Name validation
    is_valid, fname_result = InputValidator.validate_name(first_name, "First name")
    if not is_valid:
        errors.append(fname_result)
    else:
        data["first_name"] = fname_result.title()
    
    is_valid, lname_result = InputValidator.validate_name(last_name, "Last name")
    if not is_valid:
        errors.append(lname_result)
    else:
        data["last_name"] = lname_result.title()
    
    # Date of birth validation
    is_valid, dob_result = InputValidator.validate_date(dob, allow_future=False)
    if not is_valid:
        errors.append(dob_result)
    else:
        data["date_of_birth"] = dob_result
    
    # Gender validation
    is_valid, gender_result = InputValidator.validate_select_field(
        gender, "Gender", allowed_values=["male", "female", "other"]
    )
    if not is_valid:
        errors.append(gender_result)
    else:
        data["gender"] = gender_result
    
    # Email validation
    is_valid, email_result = InputValidator.validate_email(email)
    if not is_valid:
        errors.append(email_result)
    else:
        data["email"] = email_result
    
    # Phone validation
    is_valid, phone_result = InputValidator.validate_phone(phone)
    if not is_valid:
        errors.append(phone_result)
    else:
        data["phone"] = phone_result
    
    # Address validation
    is_valid, addr_result = InputValidator.validate_text_area(address, "Address", max_length=200)
    if not is_valid:
        errors.append(addr_result)
    else:
        data["address"] = addr_result
    
    # Insurance validation (optional)
    if insurance:
        is_valid, ins_result = InputValidator.validate_text_area(insurance, "Insurance", max_length=100)
        if not is_valid:
            errors.append(ins_result)
        else:
            data["insurance"] = ins_result.title()
    else:
        data["insurance"] = None
    
    return errors, data if not errors else None


def validate_password_reset_form():
    """Validate password reset form"""
    from flask import request
    
    errors = []
    data = {}
    
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm", "")
    
    # Password validation
    is_valid, password_result = InputValidator.validate_password(new_password)
    if not is_valid:
        errors.append(password_result)
    else:
        if new_password != confirm_password:
            errors.append("Passwords must match")
        else:
            data["password"] = password_result
    
    return errors, data if not errors else None


def validate_appointment_form():
    """Validate appointment creation form"""
    from flask import request
    
    errors = []
    data = {}
    
    patient_id = request.form.get("app_ID", "").strip()
    app_date = request.form.get("app_date", "").strip()
    doctor_id = request.form.get("app_doctor", "").strip()
    start_time = request.form.get("app_start", "").strip()
    reason = request.form.get("app_reason", "").strip()
    notes = request.form.get("app_notes", "").strip()
    
    # Patient ID validation
    try:
        patient_id_int = int(patient_id) if patient_id else None
        if not patient_id_int or patient_id_int <= 0:
            errors.append("Please provide a valid patient ID")
        else:
            data["patient_id"] = patient_id_int
    except ValueError:
        errors.append("Patient ID must be a number")
    
    # Doctor ID validation
    try:
        doctor_id_int = int(doctor_id) if doctor_id else None
        if not doctor_id_int or doctor_id_int <= 0:
            errors.append("Please select a doctor")
        else:
            data["doctor_id"] = doctor_id_int
    except ValueError:
        errors.append("Please select a valid doctor")
    
    # Date validation
    is_valid, date_result = InputValidator.validate_date(app_date, allow_past=False)
    if not is_valid:
        errors.append(date_result)
    else:
        data["appointment_date"] = date_result
    
    # Time validation (basic)
    if not start_time:
        errors.append("Please provide an appointment time")
    else:
        # Simple time format validation
        import re
        if not re.match(r'^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$', start_time):
            errors.append("Please provide a valid time (HH:MM format)")
        else:
            data["start_time"] = start_time
    
    # Reason validation
    is_valid, reason_result = InputValidator.validate_text_area(reason, "Reason", max_length=200, min_length=5)
    if not is_valid:
        errors.append(reason_result)
    else:
        data["reason"] = reason_result
    
    # Notes validation (optional)
    if notes:
        is_valid, notes_result = InputValidator.validate_text_area(notes, "Notes", max_length=500)
        if not is_valid:
            errors.append(notes_result)
        else:
            data["notes"] = notes_result
    else:
        data["notes"] = ""
    
    return errors, data if not errors else None


def validate_prescription_form():
    """Validate prescription form"""
    from flask import request
    
    errors = []
    data = {}
    
    medication = request.form.get("medication", "").strip()
    dosage = request.form.get("dosage", "").strip()
    instructions = request.form.get("instructions", "").strip()
    
    # Medication validation
    is_valid, med_result = InputValidator.validate_text_area(medication, "Medication", max_length=100, min_length=2)
    if not is_valid:
        errors.append(med_result)
    else:
        data["medication"] = med_result
    
    # Dosage validation
    is_valid, dose_result = InputValidator.validate_text_area(dosage, "Dosage", max_length=50, min_length=2)
    if not is_valid:
        errors.append(dose_result)
    else:
        data["dosage"] = dose_result
    
    # Instructions validation
    is_valid, inst_result = InputValidator.validate_text_area(instructions, "Instructions", max_length=500, min_length=5)
    if not is_valid:
        errors.append(inst_result)
    else:
        data["instructions"] = inst_result
    
    return errors, data if not errors else None


def validate_medical_record_form():
    """Validate medical record form"""
    from flask import request
    
    errors = []
    data = {}
    
    diagnosis = request.form.get("diagnosis", "").strip()
    test_name = request.form.get("test_name", "").strip()
    test_result = request.form.get("result", "").strip()
    reference_range = request.form.get("reference", "").strip()
    test_date = request.form.get("test_date", "").strip()
    instructions = request.form.get("instructions", "").strip()
    
    # Diagnosis validation
    is_valid, diag_result = InputValidator.validate_text_area(diagnosis, "Diagnosis", max_length=200, min_length=3)
    if not is_valid:
        errors.append(diag_result)
    else:
        data["diagnosis"] = diag_result
    
    # Test name validation (optional)
    if test_name:
        is_valid, test_result = InputValidator.validate_text_area(test_name, "Test name", max_length=100)
        if not is_valid:
            errors.append(test_result)
        else:
            data["test_name"] = test_result
    else:
        data["test_name"] = ""
    
    # Test result validation (optional)
    if test_result:
        is_valid, result_validated = InputValidator.validate_text_area(test_result, "Test result", max_length=200)
        if not is_valid:
            errors.append(result_validated)
        else:
            data["test_result"] = result_validated
    else:
        data["test_result"] = ""
    
    # Reference range validation (optional)
    if reference_range:
        is_valid, ref_result = InputValidator.validate_text_area(reference_range, "Reference range", max_length=100)
        if not is_valid:
            errors.append(ref_result)
        else:
            data["reference_range"] = ref_result
    else:
        data["reference_range"] = ""
    
    # Test date validation (optional)
    if test_date:
        is_valid, date_result = InputValidator.validate_date(test_date, allow_future=False)
        if not is_valid:
            errors.append(date_result)
        else:
            data["test_date"] = date_result
    else:
        data["test_date"] = None
    
    # Instructions validation
    is_valid, inst_result = InputValidator.validate_text_area(instructions, "Instructions", max_length=500, min_length=5)
    if not is_valid:
        errors.append(inst_result)
    else:
        data["instructions"] = inst_result
    
    return errors, data if not errors else None


def validate_file_upload_form():
    """Validate file upload form data"""
    file_date = request.form.get("date", "").strip()
    
    errors = []
    validated_data = {}
    
    # Validate file date
    if not file_date:
        errors.append("File date is required")
    else:
        is_valid, result = InputValidator.validate_date(file_date, allow_future=False)
        if not is_valid:
            errors.append(result)
        else:
            validated_data["file_date"] = result
    
    return errors, validated_data if not errors else None


def validate_expense_form():
    """Validate expense form data (for medical supplies, utilities, equipment, marketing, other expenses)"""
    amount = request.form.get("amount", "").strip()
    description = request.form.get("description", "").strip()
    
    errors = []
    validated_data = {}
    
    # Validate amount
    if not amount:
        errors.append("Amount is required")
    else:
        try:
            amount_float = float(amount)
            if amount_float <= 0:
                errors.append("Amount must be greater than zero")
            elif amount_float > 999999.99:
                errors.append("Amount cannot exceed $999,999.99")
            else:
                validated_data["amount"] = amount_float
        except ValueError:
            errors.append("Amount must be a valid number")
    
    # Validate description
    is_valid, result = InputValidator.validate_text_area(description, "Description", max_length=200, min_length=3)
    if not is_valid:
        errors.append(result)
    else:
        validated_data["description"] = result
    
    return errors, validated_data if not errors else None
