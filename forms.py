"""
MediFlow Forms Module
Comprehensive form validation using Flask-WTF for secure healthcare management
"""

try:
    from flask_wtf import FlaskForm
    from wtforms import (
        StringField, PasswordField, EmailField, SelectField, 
        TextAreaField, DateField, TimeField, IntegerField, 
        FloatField, TelField, SubmitField
    )
    from wtforms.validators import (
        DataRequired, Email, Length, EqualTo, ValidationError, 
        Regexp, NumberRange, Optional
    )
    from email_validator import validate_email as validate_email_format
    WTF_AVAILABLE = True
except ImportError:
    print("Warning: Flask-WTF or dependencies not available. Form validation will be limited.")
    WTF_AVAILABLE = False
    # Create dummy classes to prevent import errors
    class FlaskForm:
        pass
    class StringField:
        pass
    class PasswordField:
        pass
    class EmailField:
        pass

import re
import sqlite3
from datetime import datetime, date


class PasswordValidator:
    """Custom password validator for MediFlow security requirements"""
    
    def __init__(self, min_length=8, max_length=20, message=None):
        self.min_length = min_length
        self.max_length = max_length
        if not message:
            message = f'Password must be between {min_length}-{max_length} characters, include letters, numbers, and special characters (!$@%)'
        self.message = message

    def __call__(self, form, field):
        password = field.data
        if not password:
            return
        
        # Length check
        if len(password) < self.min_length or len(password) > self.max_length:
            raise ValidationError(f'Password must be between {self.min_length}-{self.max_length} characters')
        
        # Check for at least one digit
        if not any(char.isdigit() for char in password):
            raise ValidationError('Password must include at least one number')
        
        # Check for at least one letter
        if not any(char.isalpha() for char in password):
            raise ValidationError('Password must include letters')
        
        # Check for required special characters
        allowed_special_chars = "!$@%"
        if not any(char in allowed_special_chars for char in password):
            raise ValidationError('Password must include at least one of these special characters: !$@%')


class PhoneValidator:
    """Custom phone number validator"""
    
    def __init__(self, message=None):
        if not message:
            message = 'Please provide a valid phone number (10-15 digits)'
        self.message = message

    def __call__(self, form, field):
        if field.data:
            # Remove all non-digit characters
            digits_only = re.sub(r'[^\d]', '', field.data)
            
            # Check if it's between 10-15 digits
            if not (10 <= len(digits_only) <= 15):
                raise ValidationError(self.message)


class UniqueEmailValidator:
    """Custom validator to check if email already exists in database"""
    
    def __init__(self, message=None):
        if not message:
            message = 'A user with this email address already exists'
        self.message = message

    def __call__(self, form, field):
        if field.data:
            try:
                db = sqlite3.connect('mediflow.db')
                cursor = db.cursor()
                  # Check in all user tables
                tables = ['users', 'doctors', 'admins']
                for table in tables:
                    cursor.execute(f"SELECT email FROM {table} WHERE email = ?", (field.data.lower(),))
                    if cursor.fetchone():
                        raise ValidationError(self.message)
                        
                db.close()
            except sqlite3.Error:
                # If database error, let it pass (will be caught elsewhere)
                pass


class LoginForm(FlaskForm):
    """Secure login form with CSRF protection"""
    email = EmailField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please provide a valid email address')
        ],
        render_kw={"placeholder": "Email", "class": "input-field", "autocomplete": "off"}
    )
    
    password = PasswordField(
        'Password',
        validators=[DataRequired(message='Password is required')],
        render_kw={"placeholder": "Password", "class": "input-field", "autocomplete": "off"}
    )
    
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    """Secure user registration form"""
    email = EmailField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please provide a valid email address'),
            UniqueEmailValidator()
        ],
        render_kw={"placeholder": "Email", "class": "input-field", "autocomplete": "off"}
    )
    
    first_name = StringField(
        'First Name',
        validators=[
            DataRequired(message='First name is required'),
            Length(min=1, max=10, message='First name cannot exceed 10 characters'),
            Regexp(r'^[a-zA-Z]+$', message='First name can only include letters')
        ],
        render_kw={"placeholder": "First Name", "class": "input-field", "autocomplete": "off"}
    )
    
    last_name = StringField(
        'Last Name',
        validators=[
            DataRequired(message='Last name is required'),
            Length(min=1, max=10, message='Last name cannot exceed 10 characters'),
            Regexp(r'^[a-zA-Z]+$', message='Last name can only include letters')
        ],
        render_kw={"placeholder": "Last Name", "class": "input-field", "autocomplete": "off"}
    )
    
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required'),
            PasswordValidator()
        ],
        render_kw={"placeholder": "Password", "class": "input-field", "autocomplete": "off"}
    )
    
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message='Please confirm your password'),
            EqualTo('password', message='Passwords must match')
        ],
        render_kw={"placeholder": "Confirm Password", "class": "input-field", "autocomplete": "off"}
    )
    
    submit = SubmitField('Register')


class AddUserForm(FlaskForm):
    """Secure form for adding new users"""
    email = EmailField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please provide a valid email address'),
            UniqueEmailValidator()
        ],
        render_kw={"placeholder": "Email", "class": "form-control", "autocomplete": "off"}
    )
    
    phone = TelField(
        'Phone Number',
        validators=[
            DataRequired(message='Phone number is required'),
            PhoneValidator()
        ],
        render_kw={"placeholder": "Phone Number", "class": "form-control", "autocomplete": "off"}
    )
    
    first_name = StringField(
        'First Name',
        validators=[
            DataRequired(message='First name is required'),
            Length(min=1, max=10, message='First name cannot exceed 10 characters'),
            Regexp(r'^[a-zA-Z]+$', message='First name can only include letters')
        ],
        render_kw={"placeholder": "First Name", "class": "form-control", "autocomplete": "off"}
    )
    
    last_name = StringField(
        'Last Name',
        validators=[
            DataRequired(message='Last name is required'),
            Length(min=1, max=10, message='Last name cannot exceed 10 characters'),
            Regexp(r'^[a-zA-Z]+$', message='Last name can only include letters')
        ],
        render_kw={"placeholder": "Last Name", "class": "form-control", "autocomplete": "off"}
    )
    
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required'),
            PasswordValidator()
        ],
        render_kw={"placeholder": "Password", "class": "form-control", "autocomplete": "off"}
    )
    
    confirmation = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message='Please confirm the password'),
            EqualTo('password', message='Passwords must match')
        ],
        render_kw={"placeholder": "Confirm Password", "class": "form-control", "autocomplete": "off"}
    )
    
    position = SelectField(
        'Position',
        choices=[
            ('', 'Select Position'),
            ('Receptionist', 'Receptionist'),
            ('Nurse', 'Nurse'),
            ('Medical Assistant', 'Medical Assistant')
        ],
        validators=[DataRequired(message='Please select a position')],
        render_kw={"class": "form-control"}
    )
    
    payroll = FloatField(
        'Payroll',
        validators=[
            Optional(),
            NumberRange(min=0, message='Payroll must be a positive number')
        ],
        render_kw={"placeholder": "Payroll", "class": "form-control", "autocomplete": "off"}
    )
    
    submit = SubmitField('Add New User', render_kw={"class": "submit-button"})


class AddDoctorForm(FlaskForm):
    """Secure form for adding new doctors"""
    new_email = EmailField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please provide a valid email address'),
            UniqueEmailValidator()
        ],
        render_kw={"placeholder": "Email", "class": "form-control", "autocomplete": "off"}
    )
    
    new_first = StringField(
        'First Name',
        validators=[
            DataRequired(message='First name is required'),
            Length(min=1, max=10, message='First name cannot exceed 10 characters'),
            Regexp(r'^[a-zA-Z]+$', message='First name can only include letters')
        ],
        render_kw={"placeholder": "First Name", "class": "form-control", "autocomplete": "off"}
    )
    
    new_last = StringField(
        'Last Name',
        validators=[
            DataRequired(message='Last name is required'),
            Length(min=1, max=10, message='Last name cannot exceed 10 characters'),
            Regexp(r'^[a-zA-Z]+$', message='Last name can only include letters')
        ],
        render_kw={"placeholder": "Last Name", "class": "form-control", "autocomplete": "off"}
    )
    
    doc_password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required'),
            PasswordValidator()
        ],
        render_kw={"placeholder": "Password", "class": "form-control", "autocomplete": "off"}
    )
    
    confirm_doc = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message='Please confirm the password'),
            EqualTo('doc_password', message='Passwords must match')
        ],
        render_kw={"placeholder": "Confirm Password", "class": "form-control", "autocomplete": "off"}
    )
    
    doc_phone = TelField(
        'Phone Number',
        validators=[
            DataRequired(message='Phone number is required'),
            PhoneValidator()
        ],
        render_kw={"placeholder": "Phone Number", "class": "form-control", "autocomplete": "off"}
    )
    
    doc_specialization = StringField(
        'Specialization',
        validators=[
            DataRequired(message='Specialization is required'),
            Length(min=2, max=50, message='Specialization must be between 2-50 characters'),
            Regexp(r'^[a-zA-Z\s]+$', message='Specialization can only include letters and spaces')
        ],
        render_kw={"placeholder": "Specialization", "class": "form-control", "autocomplete": "off"}
    )
    
    submit = SubmitField('Add New Doctor', render_kw={"class": "submit-button"})


class NewPatientForm(FlaskForm):
    """Secure form for adding new patients"""
    newFirstName = StringField(
        'First Name',
        validators=[
            DataRequired(message='First name is required'),
            Length(min=1, max=50, message='First name cannot exceed 50 characters'),
            Regexp(r'^[a-zA-Z\s]+$', message='First name can only include letters and spaces')
        ],
        render_kw={"placeholder": "First Name", "class": "form-control", "autocomplete": "off"}
    )
    
    newLastName = StringField(
        'Last Name',
        validators=[
            DataRequired(message='Last name is required'),
            Length(min=1, max=50, message='Last name cannot exceed 50 characters'),
            Regexp(r'^[a-zA-Z\s]+$', message='Last name can only include letters and spaces')
        ],
        render_kw={"placeholder": "Last Name", "class": "form-control", "autocomplete": "off"}
    )
    
    newPhoneNumber = TelField(
        'Phone Number',
        validators=[
            DataRequired(message='Phone number is required'),
            PhoneValidator()
        ],
        render_kw={"placeholder": "Phone Number", "class": "form-control", "autocomplete": "off"}
    )
    
    newEmail = EmailField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please provide a valid email address')
        ],
        render_kw={"placeholder": "Email", "class": "form-control", "autocomplete": "off"}
    )
    
    newDateOfBirth = DateField(
        'Date of Birth',
        validators=[DataRequired(message='Date of birth is required')],
        render_kw={"class": "form-control"}
    )
    
    newGender = SelectField(
        'Gender',
        choices=[
            ('', 'Select Gender'),
            ('Male', 'Male'),
            ('Female', 'Female'),
            ('Other', 'Other')
        ],
        validators=[DataRequired(message='Please select a gender')],
        render_kw={"class": "form-control"}
    )
    
    newAddress = TextAreaField(
        'Address',
        validators=[
            DataRequired(message='Address is required'),
            Length(min=10, max=200, message='Address must be between 10-200 characters')
        ],
        render_kw={"placeholder": "Address", "class": "form-control", "rows": "3"}
    )
    
    newEmergencyContact = TelField(
        'Emergency Contact',
        validators=[
            DataRequired(message='Emergency contact is required'),
            PhoneValidator()
        ],
        render_kw={"placeholder": "Emergency Contact", "class": "form-control", "autocomplete": "off"}
    )
    
    submit = SubmitField('Create New Patient', render_kw={"class": "submit-button"})


class PasswordResetForm(FlaskForm):
    """Secure password reset form"""
    email = EmailField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please provide a valid email address')
        ],
        render_kw={"placeholder": "Email", "class": "input-field", "autocomplete": "off"}
    )
    
    submit = SubmitField('Send Reset Link')


class NewPasswordForm(FlaskForm):
    """Secure new password form for reset"""
    new_password = PasswordField(
        'New Password',
        validators=[
            DataRequired(message='New password is required'),
            PasswordValidator()
        ],
        render_kw={"placeholder": "New Password", "class": "input-field", "autocomplete": "off"}
    )
    
    confirm = PasswordField(
        'Confirm New Password',
        validators=[
            DataRequired(message='Please confirm your new password'),
            EqualTo('new_password', message='Passwords must match')
        ],
        render_kw={"placeholder": "Confirm New Password", "class": "input-field", "autocomplete": "off"}
    )
    
    submit = SubmitField('Reset Password')


class AppointmentForm(FlaskForm):
    """Secure appointment booking form"""
    patient_id = SelectField(
        'Patient',
        coerce=int,
        validators=[DataRequired(message='Please select a patient')],
        render_kw={"class": "form-control"}
    )
    
    doctor_id = SelectField(
        'Doctor',
        coerce=int,
        validators=[DataRequired(message='Please select a doctor')],
        render_kw={"class": "form-control"}
    )
    
    appointment_date = DateField(
        'Appointment Date',
        validators=[DataRequired(message='Please select an appointment date')],
        render_kw={"class": "form-control"}
    )
    
    appointment_time = TimeField(
        'Appointment Time',
        validators=[DataRequired(message='Please select an appointment time')],
        render_kw={"class": "form-control"}
    )
    
    reason = TextAreaField(
        'Reason for Visit',
        validators=[
            DataRequired(message='Please provide a reason for the visit'),
            Length(min=5, max=500, message='Reason must be between 5-500 characters')
        ],
        render_kw={"placeholder": "Reason for visit", "class": "form-control", "rows": "3"}
    )
    
    submit = SubmitField('Book Appointment', render_kw={"class": "submit-button"})

    def validate_appointment_date(self, field):
        """Custom validation to ensure appointment date is not in the past"""
        if field.data and field.data < date.today():
            raise ValidationError('Appointment date cannot be in the past')


# CSRF Error Handler
def csrf_error_handler():
    """Handle CSRF token errors"""
    return render_template('csrf_error.html'), 400
