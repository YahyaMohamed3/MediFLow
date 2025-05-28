#!/usr/bin/env python3
"""
Database Initialization and Management Script for MediFlow
This script ensures proper database setup and prevents unintended database creation.
"""

import sqlite3
import os
import sys
import shutil
from datetime import datetime


def create_database_schema(db_path):
    """Create the complete database schema for MediFlow - matches actual schema exactly"""
    
    schema_sql = """
    -- Users and Authentication Tables
    CREATE TABLE IF NOT EXISTS users (
        users_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        hash TEXT NOT NULL,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        usertype TEXT NOT NULL,
        payroll INTEGER,
        reset_token TEXT,
        admin_id INTEGER, 
        specialization TEXT, 
        phone_number TEXT,
        FOREIGN KEY (admin_id) REFERENCES admins(id)
    );

    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        hash TEXT NOT NULL,
        reset_token TEXT
    );

    -- Patient Management
    CREATE TABLE IF NOT EXISTS patients (
        patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        date_of_birth DATE NOT NULL,
        gender TEXT NOT NULL,
        address TEXT NOT NULL,
        phone TEXT,
        email TEXT NOT NULL,
        insurance TEXT,
        created_by INTEGER NOT NULL,
        FOREIGN KEY (created_by) REFERENCES users(users_id)
    );

    -- Doctor Management
    CREATE TABLE IF NOT EXISTS doctors (
        doctor_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
        admin_id INTEGER NOT NULL,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT,
        address TEXT NOT NULL,
        specialization TEXT,
        payroll INTEGER,
        years_of_experience INTEGER NOT NULL,
        hash TEXT NOT NULL,
        usertype TEXT NOT NULL,
        reset_token TEXT,
        FOREIGN KEY (admin_id) REFERENCES admins(id)
    );

    -- Extended Patient Information
    CREATE TABLE IF NOT EXISTS medical_information (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        height_medical TEXT,
        weight_medical TEXT,
        blood_type_medical TEXT,
        created_by_medical INTEGER NOT NULL,
        FOREIGN KEY(patient_id) REFERENCES patients(patient_id),
        FOREIGN KEY(created_by_medical) REFERENCES users(users_id)
    );

    CREATE TABLE IF NOT EXISTS emergency_contact(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id_emergency INTEGER,
        name_emergency TEXT,
        relationship_emergency TEXT,
        phone_number_emergency TEXT,
        created_by_emergency INTEGER,
        FOREIGN KEY(patient_id_emergency) REFERENCES patients(patient_id),
        FOREIGN KEY(created_by_emergency) REFERENCES users(users_id)
    );

    CREATE TABLE IF NOT EXISTS insurance_information (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id_insurance INTEGER,
        insurance_company TEXT,
        policy_number TEXT,
        created_by_insurance INTEGER, 
        group_number TEXT,
        FOREIGN KEY(patient_id_insurance) REFERENCES patients(patient_id),
        FOREIGN KEY(created_by_insurance) REFERENCES users(users_id)
    );

    -- Communication System
    CREATE TABLE IF NOT EXISTS messages (
        message_id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        sender_user_type TEXT NOT NULL,
        receiver_id INTEGER NOT NULL,
        receiver_user_type TEXT NOT NULL,
        message TEXT NOT NULL,
        iv BLOB NOT NULL,
        encryption_key BLOB NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users(users_id) ON DELETE CASCADE,
        FOREIGN KEY (receiver_id) REFERENCES users(users_id) ON DELETE CASCADE,
        FOREIGN KEY (sender_id) REFERENCES admins(id) ON DELETE CASCADE,
        FOREIGN KEY (receiver_id) REFERENCES admins(id) ON DELETE CASCADE,
        FOREIGN KEY (sender_id) REFERENCES doctors(doctor_id) ON DELETE CASCADE,
        FOREIGN KEY (receiver_id) REFERENCES doctors(doctor_id) ON DELETE CASCADE
    );

    -- Doctor Scheduling
    CREATE TABLE IF NOT EXISTS doctor_working_hours (
        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
        doctor_id INTEGER NOT NULL,
        day_of_week TEXT NOT NULL,
        start_working_hours TIME NOT NULL,
        end_working_hours TIME NOT NULL,
        FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id)
    );

    -- File Management
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        date_uploaded TEXT NOT NULL,
        file_date TEXT NOT NULL,
        created_by INTEGER NOT NULL,
        patient_id INTEGER NOT NULL,
        FOREIGN KEY (created_by) REFERENCES users(users_id),
        FOREIGN KEY (patient_id) REFERENCES patients(patient_id)
    );

    -- Financial Management
    CREATE TABLE IF NOT EXISTS billing (
        invoice_id INTEGER PRIMARY KEY AUTOINCREMENT,
        appointment_id INTEGER,
        patient_id INTEGER,
        invoice_date TEXT,
        payment_date TEXT,
        amount REAL,
        payment_method TEXT,
        payment_status TEXT,
        description TEXT,
        insurance_provider TEXT,
        created_by INTEGER,
        FOREIGN KEY (appointment_id) REFERENCES Appointments(AppointmentID),
        FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
        FOREIGN KEY (created_by) REFERENCES users(users_id)
    );

    -- Medical Records and Prescriptions
    CREATE TABLE IF NOT EXISTS prescriptions (
        prescription_id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        doctor_id INTEGER NOT NULL,
        medication TEXT NOT NULL,
        dosage TEXT NOT NULL,
        instructions TEXT NOT NULL,
        date_prescribed DATE NOT NULL,
        FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
        FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id)
    );

    CREATE TABLE IF NOT EXISTS history_prescriptions (
        prescription_id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        doctor_id INTEGER NOT NULL,
        medication TEXT NOT NULL,
        dosage TEXT NOT NULL,
        instructions TEXT NOT NULL,
        date_prescribed DATE NOT NULL,
        FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
        FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id)
    );

    CREATE TABLE IF NOT EXISTS medical_records (
        record_id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        doctor_id INTEGER NOT NULL,
        visit_date DATE NOT NULL,
        diagnosis TEXT,
        test_name TEXT,
        test_result TEXT,
        reference_range TEXT,
        test_date DATE,
        follow_up_instructions TEXT,
        FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
        FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id)
    );

    -- Expense Management
    CREATE TABLE IF NOT EXISTS medical_supplies(
        med_id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        amount TEXT,
        description TEXT, 
        date DATE,
        FOREIGN KEY (admin_id) REFERENCES admins(id)
    );

    CREATE TABLE IF NOT EXISTS utilities (
        utility_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
        admin_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        description TEXT NOT NULL, 
        date DATE,
        FOREIGN KEY (admin_id) REFERENCES admins(id)
    );

    CREATE TABLE IF NOT EXISTS equipments (
        equipment_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
        admin_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        description TEXT, 
        date DATE,
        FOREIGN KEY (admin_id) REFERENCES admins(id)
    );

    CREATE TABLE IF NOT EXISTS marketing(
        marketing_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
        admin_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        description TEXT, 
        date DATE,
        FOREIGN KEY (admin_id) REFERENCES admins(id)
    );

    CREATE TABLE IF NOT EXISTS other_expenses(
        other_expenses_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
        admin_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        description TEXT, 
        date DATE,
        FOREIGN KEY (admin_id) REFERENCES admins(id)
    );

    -- Appointments
    CREATE TABLE IF NOT EXISTS Appointments (
        AppointmentID INTEGER PRIMARY KEY AUTOINCREMENT,
        PatientID INTEGER NOT NULL,
        AppointmentDate DATETIME NOT NULL,
        StartTime DATETIME NOT NULL,
        DoctorID INTEGER NOT NULL,
        Reason TEXT NOT NULL,
        Notes TEXT NOT NULL,
        created_by INTEGER NOT NULL,
        confirmed INTEGER DEFAULT 0,
        FOREIGN KEY (PatientID) REFERENCES patients(patient_id),
        FOREIGN KEY (DoctorID) REFERENCES doctors(doctor_id),
        FOREIGN KEY (created_by) REFERENCES users(users_id)
    );
    """
    
    try:
        conn = sqlite3.connect(db_path)
        conn.executescript(schema_sql)
        conn.commit()
        conn.close()
        print(f"✅ Database schema created successfully: {db_path}")
        return True
    except Exception as e:
        print(f"❌ Error creating database schema: {e}")
        return False


def backup_database(db_path):
    """Create a backup of the existing database"""
    if not os.path.exists(db_path):
        print(f"⚠️ Database does not exist: {db_path}")
        return False
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{db_path}.backup_{timestamp}"
    
    try:
        shutil.copy2(db_path, backup_path)
        print(f"✅ Database backed up to: {backup_path}")
        return True
    except Exception as e:
        print(f"❌ Error backing up database: {e}")
        return False


def verify_database_schema(db_path):
    """Verify that all required tables exist in the database"""
    if not os.path.exists(db_path):
        print(f"❌ Database does not exist: {db_path}")
        return False
    
    required_tables = [
        'users', 'admins', 'patients', 'doctors', 'Appointments',
        'billing', 'prescriptions', 'medical_records', 'messages',
        'medical_supplies', 'utilities', 'equipments', 'marketing',
        'other_expenses', 'doctor_working_hours', 'files',
        'medical_information', 'emergency_contact', 'insurance_information',
        'history_prescriptions'
    ]
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        existing_tables = [table[0] for table in cursor.fetchall()]
        
        missing_tables = set(required_tables) - set(existing_tables)
        if missing_tables:
            print(f"❌ Missing tables in {db_path}: {', '.join(missing_tables)}")
            conn.close()
            return False
        
        conn.close()
        print(f"✅ All required tables exist in {db_path}")
        return True
        
    except Exception as e:
        print(f"❌ Error verifying database schema: {e}")
        return False


def initialize_production_database():
    """Initialize production database with proper schema"""
    # Ensure database directory exists
    os.makedirs('database', exist_ok=True)
    production_db = 'database/mediflow_production.db'
    
    print("🔧 Initializing production database...")
    
    # Backup existing database if it exists
    if os.path.exists(production_db):
        print(f"📦 Backing up existing production database...")
        backup_database(production_db)
    
    # Create database with schema
    if create_database_schema(production_db):
        if verify_database_schema(production_db):
            print("✅ Production database initialized successfully!")
            return True
    
    print("❌ Failed to initialize production database")
    return False


def initialize_development_database():
    """Initialize development database with proper schema"""
    # Ensure database directory exists
    os.makedirs('database', exist_ok=True)
    development_db = 'database/mediflow.db'
    
    print("🔧 Initializing development database...")
    
    # Create database with schema if it doesn't exist
    if not os.path.exists(development_db):
        if create_database_schema(development_db):
            if verify_database_schema(development_db):
                print("✅ Development database initialized successfully!")
                return True
    else:
        print("ℹ️ Development database already exists")
        return verify_database_schema(development_db)
    
    print("❌ Failed to initialize development database")
    return False


def get_database_info(db_path):
    """Get information about a database file"""
    if not os.path.exists(db_path):
        return f"❌ Database does not exist: {db_path}"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [table[0] for table in cursor.fetchall()]
        
        table_count = len(tables)
        file_size = os.path.getsize(db_path)
        file_size_mb = file_size / (1024 * 1024)
        
        conn.close()
        
        return {
            'status': '✅ Available',
            'path': db_path,
            'tables': table_count,
            'size_mb': round(file_size_mb, 2),
            'table_names': ', '.join(tables)
        }
    except Exception as e:
        return f"❌ Error reading database: {e}"


def main():
    """Main function to handle database initialization"""
    print("🏥 MediFlow Database Initialization Script")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'production':
            initialize_production_database()
        elif command == 'development':
            initialize_development_database()
        elif command == 'both':
            initialize_development_database()
            initialize_production_database()
        elif command == 'verify':
            print("🔍 Verifying databases...")
            dev_info = get_database_info('database/mediflow.db')
            prod_info = get_database_info('database/mediflow_production.db')
            
            print(f"\n📊 Development Database:")
            if isinstance(dev_info, dict):
                for key, value in dev_info.items():
                    print(f"   {key}: {value}")
            else:
                print(f"   {dev_info}")
            
            print(f"\n📊 Production Database:")
            if isinstance(prod_info, dict):
                for key, value in prod_info.items():
                    print(f"   {key}: {value}")
            else:
                print(f"   {prod_info}")
                
        elif command == 'help':
            print("""
Usage: python scripts/init_database.py [command]

Commands:
    production  - Initialize production database
    development - Initialize development database  
    both        - Initialize both databases
    verify      - Verify and show database information
    help        - Show this help message

If no command is provided, both databases will be initialized.
            """)
        else:
            print(f"❌ Unknown command: {command}")
            print("Use 'help' for available commands")
    else:
        # Default: initialize both databases
        initialize_development_database()
        initialize_production_database()


if __name__ == "__main__":
    main()
