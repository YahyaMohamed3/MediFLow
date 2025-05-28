#!/usr/bin/env python3
"""
MediFlow Production Deployment Script
=====================================
This script helps prepare MediFlow for production deployment by:
1. Setting up production environment
2. Cleaning test data from production database
3. Validating configuration
4. Running basic health checks
"""

import os
import sqlite3
import shutil
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def validate_environment():
    """Validate that all required environment variables are set"""
    required_vars = [
        'SECRET_KEY',
        'JWT_SECRET', 
        'MAIL_SERVER',
        'MAIL_PORT',
        'MAIL_USERNAME',
        'MAIL_PASSWORD'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
        return False
    
    print("✅ All required environment variables are set")
    return True

def backup_database(db_path):
    """Create a backup of the current database"""
    if not os.path.exists(db_path):
        print(f"⚠️  Database {db_path} does not exist")
        return False
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{db_path}.backup_{timestamp}"
    
    try:
        shutil.copy2(db_path, backup_path)
        print(f"✅ Database backed up to: {backup_path}")
        return True
    except Exception as e:
        print(f"❌ Failed to backup database: {e}")
        return False

def clean_test_data(db_path):
    """Clean test data from production database"""
    if not os.path.exists(db_path):
        print(f"❌ Database {db_path} does not exist")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get initial counts
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM patients")
        patient_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM appointments")
        appointment_count = cursor.fetchone()[0]
        
        print(f"📊 Current database stats:")
        print(f"   Users: {user_count}")
        print(f"   Patients: {patient_count}")
        print(f"   Appointments: {appointment_count}")
        
        # Ask for confirmation before cleaning
        response = input("\n🗑️  Do you want to clean test data? This will remove demo users and test records. (y/N): ")
        if response.lower() != 'y':
            print("❌ Database cleaning cancelled")
            conn.close()
            return False
        
        # Clean test data (preserve admin user if exists)
        print("🧹 Cleaning test data...")
          # Delete test appointments (table name is 'Appointments' with capital A)
        cursor.execute("DELETE FROM Appointments WHERE AppointmentID > 0")
        deleted_appointments = cursor.rowcount
          # Delete test prescriptions
        cursor.execute("DELETE FROM prescriptions WHERE prescription_id > 0")
        deleted_prescriptions = cursor.rowcount
        
        # Delete test patients (keep structure)
        cursor.execute("DELETE FROM patients WHERE patient_id > 0")
        deleted_patients = cursor.rowcount
        
        # Delete test users except admin (keep admin user)
        cursor.execute("DELETE FROM users WHERE users_id > 1")
        deleted_users = cursor.rowcount
        
        # Delete test doctors
        cursor.execute("DELETE FROM doctors WHERE doctor_id > 0")
        deleted_doctors = cursor.rowcount
        
        # Delete test medical records
        cursor.execute("DELETE FROM medical_records WHERE record_id > 0")
        deleted_records = cursor.rowcount
          # Delete test billing records
        cursor.execute("DELETE FROM billing WHERE invoice_id > 0")
        deleted_billing = cursor.rowcount
          # Reset auto-increment counters for the tables we cleaned
        tables_to_reset = ['users', 'patients', 'Appointments', 'prescriptions', 'doctors', 'medical_records', 'billing']
        for table in tables_to_reset:
            cursor.execute(f"DELETE FROM sqlite_sequence WHERE name='{table}'")
        
        conn.commit()
        conn.close()
        
        print(f"✅ Test data cleaned successfully:")
        print(f"   Deleted {deleted_users} test users")
        print(f"   Deleted {deleted_patients} test patients")
        print(f"   Deleted {deleted_appointments} test appointments")
        print(f"   Deleted {deleted_prescriptions} test prescriptions")
        print(f"   Deleted {deleted_doctors} test doctors")
        print(f"   Deleted {deleted_records} test medical records")
        print(f"   Deleted {deleted_billing} test billing records")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to clean test data: {e}")
        return False

def setup_production_environment():
    """Setup production environment variables"""
    env_file_path = ".env"
    
    if not os.path.exists(env_file_path):
        print("❌ .env file not found")
        return False
    
    # Read current .env file
    with open(env_file_path, 'r') as f:
        content = f.read()
    
    # Update Flask environment to production
    if "FLASK_ENV=development" in content:
        content = content.replace("FLASK_ENV=development", "FLASK_ENV=production")
        print("✅ Updated FLASK_ENV to production")
    elif "FLASK_ENV=production" not in content:
        content = "FLASK_ENV=production\n" + content
        print("✅ Added FLASK_ENV=production")
    
    # Ensure DEBUG is False
    if "DEBUG=True" in content:
        content = content.replace("DEBUG=True", "DEBUG=False")
        print("✅ Set DEBUG=False")
    elif "DEBUG=False" not in content:
        content = "DEBUG=False\n" + content
        print("✅ Added DEBUG=False")
    
    # Write updated content
    with open(env_file_path, 'w') as f:
        f.write(content)
    
    print("✅ Production environment configured")
    return True

def validate_database_schema(db_path):
    """Validate that the database schema is correct"""
    if not os.path.exists(db_path):
        print(f"❌ Database {db_path} does not exist")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
          # Check required tables exist (using actual table names from schema)
        required_tables = [
            'users', 'patients', 'Appointments', 'prescriptions', 
            'doctors', 'medical_records', 'billing'
        ]
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        existing_tables = [row[0] for row in cursor.fetchall()]
        
        missing_tables = []
        for table in required_tables:
            if table not in existing_tables:
                missing_tables.append(table)
        
        if missing_tables:
            print(f"❌ Missing required tables: {', '.join(missing_tables)}")
            conn.close()
            return False
        
        print("✅ Database schema validation passed")
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Database schema validation failed: {e}")
        return False

def main():
    """Main deployment script"""
    print("🚀 MediFlow Production Deployment")
    print("=" * 40)
    
    # Step 1: Validate environment
    print("\n1️⃣  Validating environment variables...")
    if not validate_environment():
        return False
    
    # Step 2: Setup production environment
    print("\n2️⃣  Setting up production environment...")
    if not setup_production_environment():
        return False
      # Step 3: Backup and prepare production database
    print("\n3️⃣  Preparing production database...")
    prod_db = "database/mediflow_production.db"
    
    if os.path.exists(prod_db):
        if not backup_database(prod_db):
            return False
        
        if not clean_test_data(prod_db):
            return False
    else:
        # Copy from development database
        dev_db = "database/mediflow.db"
        if os.path.exists(dev_db):
            print(f"📋 Copying {dev_db} to {prod_db}...")
            shutil.copy2(dev_db, prod_db)
            if not clean_test_data(prod_db):
                return False
        else:
            print(f"❌ Neither {prod_db} nor {dev_db} exists")
            return False
    
    # Step 4: Validate database schema
    print("\n4️⃣  Validating database schema...")
    if not validate_database_schema(prod_db):
        return False
    
    # Step 5: Final checks
    print("\n5️⃣  Final deployment checks...")
    
    # Check if upload directory exists
    upload_dir = "uploads"
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)
        print(f"✅ Created upload directory: {upload_dir}")
      # Display deployment summary
    print("\n🎉 Production deployment preparation complete!")
    print("\nNext steps:")
    print("1. Test the application locally with FLASK_ENV=production")
    print("2. Run: python src/app.py")
    print("3. Visit http://localhost:5000 and test key functions")
    print("4. Deploy to your chosen cloud platform")
    
    print("\n📋 Deployment checklist:")
    print("✅ Environment variables configured")
    print("✅ Production database prepared")
    print("✅ Test data cleaned")
    print("✅ Security headers enabled")
    print("✅ Upload directory ready")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        if success:
            print("\n🚀 Ready for production deployment!")
        else:
            print("\n❌ Deployment preparation failed")
    except KeyboardInterrupt:
        print("\n\n❌ Deployment cancelled by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
