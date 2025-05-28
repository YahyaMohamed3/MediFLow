#!/usr/bin/env python3
"""
MediFlow Health Check Script
===========================
This script performs basic health checks on the MediFlow application
to ensure it's ready for production deployment.
"""

import os
import sqlite3
import requests
import time
from dotenv import load_dotenv

load_dotenv()

def check_database_connection():
    """Check if database is accessible and has required tables"""
    try:
        db_path = 'database/mediflow_production.db' if os.getenv('FLASK_ENV') == 'production' else 'database/mediflow.db'
        
        if not os.path.exists(db_path):
            return False, f"Database file {db_path} not found"
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
          # Check if main tables exist (using actual table names from schema)
        required_tables = ['users', 'patients', 'Appointments', 'prescriptions']
        for table in required_tables:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}';")
            if not cursor.fetchone():
                conn.close()
                return False, f"Required table '{table}' not found"
        
        conn.close()
        return True, "Database connection successful"
        
    except Exception as e:
        return False, f"Database error: {str(e)}"

def check_environment_variables():
    """Check if all required environment variables are set"""
    required_vars = [
        'SECRET_KEY',
        'MAIL_SERVER',
        'MAIL_USERNAME',
        'MAIL_PASSWORD'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        return False, f"Missing environment variables: {', '.join(missing_vars)}"
    
    return True, "All environment variables configured"

def check_upload_directory():
    """Check if upload directory exists and is writable"""
    try:
        upload_dir = 'uploads'
        
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        
        # Test write permissions
        test_file = os.path.join(upload_dir, 'test_write.tmp')
        with open(test_file, 'w') as f:
            f.write('test')
        
        os.remove(test_file)
        return True, "Upload directory is accessible and writable"
        
    except Exception as e:
        return False, f"Upload directory error: {str(e)}"

def check_application_startup():
    """Check if application can start without errors"""
    try:
        # Import the main app to check for import errors
        import app
        return True, "Application imports successful"
    except Exception as e:
        return False, f"Application startup error: {str(e)}"

def run_health_checks():
    """Run all health checks"""
    print("🏥 MediFlow Health Check")
    print("=" * 30)
    
    checks = [
        ("Environment Variables", check_environment_variables),
        ("Database Connection", check_database_connection),
        ("Upload Directory", check_upload_directory),
        ("Application Startup", check_application_startup)
    ]
    
    all_passed = True
    
    for check_name, check_func in checks:
        print(f"\n🔍 {check_name}...")
        
        try:
            passed, message = check_func()
            if passed:
                print(f"   ✅ {message}")
            else:
                print(f"   ❌ {message}")
                all_passed = False
        except Exception as e:
            print(f"   ❌ Check failed: {str(e)}")
            all_passed = False
    
    print("\n" + "=" * 30)
    if all_passed:
        print("🎉 All health checks passed! Application is ready.")
        
        # Display environment info
        env = os.getenv('FLASK_ENV', 'development')
        debug = os.getenv('DEBUG', 'True')
        port = os.getenv('PORT', '5000')
        
        print(f"\n📊 Environment: {env}")
        print(f"🔧 Debug mode: {debug}")
        print(f"🌐 Port: {port}")
        
        if env == 'production':
            print("🔒 Security headers: ENABLED")
            print("📊 Production database: mediflow_production.db")
        else:
            print("⚠️  Development mode - remember to set FLASK_ENV=production for deployment")
    else:
        print("❌ Some health checks failed. Please fix the issues before deployment.")
    
    return all_passed

if __name__ == "__main__":
    success = run_health_checks()
    exit(0 if success else 1)
