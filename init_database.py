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
    """Create the complete database schema for MediFlow"""
    
    schema_sql = """
    -- (your full SQL schema as you provided)
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
    """Create a backup of the database"""
    if not os.path.exists(db_path):
        print(f"⚠️ Database does not exist: {db_path}")
        return None
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{db_path}.backup_{timestamp}"
    
    try:
        shutil.copy2(db_path, backup_path)
        print(f"✅ Database backed up to: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"❌ Error backing up database: {e}")
        return None


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
            print(f"❌ Missing tables: {missing_tables}")
            conn.close()
            return False
        
        print(f"✅ All required tables exist in {db_path}")
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Error verifying database schema: {e}")
        return False


def initialize_production_database():
    """Initialize production database with proper schema"""
    production_db = 'database/mediflow_production.db'
    
    print("🔧 Initializing production database...")
    
    if os.path.exists(production_db):
        print(f"📦 Backing up existing production database...")
        backup_database(production_db)
    
    if create_database_schema(production_db):
        if verify_database_schema(production_db):
            print("✅ Production database initialized successfully!")
            return True
    
    print("❌ Failed to initialize production database")
    return False


def initialize_development_database():
    """Initialize development database with proper schema"""
    development_db = 'database/mediflow.db'
    
    print("🔧 Initializing development database...")
    
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
    """Get information about a database"""
    if not os.path.exists(db_path):
        return f"❌ Database does not exist: {db_path}"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table';")
        table_count = cursor.fetchone()[0]
        
        file_size = os.path.getsize(db_path)
        size_mb = file_size / (1024 * 1024)
        
        conn.close()
        
        return {
            'path': db_path,
            'size_mb': round(size_mb, 2),
            'tables': table_count,
            'exists': True
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
            print(f"   {dev_info}")
            
            print(f"\n📊 Production Database:")
            print(f"   {prod_info}")
            
        elif command == 'help':
            print("""
Usage: python init_database.py [command]

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
        initialize_development_database()
        initialize_production_database()


if __name__ == "__main__":
    main()
