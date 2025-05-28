#!/usr/bin/env python3
"""
Production Configuration Test
============================
This script tests the production configuration of MediFlow to ensure:
1. Security headers are applied
2. Database connection works
3. Environment is correctly set to production
"""

import requests
import os
from dotenv import load_dotenv

load_dotenv()

def test_security_headers():
    """Test that security headers are applied in production mode"""
    try:
        response = requests.get('http://localhost:5001', timeout=10)
        headers = response.headers
        
        print("🔒 Testing Security Headers...")
        
        # Check for security headers
        security_checks = {
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block',
            'Content-Security-Policy': 'default-src',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        
        passed = 0
        total = len(security_checks)
        
        for header, expected_value in security_checks.items():
            if header in headers:
                if expected_value in headers[header]:
                    print(f"   ✅ {header}: {headers[header]}")
                    passed += 1
                else:
                    print(f"   ⚠️  {header}: {headers[header]} (expected to contain '{expected_value}')")
            else:
                print(f"   ❌ {header}: Missing")
        
        # Check cache control
        if 'Cache-Control' in headers:
            print(f"   ✅ Cache-Control: {headers['Cache-Control']}")
            passed += 1
        else:
            print("   ❌ Cache-Control: Missing")
            
        total += 1
        
        print(f"\n📊 Security Headers: {passed}/{total} passed")
        return passed == total
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to connect to application: {e}")
        return False

def test_environment_config():
    """Test environment configuration"""
    print("\n🔧 Testing Environment Configuration...")
    
    flask_env = os.getenv('FLASK_ENV')
    debug = os.getenv('DEBUG')
    
    if flask_env == 'production':
        print("   ✅ FLASK_ENV: production")
    else:
        print(f"   ❌ FLASK_ENV: {flask_env} (expected: production)")
        return False
    
    if debug and debug.lower() == 'false':
        print("   ✅ DEBUG: False")
    else:
        print(f"   ❌ DEBUG: {debug} (expected: False)")
        return False
    
    return True

def test_database_access():
    """Test database access"""
    print("\n📊 Testing Database Access...")
    
    import sqlite3
    
    try:
        # Test production database
        conn = sqlite3.connect('mediflow_production.db')
        cursor = conn.cursor()
        
        # Test basic query
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM patients")
        patient_count = cursor.fetchone()[0]
        
        print(f"   ✅ Database connection successful")
        print(f"   📈 Users: {user_count}")
        print(f"   📈 Patients: {patient_count}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"   ❌ Database error: {e}")
        return False

def main():
    """Run all production tests"""
    print("🚀 MediFlow Production Configuration Test")
    print("=" * 45)
    
    tests = [
        ("Environment Configuration", test_environment_config),
        ("Database Access", test_database_access),
        ("Security Headers", test_security_headers)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")
    
    print("\n" + "=" * 45)
    print(f"📋 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All production tests passed! MediFlow is ready for deployment.")
        return True
    else:
        print("⚠️  Some tests failed. Please review the issues above.")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
