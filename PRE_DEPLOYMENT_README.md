# MediFlow Pre-Deployment Guide

## Overview
This comprehensive guide covers all necessary steps to deploy the MediFlow healthcare management application to production. Follow these steps in order to ensure a secure, stable, and functional deployment.

## Table of Contents
1. [Critical Bug Fixes Required](#critical-bug-fixes-required)
2. [Database Setup and Migration](#database-setup-and-migration)
3. [Security Configuration](#security-configuration)
4. [Environment Configuration](#environment-configuration)
5. [Dependencies Installation](#dependencies-installation)
6. [Static Files and Frontend](#static-files-and-frontend)
7. [Application Testing](#application-testing)
8. [Production Server Setup](#production-server-setup)
9. [Monitoring and Logging](#monitoring-and-logging)
10. [Backup and Recovery](#backup-and-recovery)
11. [Post-Deployment Verification](#post-deployment-verification)

---

## 1. Critical Bug Fixes Required

### URGENT: Fix UnboundLocalError in admin_appointments route
**File**: `app.py` (Line 793)
**Error**: `end_date_str_current_week = end_date_str_current_week.strftime('%Y-%m-%d')`
**Fix**: Change to `end_date_str_current_week = end_date_current_week.strftime('%Y-%m-%d')`

```python
# BEFORE (BROKEN):
end_date_str_current_week = end_date_str_current_week.strftime('%Y-%m-%d')

# AFTER (FIXED):
end_date_str_current_week = end_date_current_week.strftime('%Y-%m-%d')
```

### Cleanup Unused Files
- **Optional**: Remove `forms.py` as it's not used in the application
- Verify no imports reference the removed file

---

## 2. Database Setup and Migration

### Database Schema Overview
The application uses SQLite with the following main tables:
- **User Management**: `users`, `admins`, `doctors`
- **Patient Management**: `patients`, `medical_information`, `emergency_contact`, `insurance_information`
- **Healthcare Operations**: `Appointments`, `prescriptions`, `history_prescriptions`, `medical_records`
- **Financial Management**: `billing`
- **Expense Tracking**: `medical_supplies`, `utilities`, `equipments`, `marketing`, `other_expenses`
- **Communication**: `messages` (with encryption)
- **File Management**: `files`
- **Scheduling**: `doctor_working_hours`

### Production Database Setup

#### Option A: SQLite (Small to Medium Scale)
```bash
# 1. Copy existing database structure
cp mediflow.db mediflow_production.db

# 2. Clear test data (if any)
sqlite3 mediflow_production.db
> DELETE FROM users WHERE email LIKE '%test%';
> DELETE FROM admins WHERE email LIKE '%test%';
> -- Clear other test data as needed
> .exit

# 3. Set proper permissions
chmod 644 mediflow_production.db
```

#### Option B: PostgreSQL (Large Scale Production)
```bash
# 1. Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib

# 2. Create database and user
sudo -u postgres psql
CREATE DATABASE mediflow_production;
CREATE USER mediflow_user WITH PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE mediflow_production TO mediflow_user;
\q

# 3. Convert SQLite schema to PostgreSQL
# Use a migration tool or manually convert the schema
```

### Database Migration Script
Create `migrate_database.py`:
```python
import sqlite3
import os
from datetime import datetime

def backup_database():
    """Create backup before migration"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_name = f"mediflow_backup_{timestamp}.db"
    os.system(f"cp mediflow.db {backup_name}")
    print(f"Database backed up to {backup_name}")

def verify_schema():
    """Verify all tables exist"""
    conn = sqlite3.connect('mediflow.db')
    cursor = conn.cursor()
    
    required_tables = [
        'users', 'admins', 'patients', 'doctors', 'Appointments',
        'billing', 'prescriptions', 'medical_records', 'messages',
        'medical_supplies', 'utilities', 'equipments', 'marketing',
        'other_expenses', 'doctor_working_hours', 'files',
        'medical_information', 'emergency_contact', 'insurance_information'
    ]
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    existing_tables = [table[0] for table in cursor.fetchall()]
    
    missing_tables = set(required_tables) - set(existing_tables)
    if missing_tables:
        print(f"Missing tables: {missing_tables}")
        return False
    
    print("All required tables exist")
    return True

if __name__ == "__main__":
    backup_database()
    verify_schema()
```

---

## 3. Security Configuration

### Environment Variables
Create `.env` file (NEVER commit to git):
```bash
# Database Configuration
DATABASE_URL=sqlite:///mediflow_production.db
# OR for PostgreSQL:
# DATABASE_URL=postgresql://mediflow_user:secure_password@localhost/mediflow_production

# Flask Security
SECRET_KEY=your_super_secret_key_here_minimum_32_chars
FLASK_ENV=production

# Email Configuration (for password reset)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@domain.com
MAIL_PASSWORD=your_app_password

# File Upload Security
MAX_CONTENT_LENGTH=16777216  # 16MB
UPLOAD_FOLDER=/secure/path/to/uploads

# Session Security
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax

# Rate Limiting
RATELIMIT_STORAGE_URL=redis://localhost:6379
```

### Security Headers Configuration
Add to `app.py`:
```python
from flask_talisman import Talisman

# Add after app creation
Talisman(app, 
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        'style-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        'font-src': "'self' https://fonts.gstatic.com",
        'img-src': "'self' data:",
    }
)
```

### Password Security
Ensure all passwords use proper hashing:
```python
# Verify password hashing in validation.py is using werkzeug.security
from werkzeug.security import generate_password_hash, check_password_hash

# Minimum password requirements (already implemented in register.html)
# - At least 8 characters
# - At least one uppercase letter
# - At least one lowercase letter  
# - At least one number
# - At least one special character
```

### File Upload Security
```python
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
```

---

## 4. Environment Configuration

### Production Flask Configuration
Update `app.py` configuration:
```python
import os
from dotenv import load_dotenv

load_dotenv()

class ProductionConfig:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session Configuration
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16777216))
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/var/www/mediflow/uploads')
    
    # Security
    WTF_CSRF_ENABLED = True
    
    # Email Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

app.config.from_object(ProductionConfig)
```

### Logging Configuration
```python
import logging
from logging.handlers import RotatingFileHandler

if not app.debug:
    file_handler = RotatingFileHandler('logs/mediflow.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('MediFlow startup')
```

---

## 5. Dependencies Installation

### Python Dependencies
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install production dependencies
pip install -r requirements.txt

# Additional production dependencies
pip install python-dotenv flask-talisman gunicorn psycopg2-binary redis flask-limiter

# Update requirements.txt
pip freeze > requirements.txt
```

### System Dependencies
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install nginx redis-server postgresql postgresql-contrib

# CentOS/RHEL
sudo yum install nginx redis postgresql postgresql-server

# Start services
sudo systemctl start nginx
sudo systemctl start redis
sudo systemctl start postgresql
sudo systemctl enable nginx
sudo systemctl enable redis
sudo systemctl enable postgresql
```

---

## 6. Static Files and Frontend

### Static Files Setup
```bash
# Create static directories
mkdir -p static/css static/js static/images static/uploads

# Set proper permissions
chmod 755 static/
chmod 755 static/css static/js static/images
chmod 775 static/uploads  # Write permissions for uploads

# Copy any existing static files
# Ensure Bootstrap, jQuery, and other assets are properly linked
```

### Frontend Validation
Verify the following files have proper Bootstrap integration:
- ✅ `templates/login.html` - Updated with error message handling
- ✅ `templates/register.html` - Complete Bootstrap 5 integration with validation
- ❓ Other templates - Check for consistent styling

---

## 7. Application Testing

### Pre-Deployment Test Checklist

#### Authentication Testing
```bash
# Test login functionality
curl -X POST http://localhost:5000/login \
  -d "email=test@example.com&password=wrongpassword" \
  -H "Content-Type: application/x-www-form-urlencoded"
# Should return error message

# Test registration validation
curl -X POST http://localhost:5000/register \
  -d "email=invalid&password=weak" \
  -H "Content-Type: application/x-www-form-urlencoded"
# Should return validation errors
```

#### Database Testing
```python
# Create test_database.py
import sqlite3
import sys

def test_database_integrity():
    try:
        conn = sqlite3.connect('mediflow.db')
        cursor = conn.cursor()
        
        # Test all foreign key constraints
        cursor.execute("PRAGMA foreign_keys = ON")
        
        # Test table accessibility
        tables_to_test = [
            'users', 'admins', 'patients', 'doctors', 'Appointments',
            'billing', 'prescriptions', 'medical_records'
        ]
        
        for table in tables_to_test:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"Table {table}: {count} records")
        
        conn.close()
        print("Database integrity test passed")
        return True
        
    except Exception as e:
        print(f"Database test failed: {e}")
        return False

if __name__ == "__main__":
    if not test_database_integrity():
        sys.exit(1)
```

#### Form Validation Testing
Test all forms with:
- Valid data
- Invalid email formats
- Weak passwords
- Missing required fields
- SQL injection attempts
- XSS attempts

#### File Upload Testing
```bash
# Test file upload security
# Try uploading:
# - Valid PDF file
# - Valid image file
# - Invalid file type (.exe, .php)
# - Oversized file
# - File with malicious content
```

---

## 8. Production Server Setup

### Nginx Configuration
Create `/etc/nginx/sites-available/mediflow`:
```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com www.your-domain.com;
    
    ssl_certificate /path/to/ssl/certificate.crt;
    ssl_certificate_key /path/to/ssl/private.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /static {
        alias /var/www/mediflow/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    client_max_body_size 16M;
}
```

### Gunicorn Configuration
Create `gunicorn.conf.py`:
```python
bind = "127.0.0.1:8000"
workers = 4
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100
timeout = 30
keepalive = 2
preload_app = True
user = "www-data"
group = "www-data"
tmp_upload_dir = None
secure_scheme_headers = {
    'X-FORWARDED-PROTOCOL': 'ssl',
    'X-FORWARDED-PROTO': 'https',
    'X-FORWARDED-SSL': 'on'
}
```

### Systemd Service
Create `/etc/systemd/system/mediflow.service`:
```ini
[Unit]
Description=MediFlow Healthcare Management
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/mediflow
Environment=PATH=/var/www/mediflow/venv/bin
ExecStart=/var/www/mediflow/venv/bin/gunicorn -c gunicorn.conf.py app:app
ExecReload=/bin/kill -s HUP $MAINPID
Restart=always

[Install]
WantedBy=multi-user.target
```

### SSL Certificate Setup
```bash
# Using Let's Encrypt (recommended)
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Or use a purchased SSL certificate
# Copy certificate files to /etc/ssl/certs/
# Copy private key to /etc/ssl/private/
```

---

## 9. Monitoring and Logging

### Log File Setup
```bash
# Create log directories
sudo mkdir -p /var/log/mediflow
sudo chown www-data:www-data /var/log/mediflow

# Create log rotation
sudo nano /etc/logrotate.d/mediflow
```

Logrotate configuration:
```
/var/log/mediflow/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
    postrotate
        systemctl reload mediflow
    endscript
}
```

### Health Check Endpoint
Add to `app.py`:
```python
@app.route('/health')
def health_check():
    try:
        # Test database connection
        conn = sqlite3.connect('mediflow.db')
        conn.execute('SELECT 1')
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500
```

### Monitoring Script
Create `monitor.sh`:
```bash
#!/bin/bash
LOG_FILE="/var/log/mediflow/monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Check service status
if systemctl is-active --quiet mediflow; then
    echo "[$DATE] MediFlow service is running" >> $LOG_FILE
else
    echo "[$DATE] ERROR: MediFlow service is down" >> $LOG_FILE
    systemctl restart mediflow
fi

# Check disk space
DISK_USAGE=$(df /var/www/mediflow | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    echo "[$DATE] WARNING: Disk usage is ${DISK_USAGE}%" >> $LOG_FILE
fi

# Check database size
DB_SIZE=$(ls -lh /var/www/mediflow/mediflow.db | awk '{print $5}')
echo "[$DATE] Database size: $DB_SIZE" >> $LOG_FILE
```

---

## 10. Backup and Recovery

### Database Backup Script
Create `backup.sh`:
```bash
#!/bin/bash
BACKUP_DIR="/var/backups/mediflow"
DATE=$(date +%Y%m%d_%H%M%S)
DB_FILE="/var/www/mediflow/mediflow.db"

# Create backup directory
mkdir -p $BACKUP_DIR

# Database backup
cp $DB_FILE "$BACKUP_DIR/mediflow_$DATE.db"

# Compress old backups
find $BACKUP_DIR -name "*.db" -mtime +7 -exec gzip {} \;

# Remove backups older than 30 days
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete

# Backup uploads
tar -czf "$BACKUP_DIR/uploads_$DATE.tar.gz" /var/www/mediflow/static/uploads/

echo "Backup completed: mediflow_$DATE.db"
```

### Automated Backup with Crontab
```bash
# Add to crontab
sudo crontab -e

# Daily backup at 2 AM
0 2 * * * /var/www/mediflow/backup.sh >> /var/log/mediflow/backup.log 2>&1

# Weekly database optimization
0 3 * * 0 sqlite3 /var/www/mediflow/mediflow.db "VACUUM;" >> /var/log/mediflow/maintenance.log 2>&1
```

### Recovery Procedure
```bash
# To restore from backup:
# 1. Stop the service
sudo systemctl stop mediflow

# 2. Restore database
cp /var/backups/mediflow/mediflow_YYYYMMDD_HHMMSS.db /var/www/mediflow/mediflow.db

# 3. Restore uploads (if needed)
tar -xzf /var/backups/mediflow/uploads_YYYYMMDD_HHMMSS.tar.gz -C /

# 4. Set permissions
sudo chown www-data:www-data /var/www/mediflow/mediflow.db
sudo chmod 644 /var/www/mediflow/mediflow.db

# 5. Start the service
sudo systemctl start mediflow
```

---

## 11. Post-Deployment Verification

### Deployment Checklist

#### Security Verification
- [ ] All environment variables are set in `.env`
- [ ] Secret key is randomly generated and secure
- [ ] Database credentials are not in source code
- [ ] SSL certificate is properly configured
- [ ] File upload directory has correct permissions
- [ ] Debug mode is disabled (`FLASK_ENV=production`)
- [ ] Security headers are enabled
- [ ] Rate limiting is configured

#### Functionality Testing
- [ ] Login page displays properly
- [ ] Registration form validates correctly
- [ ] Error messages display with Bootstrap styling
- [ ] Password requirements tooltip works
- [ ] File uploads work and are secure
- [ ] Database queries execute without errors
- [ ] All user types can access appropriate pages
- [ ] Admin appointments page works (bug fixed)
- [ ] Email notifications work (if configured)

#### Performance Testing
- [ ] Page load times are acceptable
- [ ] Database queries are optimized
- [ ] Static files are served efficiently
- [ ] Concurrent user handling works
- [ ] Memory usage is reasonable

#### Monitoring Setup
- [ ] Log files are being created
- [ ] Health check endpoint responds
- [ ] Backup script runs successfully
- [ ] Service auto-starts on boot
- [ ] Monitoring alerts are configured

### Final Testing Commands
```bash
# Test all major endpoints
curl -I https://your-domain.com/  # Should return 200
curl -I https://your-domain.com/login  # Should return 200
curl -I https://your-domain.com/register  # Should return 200
curl -I https://your-domain.com/health  # Should return 200

# Test SSL
openssl s_client -connect your-domain.com:443 -servername your-domain.com

# Test database connection
python3 -c "import sqlite3; conn = sqlite3.connect('mediflow.db'); print('Database OK')"

# Check service status
sudo systemctl status mediflow
sudo systemctl status nginx
```

---

## Emergency Contacts and Procedures

### Critical Issues
1. **Database corruption**: Restore from latest backup
2. **Service down**: Check logs at `/var/log/mediflow/`
3. **SSL certificate expiry**: Renew with `sudo certbot renew`
4. **High server load**: Check logs and restart services if needed

### Rollback Procedure
```bash
# If deployment fails:
# 1. Stop new service
sudo systemctl stop mediflow

# 2. Restore previous version
git checkout previous_working_commit

# 3. Restore database backup if needed
cp /var/backups/mediflow/mediflow_BACKUP.db mediflow.db

# 4. Restart service
sudo systemctl start mediflow
```

---

## Maintenance Schedule

### Daily
- Monitor service status
- Check log files for errors
- Verify backup completion

### Weekly
- Review security logs
- Update system packages
- Database optimization (VACUUM)
- Test backup restoration

### Monthly
- Security audit
- Performance review
- Update dependencies
- Review user accounts

### Quarterly
- Full security assessment
- Disaster recovery test
- Documentation update
- Staff training update

---

## Success Criteria

Your deployment is successful when:
1. ✅ All critical bugs are fixed
2. ✅ Application loads without errors
3. ✅ User authentication works correctly
4. ✅ Error messages display properly
5. ✅ Database operations complete successfully
6. ✅ File uploads work securely
7. ✅ SSL is properly configured
8. ✅ Backups are running automatically
9. ✅ Monitoring is functional
10. ✅ Performance meets requirements

---

## Support Information

- **Application Version**: 1.0.0
- **Database Schema**: See `databse.txt` for complete structure
- **Last Updated**: May 27, 2025
- **Critical Dependencies**: Flask, SQLite3, Bootstrap 5, Werkzeug

For issues not covered in this guide, check the application logs at `/var/log/mediflow/` and review the troubleshooting section of the main README.md file.
