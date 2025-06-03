#!/bin/bash

# MediFlow Production Quick Start Script
# ====================================
# This script quickly starts MediFlow in production mode

echo "🚀 MediFlow Production Quick Start"
echo "=================================="

# Create database directory if it doesn't exist
echo "📁 Ensuring database directory exists..."
mkdir -p database

# Check if production database exists
if [ ! -f "database/mediflow_production.db" ]; then
    echo "📊 Production database not found. Running deployment preparation..."
    # Check if deploy script exists
    if [ -f "scripts/deploy.py" ]; then
        python scripts/deploy.py
    elif [ -f "init_database.py" ]; then
        python init_database.py production
    else
        echo "⚠️  No database initialization script found. Creating empty database..."
        touch database/mediflow_production.db
    fi
fi

# Run health checks
echo "🏥 Running health checks..."
if [ -f "deployment/health_check.py" ]; then
    python deployment/health_check.py
    
    if [ $? -ne 0 ]; then
        echo "❌ Health checks failed. Please fix issues before starting."
        exit 1
    fi
else
    echo "⚠️  Health check script not found, skipping..."
fi

# Start the application
echo "🚀 Starting MediFlow in production mode..."
echo "📱 Access your clinic management system at: http://localhost:${PORT:-5000}"
echo "🛑 Press Ctrl+C to stop the server"
echo ""

# Start the Flask application
python src/app.py