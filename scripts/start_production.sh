#!/bin/bash

# MediFlow Production Quick Start Script
# ====================================
# This script quickly starts MediFlow in production mode

echo "🚀 MediFlow Production Quick Start"
echo "=================================="

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "❌ Virtual environment not found. Please run setup first."
    exit 1
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source .venv/Scripts/activate

# Check if production database exists
if [ ! -f "database/mediflow_production.db" ]; then
    echo "📊 Production database not found. Running deployment preparation..."
    python scripts/deploy.py
fi

# Run health checks
echo "🏥 Running health checks..."
python deployment/health_check.py

if [ $? -ne 0 ]; then
    echo "❌ Health checks failed. Please fix issues before starting."
    exit 1
fi

# Start the application
echo "🚀 Starting MediFlow in production mode..."
echo "📱 Access your clinic management system at: http://localhost:5000"
echo "🛑 Press Ctrl+C to stop the server"
echo ""

# Kill any existing process on port 5000 (Windows compatible)
netstat -ano | findstr :5000 | awk '{print $5}' | xargs -r taskkill //PID //F 2>/dev/null || true

python src/app.py
