#!/bin/bash

# MediFlow Development Server Startup Script
# ==========================================

echo "🏥 Starting MediFlow Development Server"
echo "======================================="

# Check if virtual environment is activated
if [ -z "$VIRTUAL_ENV" ]; then
    echo "🔧 Activating virtual environment..."
    source .venv/Scripts/activate
fi

# Check if we're in the correct directory
if [ ! -f "src/app.py" ]; then
    echo "❌ Error: Please run this script from the MediFlow root directory"
    echo "💡 Current directory should contain 'src/app.py'"
    exit 1
fi

# Check if database exists
if [ ! -f "database/mediflow.db" ]; then
    echo "📊 Development database not found. Creating it..."
    python init_database.py development
fi

# Set development environment
export FLASK_ENV=development
export DEBUG=True

# Start the development server
echo "🚀 Starting development server..."
echo "📱 Access your application at: http://localhost:5000"
echo "🛑 Press Ctrl+C to stop the server"
echo ""

# Run from project root, but execute the app in src/
python src/app.py
