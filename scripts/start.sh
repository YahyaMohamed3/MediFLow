#!/bin/bash
# Production deployment script for Render
if [ "$RENDER" = "true" ]; then
    # Use Gunicorn on Render (Linux environment)
    gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:$PORT app:app
else
    # Use development server locally
    python app.py
fi
