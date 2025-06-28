#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys

# Set environment variables for UTF-8 support
os.environ['PYTHONIOENCODING'] = 'utf-8'
os.environ['PYTHONUTF8'] = '1'

# Import and run the Flask app
if __name__ == '__main__':
    from app import app
    with app.app_context():
        from app import create_tables, ensure_basic_functionality
        create_tables()
        ensure_basic_functionality()
    app.run(debug=True, host='0.0.0.0', port=5000) 