#!/usr/bin/env python3
"""
IOC Manager - Application Entry Point
Run this file to start the development server
"""

import os
from app import create_app

# Create Flask application
app = create_app()

if __name__ == '__main__':
    # Get host and port from environment or use defaults
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'

    print(f"Starting IOC Manager on http://{host}:{port}")
    print(f"Debug mode: {debug}")
    print("Press CTRL+C to quit")

    app.run(host=host, port=port, debug=debug)
