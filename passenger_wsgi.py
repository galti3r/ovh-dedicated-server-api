# passenger_wsgi.py
# WSGI entrypoint for cPanel/Passenger

import sys
import os

# Ensure app root is on sys.path (Passenger sets cwd to app root, but keep it robust)
APP_DIR = os.path.dirname(os.path.abspath(__file__))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

# Import the Flask app object from your module
from ovh_dedicated import app as application  # <- Passenger expects 'application'

