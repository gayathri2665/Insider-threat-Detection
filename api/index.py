import os
import sys

# Add root folder to python path so it can resolve src.* imports under Vercel serverless function
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the Flask app object from src/app.py
from src.app import app
