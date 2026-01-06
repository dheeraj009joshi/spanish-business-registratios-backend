import os
import certifi
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MongoDB URI from environment variable or default
MONGODB_URI = os.getenv(
    'MONGODB_URI', 
    'mongodb+srv://dlovej009:Dheeraj2006@cluster0.dnu8vna.mongodb.net/?retryWrites=true&w=majority'
)

# Initialize MongoDB client
client = MongoClient(MONGODB_URI, tlsCAFile=certifi.where())
db = client['register_businesses']

# User Collections
STUDY_USER_collection = db['USERS']
ADMIN_USER_collection = db['ADMINS']

# Form & Submission Collections
FORM_SUBMISSION_Collection = db["forms_submitted"]
SUBMISSION_Collection = db["submissions"]

# Payment & Transaction Collections
TRANSACTIONS_Collection = db["transactions"]
PAYMENTS_Collection = db["payments"]

# Contact & Support Collections
CONTACT_QUERIES_Collection = db["contact_queries"]

# Settings Collection
SETTINGS_Collection = db["settings"]

# Health check function
def check_db_connection():
    """Check if database connection is healthy"""
    try:
        client.admin.command('ping')
        return True
    except Exception as e:
        print(f"Database connection error: {e}")
        return False
