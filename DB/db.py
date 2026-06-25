import certifi
from pymongo import MongoClient
# uri = "mongodb+srv://dlovej009:dlovej009@cluster0.2pepq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
uri = "mongodb+srv://dlovej009:Dheeraj2006@cluster0.dnu8vna.mongodb.net/?retryWrites=true&w=majority" ## test url
client = MongoClient(uri,tlsCAFile=certifi.where())
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