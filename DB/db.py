import certifi
from pymongo import MongoClient
# uri = "mongodb+srv://dlovej009:dlovej009@cluster0.2pepq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
uri = "mongodb+srv://dlovej009:Dheeraj2006@cluster0.dnu8vna.mongodb.net/?retryWrites=true&w=majority" ## test url
client = MongoClient(uri,tlsCAFile=certifi.where())
db = client['register_businesses']
STUDY_USER_collection = db['USERS']
FORM_SUBMISSION_Collection = db["forms_submitted"]
SUBMISSION_Collection = db["submissions"]
# STUDIES_collection = db['STUDIES']
# ARTICLE_collection = db['ARTICLE']