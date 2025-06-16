from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail
from extension import jwt, oauth,mail
app = Flask(__name__)
app.secret_key = 'Dheeraj@2006'


app.config['JWT_SECRET_KEY'] = 'Dheeraj@2006'  # Change this to a secure key

# ✅ Initialize JWT and OAuth with the app
jwt.init_app(app)
oauth.init_app(app)


# Flask-Mail Configuration for Hostinger
app.config['MAIL_SERVER'] = 'smtp.hostinger.com'  # ✅ Use Hostinger's SMTP
app.config['MAIL_PORT'] = 465  # ✅ Use 465 for SSL (or 587 for TLS)
app.config['MAIL_USE_TLS'] = False  # ✅ Set False for SSL
app.config['MAIL_USE_SSL'] = True  # ✅ Set True for SSL
app.config['MAIL_USERNAME'] = 'business@registrarnegocio.com'  # ✅ Replace with your Hostinger email
app.config['MAIL_PASSWORD'] = 'Dheeraj@2006'  # ✅ Use your actual email password
app.config['MAIL_DEFAULT_SENDER'] = 'business@registrarnegocio.com'  # ✅ Set default sender

# Initialize Mail
mail.init_app(app)

CORS(app, resources={r"/*": {"origins": ["http://localhost:1000","*"],
                             "methods": ["GET","PUT", "POST", "OPTIONS","DELETE"],
                             "supports_credentials": True}})


# Register Blueprints
@app.route("/", methods=['GET'])
def home():
    return jsonify({"status": "success", "message": "Flask API is running!"})

from Routes.auth import auth_bp
from Routes.form import forms_bp
from Routes.submissions import submissions_bp


app.register_blueprint(auth_bp,url_prefix='/api/auth')  
app.register_blueprint(forms_bp ,url_prefix='/api/forms')  
app.register_blueprint(submissions_bp,url_prefix='/api/submissions' )  



if __name__ == "__main__":
    # print("Server is running on http://127.0.0.1:5000")  # Debugging
    # app.run(debug=True, port=5000)
    app.run(host="0.0.0.0",debug=True, port=2000)