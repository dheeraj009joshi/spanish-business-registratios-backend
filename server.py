import os
from datetime import timedelta
from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from extension import jwt, oauth, mail

app = Flask(__name__)

# ===========================================
# CONFIGURATION FROM ENVIRONMENT VARIABLES
# ===========================================

# Flask Secret Key
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-jwt-secret-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize JWT and OAuth
jwt.init_app(app)
oauth.init_app(app)

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.hostinger.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 465))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'False').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'business@registrarnegocio.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'business@registrarnegocio.com')

# Initialize Mail
mail.init_app(app)

# ===========================================
# CORS CONFIGURATION
# ===========================================

# Get environment
is_production = os.getenv('FLASK_ENV', 'development') == 'production'

# Allowed origins
allowed_origins = [
    "http://localhost:3000",
    "http://localhost:1000",
    "https://registrarnegocio.com",
    "https://www.registrarnegocio.com",
    "https://georgia.registrarnegocio.com",
]

# Add frontend URL from environment if set
frontend_url = os.getenv('FRONTEND_URL')
if frontend_url and frontend_url not in allowed_origins:
    allowed_origins.append(frontend_url)

CORS(app, resources={
    r"/*": {
        "origins": allowed_origins,
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "supports_credentials": True,
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"]
    }
})

# ===========================================
# ROUTES
# ===========================================

@app.route("/", methods=['GET'])
def home():
    return jsonify({
        "status": "success", 
        "message": "GeorgiaBiz Pro API is running!",
        "version": "1.0.0"
    })

@app.route("/health", methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({
        "status": "healthy",
        "environment": os.getenv('FLASK_ENV', 'development')
    })

# ===========================================
# REGISTER BLUEPRINTS
# ===========================================

from Routes.auth import auth_bp
from Routes.form import forms_bp
from Routes.submissions import submissions_bp
from Routes.payments import payments_bp
from Routes.admin import admin_bp

app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(forms_bp, url_prefix='/api/forms')
app.register_blueprint(submissions_bp, url_prefix='/api/submissions')
app.register_blueprint(payments_bp, url_prefix='/api/payments')
app.register_blueprint(admin_bp, url_prefix='/api/admin')

# ===========================================
# ERROR HANDLERS
# ===========================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"success": False, "error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"success": False, "error": "Internal server error"}), 500

# ===========================================
# MAIN
# ===========================================

if __name__ == "__main__":
    port = int(os.getenv('PORT', 2000))
    debug = os.getenv('FLASK_ENV', 'development') != 'production'
    
    print(f"🚀 Starting server on port {port}")
    print(f"📍 Environment: {os.getenv('FLASK_ENV', 'development')}")
    print(f"🔧 Debug mode: {debug}")
    
    app.run(host="0.0.0.0", debug=debug, port=port)
