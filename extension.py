from flask_jwt_extended import JWTManager
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail
jwt = JWTManager()  # Initialize JWT without passing app yet
oauth = OAuth() 
mail=Mail()