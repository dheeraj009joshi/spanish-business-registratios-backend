import datetime
from flask_jwt_extended import  jwt_required
import jwt

def protected(f):
    @jwt_required()
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)
    return wrapper



def generate_token(user_id):
    payload = {
        'user_id': str(user_id),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, "dheeraj", algorithm='HS256')

def decode_token(token):
    try:
        payload = jwt.decode(token,  "dheeraj", algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


from flask_mail import Message
from flask import current_app
from extension import mail
def send_submission_email(to_email, submission_id):
    msg = Message(
        subject="New Business Registration Submitted",
        sender=current_app.config['MAIL_USERNAME'],
        recipients=[to_email],
        body=f"Your business registration (ID: {submission_id}) was submitted successfully."
    )
    mail.send(msg)
