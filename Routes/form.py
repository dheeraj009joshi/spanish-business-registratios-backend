from flask import Blueprint, request, jsonify
from functions import decode_token
from DB.db import FORM_SUBMISSION_Collection
import datetime
import uuid

from functions import protected, send_submission_email

forms_bp = Blueprint('forms', __name__)
@protected
@forms_bp.route('/submit', methods=['POST'])
def submit_form():
    if request.method == "OPTIONS":
        return '', 204

    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    form_type = data.get("type")
    form_data = data.get("data")

    if not form_type:
        return jsonify({"success": False, "error": "Missing form type"}), 422

    if not form_data or not isinstance(form_data, dict):
        return jsonify({"success": False, "error": "Missing or invalid form data"}), 422

    # Optional: Validate DIY-specific fields
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({'success': False, 'error': 'Missing or invalid token'}), 401

    token = auth_header.split(" ")[1]
    if form_type == "DIY":
        required_fields = ["businesstype", "businessName1", "principalState"]
        for field in required_fields:
            if not form_data.get(field):
                return jsonify({"success": False, "error": f"Missing field: {field}"}), 422

    now = datetime.datetime.utcnow()
    submission_id = str(uuid.uuid4())
    user_id = decode_token(token)

    FORM_SUBMISSION_Collection.insert_one({
        "submissionId": submission_id,
        "userId": user_id,
        "type": form_type,
        "data": form_data,
        "status": "pending",                     # default
        "submittedAt": now,
        "lastUpdated": now,
        "totalAmount": 0,                        # default
        "notes": "",                             # default
        "documents": [],                         # default
        "timeline": []                           # default
    }
)

    return jsonify({"success": True, "message": "Form submitted"})