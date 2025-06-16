from flask import Blueprint, request, jsonify
from functions import decode_token
from DB.db import FORM_SUBMISSION_Collection, SUBMISSION_Collection
from bson.objectid import ObjectId

submissions_bp = Blueprint('submissions', __name__)

@submissions_bp.route('', methods=['GET'])
def get_user_submissions():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({'success': False, 'error': 'Missing or invalid token'}), 401

    token = auth_header.split(" ")[1]
    user_id = decode_token(token)
    if not user_id:
        return jsonify({'success': False, 'error': 'Invalid or expired token'}), 401

    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    skip = (page - 1) * limit

    submissions_cursor =FORM_SUBMISSION_Collection.find({'userId': user_id}).skip(skip).limit(limit)
    total =FORM_SUBMISSION_Collection.count_documents({'userId': user_id})
    submissions = []
    
    for sub in submissions_cursor:
        print(sub)
        submissions.append({
            'id': str(sub['_id']),
            'type': sub['type'],
            'businessName': sub['data'].get('businessName') or sub['data'].get('businessName1'),
            'status':sub["status"],
            'submittedAt': sub["submittedAt"],
            'lastUpdated': sub["lastUpdated"],
            'totalAmount': sub.get('totalAmount', 0),
            'notes': sub.get('notes', ''),
            'documents': sub.get('documents', [])
        })

    return jsonify({
        'success': True,
        'data': {
            'submissions': submissions,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total,
                'totalPages': (total + limit - 1) // limit
            }
        }
    })

@submissions_bp.route('/<submission_id>', methods=['GET'])
def get_submission_details(submission_id):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({'success': False, 'error': 'Missing or invalid token'}), 401

    token = auth_header.split(" ")[1]
    user_id = decode_token(token)
    if not user_id:
        return jsonify({'success': False, 'error': 'Invalid or expired token'}), 401

    sub = FORM_SUBMISSION_Collection.find_one({'submissionId': submission_id, 'userId': user_id})
    if not sub:
        return jsonify({'success': False, 'error': 'Submission not found'}), 404

    return jsonify({
        'success': True,
        'data': {
            'id': sub['submissionId'],
            'type': sub['type'],
            'businessName': sub['data'].get('businessName') or sub['data'].get('businessName1'),
            'businessType': sub['data'].get('businesstype'),
            'status': sub['status'],
            'submittedAt': sub['submittedAt'].isoformat(),
            'lastUpdated': sub['lastUpdated'].isoformat(),
            'totalAmount': sub.get('totalAmount', 0),
            'documents': sub.get('documents', []),
            'notes': sub.get('notes', ''),
            'timeline': sub.get('timeline', []),
            'businessDetails': sub.get('data')
        }
    })
