from flask import Blueprint, request, jsonify
from functions import decode_token
from DB.db import FORM_SUBMISSION_Collection, TRANSACTIONS_Collection
from bson.objectid import ObjectId
import datetime

submissions_bp = Blueprint('submissions', __name__)

def format_submission(sub, include_details=False):
    """Format submission for API response"""
    data = sub.get('data', {})
    
    # Extract business name from various possible fields
    business_name = (
        data.get('businessName') or 
        data.get('businessName1') or 
        sub.get('businessInfo', {}).get('businessName') or
        'Unnamed Business'
    )
    
    # Extract business type
    business_type = (
        data.get('businesstype') or 
        data.get('businessType') or 
        sub.get('businessInfo', {}).get('businessType') or
        'domestic-llc'
    )
    
    # Extract contact info
    email = (
        data.get('businessEmail') or 
        data.get('primaryEmail') or 
        sub.get('personalInfo', {}).get('email') or
        ''
    )
    
    phone = (
        data.get('phoneNumber') or 
        sub.get('personalInfo', {}).get('phone') or
        ''
    )
    
    result = {
        'id': str(sub.get('_id', '')),
        'submissionId': sub.get('submissionId', str(sub.get('_id', ''))),
        'type': sub.get('type', 'ASSISTED'),
        'businessName': business_name,
        'businessType': business_type,
        'email': email,
        'phone': phone,
        'status': sub.get('status', 'pending'),
        'paymentStatus': sub.get('paymentStatus', 'unpaid'),
        'totalAmount': sub.get('totalAmount') or data.get('totalAmount', 0),
        'submittedAt': sub.get('submittedAt') or sub.get('createdAt', ''),
        'lastUpdated': sub.get('lastUpdated', ''),
        'notes': sub.get('notes', ''),
        'adminNotes': sub.get('adminNotes', []),
        'timeline': sub.get('timeline', []),
        'documents': sub.get('documents', [])
    }
    
    if include_details:
        result['data'] = data
        result['additionalServices'] = data.get('additionalServices', [])
        
        # Format addresses
        result['businessAddress'] = {
            'line1': data.get('businessAddressLine1', ''),
            'line2': data.get('businessAddressLine2', ''),
            'city': data.get('businessCity', ''),
            'state': data.get('businessState', ''),
            'zipCode': data.get('businessZipCode', ''),
            'county': data.get('businessCounty', '')
        }
        result['personalAddress'] = {
            'line1': data.get('personalAddressLine1', ''),
            'line2': data.get('personalAddressLine2', ''),
            'city': data.get('personalCity', ''),
            'state': data.get('personalState', ''),
            'zipCode': data.get('personalZipCode', ''),
            'county': data.get('personalCounty', '')
        }
        
        # Additional business info
        result['industry'] = data.get('industry', '')
        result['businessDescription'] = data.get('businessDescription', '')
    
    return result


@submissions_bp.route('', methods=['GET'])
def get_user_submissions():
    """Get all submissions for the authenticated user"""
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

    submissions_cursor = FORM_SUBMISSION_Collection.find({'userId': user_id}).sort('submittedAt', -1).skip(skip).limit(limit)
    total = FORM_SUBMISSION_Collection.count_documents({'userId': user_id})
    
    submissions = [format_submission(sub) for sub in submissions_cursor]

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
    """Get detailed submission info for user"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({'success': False, 'error': 'Missing or invalid token'}), 401

    token = auth_header.split(" ")[1]
    user_id = decode_token(token)
    if not user_id:
        return jsonify({'success': False, 'error': 'Invalid or expired token'}), 401

    # Try to find by _id first, then by submissionId
    sub = None
    
    # Try ObjectId first
    if ObjectId.is_valid(submission_id):
        sub = FORM_SUBMISSION_Collection.find_one({
            '_id': ObjectId(submission_id),
            'userId': user_id
        })
    
    # If not found, try submissionId
    if not sub:
        sub = FORM_SUBMISSION_Collection.find_one({
            'submissionId': submission_id,
            'userId': user_id
        })
    
    if not sub:
        return jsonify({'success': False, 'error': 'Submission not found'}), 404

    # Get related transactions
    transactions = list(TRANSACTIONS_Collection.find({
        '$or': [
            {'submissionId': str(sub.get('_id'))},
            {'submissionId': sub.get('submissionId')}
        ]
    }))
    
    result = format_submission(sub, include_details=True)
    result['transactions'] = [{
        'id': str(t['_id']),
        'amount': t.get('amount', 0),
        'status': t.get('status', 'pending'),
        'createdAt': t.get('createdAt', '')
    } for t in transactions]

    return jsonify({
        'success': True,
        'data': result
    })


@submissions_bp.route('/<submission_id>/notes', methods=['GET'])
def get_submission_notes(submission_id):
    """Get admin notes for a submission (visible to user)"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({'success': False, 'error': 'Missing or invalid token'}), 401

    token = auth_header.split(" ")[1]
    user_id = decode_token(token)
    if not user_id:
        return jsonify({'success': False, 'error': 'Invalid or expired token'}), 401

    sub = None
    if ObjectId.is_valid(submission_id):
        sub = FORM_SUBMISSION_Collection.find_one({
            '_id': ObjectId(submission_id),
            'userId': user_id
        })
    
    if not sub:
        sub = FORM_SUBMISSION_Collection.find_one({
            'submissionId': submission_id,
            'userId': user_id
        })
    
    if not sub:
        return jsonify({'success': False, 'error': 'Submission not found'}), 404

    # Filter admin notes to only show public ones
    admin_notes = sub.get('adminNotes', [])
    public_notes = [note for note in admin_notes if note.get('isPublic', True)]

    return jsonify({
        'success': True,
        'data': {
            'notes': public_notes,
            'timeline': sub.get('timeline', [])
        }
    })
