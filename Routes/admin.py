import datetime
import hashlib
import secrets
from flask import Blueprint, request, jsonify
from bson import ObjectId
from functools import wraps
from functions import decode_token
from DB.db import (
    ADMIN_USER_collection,
    STUDY_USER_collection,
    FORM_SUBMISSION_Collection,
    TRANSACTIONS_Collection,
    PAYMENTS_Collection,
    CONTACT_QUERIES_Collection,
    SETTINGS_Collection
)

admin_bp = Blueprint('admin', __name__)


def hash_password(password):
    """Hash password with SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()


def admin_required(f):
    """Decorator to require admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask_jwt_extended import decode_token as jwt_decode, get_jwt_identity
        import jwt as pyjwt
        
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
        token = auth_header.split(" ")[1]
        
        # Try to decode using Flask-JWT-Extended
        try:
            decoded = jwt_decode(token)
            admin_id = decoded.get('sub')
        except Exception as e:
            # Fallback to custom decode
            admin_id = decode_token(token)
        
        if not admin_id:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401
        
        # Check if user is admin
        try:
            admin = ADMIN_USER_collection.find_one({'_id': ObjectId(admin_id)})
        except:
            return jsonify({'success': False, 'error': 'Invalid admin ID'}), 401
            
        if not admin:
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        request.admin_id = admin_id
        request.admin = admin
        return f(*args, **kwargs)
    return decorated_function


# ============== ADMIN AUTH ==============

@admin_bp.route('/login', methods=['POST'])
def admin_login():
    """Admin login"""
    from flask_jwt_extended import create_access_token
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'success': False, 'error': 'Email and password required'}), 400
    
    admin = ADMIN_USER_collection.find_one({'email': email.lower()})
    if not admin:
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    
    if admin.get('password') != hash_password(password):
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    
    # Create JWT token
    access_token = create_access_token(identity=str(admin['_id']))
    
    # Update last login
    ADMIN_USER_collection.update_one(
        {'_id': admin['_id']},
        {'$set': {'lastLogin': datetime.datetime.utcnow().isoformat()}}
    )
    
    return jsonify({
        'success': True,
        'data': {
            'token': access_token,
            'admin': {
                'id': str(admin['_id']),
                'email': admin['email'],
                'name': admin.get('name', 'Admin'),
                'role': admin.get('role', 'admin')
            }
        }
    })


@admin_bp.route('/create-admin', methods=['POST'])
@admin_required
def create_admin():
    """Create a new admin (only super admins can do this)"""
    if request.admin.get('role') != 'super_admin':
        return jsonify({'success': False, 'error': 'Super admin access required'}), 403
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    role = data.get('role', 'admin')
    
    if not email or not password:
        return jsonify({'success': False, 'error': 'Email and password required'}), 400
    
    # Check if admin already exists
    if ADMIN_USER_collection.find_one({'email': email.lower()}):
        return jsonify({'success': False, 'error': 'Admin already exists'}), 400
    
    admin = {
        'email': email.lower(),
        'password': hash_password(password),
        'name': name or email.split('@')[0],
        'role': role,
        'createdAt': datetime.datetime.utcnow().isoformat(),
        'createdBy': request.admin_id
    }
    
    result = ADMIN_USER_collection.insert_one(admin)
    
    return jsonify({
        'success': True,
        'data': {
            'id': str(result.inserted_id),
            'message': 'Admin created successfully'
        }
    })


# ============== DASHBOARD STATS ==============

@admin_bp.route('/dashboard/stats', methods=['GET'])
@admin_required
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        # Get date ranges
        now = datetime.datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        
        # Total counts
        total_users = STUDY_USER_collection.count_documents({})
        total_submissions = FORM_SUBMISSION_Collection.count_documents({})
        total_transactions = TRANSACTIONS_Collection.count_documents({'status': 'completed'})
        total_contacts = CONTACT_QUERIES_Collection.count_documents({})
        
        # Status counts
        pending_submissions = FORM_SUBMISSION_Collection.count_documents({'status': 'pending'})
        processing_submissions = FORM_SUBMISSION_Collection.count_documents({'status': 'processing'})
        completed_submissions = FORM_SUBMISSION_Collection.count_documents({'status': 'completed'})
        
        # Revenue calculation
        revenue_pipeline = [
            {'$match': {'status': 'completed'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        revenue_result = list(TRANSACTIONS_Collection.aggregate(revenue_pipeline))
        total_revenue = revenue_result[0]['total'] if revenue_result else 0
        
        # Monthly revenue
        monthly_pipeline = [
            {'$match': {'status': 'completed', 'createdAt': {'$gte': month_start}}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        monthly_result = list(TRANSACTIONS_Collection.aggregate(monthly_pipeline))
        monthly_revenue = monthly_result[0]['total'] if monthly_result else 0
        
        # Pending contact queries
        pending_contacts = CONTACT_QUERIES_Collection.count_documents({'status': 'pending'})
        
        return jsonify({
            'success': True,
            'data': {
                'users': {
                    'total': total_users
                },
                'submissions': {
                    'total': total_submissions,
                    'pending': pending_submissions,
                    'processing': processing_submissions,
                    'completed': completed_submissions
                },
                'revenue': {
                    'total': total_revenue,
                    'monthly': monthly_revenue,
                    'transactions': total_transactions
                },
                'contacts': {
                    'total': total_contacts,
                    'pending': pending_contacts
                }
            }
        })
        
    except Exception as e:
        print(f"Error getting dashboard stats: {e}")
        return jsonify({'success': False, 'error': 'Failed to get stats'}), 500


# ============== SUBMISSIONS MANAGEMENT ==============

def format_admin_submission(s, include_details=False):
    """Format submission for admin API response"""
    data = s.get('data', {})
    
    # Extract business info from data field
    business_name = (
        data.get('businessName') or 
        data.get('businessName1') or 
        s.get('businessInfo', {}).get('businessName') or
        ''
    )
    
    business_type = (
        data.get('businesstype') or 
        data.get('businessType') or 
        s.get('businessInfo', {}).get('businessType') or
        'domestic-llc'
    )
    
    # Extract contact info
    email = (
        data.get('businessEmail') or 
        data.get('primaryEmail') or 
        s.get('personalInfo', {}).get('email') or
        ''
    )
    
    phone = (
        data.get('phoneNumber') or 
        s.get('personalInfo', {}).get('phone') or
        ''
    )
    
    result = {
        'id': str(s['_id']),
        'submissionId': s.get('submissionId', str(s['_id'])),
        'userId': s.get('userId'),
        'type': s.get('type', 'ASSISTED'),
        'status': s.get('status', 'pending'),
        'paymentStatus': s.get('paymentStatus', 'unpaid'),
        'businessName': business_name,
        'businessType': business_type,
        'email': email,
        'phone': phone,
        'totalAmount': s.get('totalAmount') or data.get('totalAmount', 0),
        'createdAt': s.get('submittedAt') or s.get('createdAt', ''),
        'lastUpdated': s.get('lastUpdated', '')
    }
    
    if include_details:
        result['data'] = data
        result['additionalServices'] = data.get('additionalServices', [])
        result['industry'] = data.get('industry', '')
        result['businessDescription'] = data.get('businessDescription', '')
        
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
        
        result['documents'] = s.get('documents', [])
        result['timeline'] = s.get('timeline', [])
        result['adminNotes'] = s.get('adminNotes', [])
        result['notes'] = s.get('notes', '')
    
    return result


@admin_bp.route('/submissions', methods=['GET'])
@admin_required
def get_all_submissions():
    """Get all submissions with filtering and pagination"""
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        status = request.args.get('status')
        search = request.args.get('search')
        skip = (page - 1) * limit
        
        # Build query
        query = {}
        if status and status != 'all':
            query['status'] = status
        if search:
            query['$or'] = [
                {'data.businessName': {'$regex': search, '$options': 'i'}},
                {'data.businessName1': {'$regex': search, '$options': 'i'}},
                {'data.businessEmail': {'$regex': search, '$options': 'i'}},
                {'data.primaryEmail': {'$regex': search, '$options': 'i'}},
                {'submissionId': {'$regex': search, '$options': 'i'}}
            ]
        
        submissions_cursor = FORM_SUBMISSION_Collection.find(query).sort('submittedAt', -1).skip(skip).limit(limit)
        total = FORM_SUBMISSION_Collection.count_documents(query)
        
        submissions = [format_admin_submission(s) for s in submissions_cursor]
        
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
        
    except Exception as e:
        print(f"Error fetching submissions: {e}")
        return jsonify({'success': False, 'error': 'Failed to fetch submissions'}), 500


@admin_bp.route('/submissions/<submission_id>', methods=['GET'])
@admin_required
def get_submission_detail(submission_id):
    """Get detailed submission info"""
    try:
        submission = None
        
        # Try ObjectId first
        if ObjectId.is_valid(submission_id):
            submission = FORM_SUBMISSION_Collection.find_one({'_id': ObjectId(submission_id)})
        
        # If not found, try submissionId
        if not submission:
            submission = FORM_SUBMISSION_Collection.find_one({'submissionId': submission_id})
        
        if not submission:
            return jsonify({'success': False, 'error': 'Submission not found'}), 404
        
        # Get user info
        user = None
        if submission.get('userId'):
            try:
                user_doc = STUDY_USER_collection.find_one({'_id': ObjectId(submission['userId'])})
                if user_doc:
                    user = {
                        'id': str(user_doc['_id']),
                        'email': user_doc.get('email'),
                        'name': f"{user_doc.get('firstName', '')} {user_doc.get('lastName', '')}".strip() or user_doc.get('name', 'User')
                    }
            except:
                pass
        
        # Get related transactions
        transactions = list(TRANSACTIONS_Collection.find({
            '$or': [
                {'submissionId': str(submission['_id'])},
                {'submissionId': submission.get('submissionId')}
            ]
        }))
        
        result = format_admin_submission(submission, include_details=True)
        result['user'] = user
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
        
    except Exception as e:
        print(f"Error fetching submission: {e}")
        return jsonify({'success': False, 'error': 'Failed to fetch submission'}), 500


@admin_bp.route('/submissions/<submission_id>/status', methods=['PUT'])
@admin_required
def update_submission_status(submission_id):
    """Update submission status"""
    try:
        data = request.get_json()
        new_status = data.get('status')
        note = data.get('note', '')
        
        valid_statuses = ['pending', 'processing', 'review', 'approved', 'completed', 'rejected', 'cancelled']
        if new_status not in valid_statuses:
            return jsonify({'success': False, 'error': 'Invalid status'}), 400
        
        now = datetime.datetime.utcnow().isoformat()
        
        update = {
            '$set': {
                'status': new_status,
                'lastUpdated': now
            },
            '$push': {
                'timeline': {
                    'status': new_status,
                    'message': note or f'Status updated to {new_status}',
                    'timestamp': now,
                    'updatedBy': request.admin_id
                }
            }
        }
        
        result = FORM_SUBMISSION_Collection.update_one(
            {'$or': [
                {'_id': ObjectId(submission_id) if ObjectId.is_valid(submission_id) else None},
                {'submissionId': submission_id}
            ]},
            update
        )
        
        if result.modified_count == 0:
            return jsonify({'success': False, 'error': 'Submission not found'}), 404
        
        return jsonify({
            'success': True,
            'message': 'Status updated successfully'
        })
        
    except Exception as e:
        print(f"Error updating submission: {e}")
        return jsonify({'success': False, 'error': 'Failed to update submission'}), 500


@admin_bp.route('/submissions/<submission_id>/notes', methods=['POST'])
@admin_required
def add_submission_note(submission_id):
    """Add admin note to submission"""
    try:
        data = request.get_json()
        note = data.get('note')
        is_public = data.get('isPublic', True)  # Default to public so users can see
        
        if not note:
            return jsonify({'success': False, 'error': 'Note is required'}), 400
        
        now = datetime.datetime.utcnow().isoformat()
        
        # Get admin name
        admin_name = request.admin.get('name', 'Admin')
        
        result = FORM_SUBMISSION_Collection.update_one(
            {'$or': [
                {'_id': ObjectId(submission_id) if ObjectId.is_valid(submission_id) else None},
                {'submissionId': submission_id}
            ]},
            {
                '$push': {
                    'adminNotes': {
                        'id': str(ObjectId()),
                        'note': note,
                        'createdBy': request.admin_id,
                        'adminName': admin_name,
                        'createdAt': now,
                        'isPublic': is_public
                    }
                },
                '$set': {'lastUpdated': now}
            }
        )
        
        if result.modified_count == 0:
            return jsonify({'success': False, 'error': 'Submission not found'}), 404
        
        return jsonify({
            'success': True,
            'message': 'Note added successfully'
        })
        
    except Exception as e:
        print(f"Error adding note: {e}")
        return jsonify({'success': False, 'error': 'Failed to add note'}), 500


@admin_bp.route('/submissions/<submission_id>/payment-status', methods=['PUT'])
@admin_required
def update_payment_status(submission_id):
    """Update submission payment status"""
    try:
        data = request.get_json()
        payment_status = data.get('paymentStatus')
        
        valid_statuses = ['unpaid', 'pending', 'paid', 'refunded', 'failed']
        if payment_status not in valid_statuses:
            return jsonify({'success': False, 'error': 'Invalid payment status'}), 400
        
        now = datetime.datetime.utcnow().isoformat()
        
        result = FORM_SUBMISSION_Collection.update_one(
            {'$or': [
                {'_id': ObjectId(submission_id) if ObjectId.is_valid(submission_id) else None},
                {'submissionId': submission_id}
            ]},
            {
                '$set': {
                    'paymentStatus': payment_status,
                    'lastUpdated': now
                },
                '$push': {
                    'timeline': {
                        'status': f'payment_{payment_status}',
                        'message': f'Payment status updated to {payment_status}',
                        'timestamp': now,
                        'updatedBy': request.admin_id
                    }
                }
            }
        )
        
        if result.modified_count == 0:
            return jsonify({'success': False, 'error': 'Submission not found'}), 404
        
        return jsonify({
            'success': True,
            'message': 'Payment status updated successfully'
        })
        
    except Exception as e:
        print(f"Error updating payment status: {e}")
        return jsonify({'success': False, 'error': 'Failed to update payment status'}), 500


# ============== USERS MANAGEMENT ==============

@admin_bp.route('/users', methods=['GET'])
@admin_required
def get_all_users():
    """Get all users with pagination"""
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        search = request.args.get('search')
        skip = (page - 1) * limit
        
        query = {}
        if search:
            query['$or'] = [
                {'email': {'$regex': search, '$options': 'i'}},
                {'name': {'$regex': search, '$options': 'i'}}
            ]
        
        users_cursor = STUDY_USER_collection.find(query).sort('createdAt', -1).skip(skip).limit(limit)
        total = STUDY_USER_collection.count_documents(query)
        
        users = []
        for u in users_cursor:
            # Get submission count for user
            submission_count = FORM_SUBMISSION_Collection.count_documents({'userId': str(u['_id'])})
            
            users.append({
                'id': str(u['_id']),
                'email': u.get('email'),
                'name': u.get('name'),
                'phone': u.get('phone'),
                'authProvider': u.get('authProvider', 'local'),
                'submissionCount': submission_count,
                'createdAt': u.get('createdAt'),
                'lastLogin': u.get('lastLogin')
            })
        
        return jsonify({
            'success': True,
            'data': {
                'users': users,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': total,
                    'totalPages': (total + limit - 1) // limit
                }
            }
        })
        
    except Exception as e:
        print(f"Error fetching users: {e}")
        return jsonify({'success': False, 'error': 'Failed to fetch users'}), 500


@admin_bp.route('/users/<user_id>', methods=['GET'])
@admin_required
def get_user_detail(user_id):
    """Get detailed user info"""
    try:
        user = STUDY_USER_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Get user's submissions
        submissions = list(FORM_SUBMISSION_Collection.find({'userId': user_id}).sort('createdAt', -1).limit(10))
        
        # Get user's transactions
        transactions = list(TRANSACTIONS_Collection.find({'userId': user_id}).sort('createdAt', -1).limit(10))
        
        return jsonify({
            'success': True,
            'data': {
                'id': str(user['_id']),
                'email': user.get('email'),
                'name': user.get('name'),
                'phone': user.get('phone'),
                'authProvider': user.get('authProvider', 'local'),
                'createdAt': user.get('createdAt'),
                'lastLogin': user.get('lastLogin'),
                'submissions': [{
                    'id': str(s['_id']),
                    'submissionId': s.get('submissionId'),
                    'status': s.get('status'),
                    'businessName': s.get('businessInfo', {}).get('businessName'),
                    'createdAt': s.get('createdAt')
                } for s in submissions],
                'transactions': [{
                    'id': str(t['_id']),
                    'amount': t.get('amount'),
                    'status': t.get('status'),
                    'createdAt': t.get('createdAt')
                } for t in transactions]
            }
        })
        
    except Exception as e:
        print(f"Error fetching user: {e}")
        return jsonify({'success': False, 'error': 'Failed to fetch user'}), 500


# ============== TRANSACTIONS MANAGEMENT ==============

@admin_bp.route('/transactions', methods=['GET'])
@admin_required
def get_all_transactions():
    """Get all transactions with filtering"""
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        status = request.args.get('status')
        skip = (page - 1) * limit
        
        query = {}
        if status and status != 'all':
            query['status'] = status
        
        transactions_cursor = TRANSACTIONS_Collection.find(query).sort('createdAt', -1).skip(skip).limit(limit)
        total = TRANSACTIONS_Collection.count_documents(query)
        
        transactions = []
        for t in transactions_cursor:
            # Get user email
            user_email = None
            if t.get('userId'):
                user = STUDY_USER_collection.find_one({'_id': ObjectId(t['userId'])})
                if user:
                    user_email = user.get('email')
            
            transactions.append({
                'id': str(t['_id']),
                'userId': t.get('userId'),
                'userEmail': user_email,
                'submissionId': t.get('submissionId'),
                'type': t.get('type'),
                'amount': t.get('amount'),
                'currency': t.get('currency'),
                'status': t.get('status'),
                'stripeSessionId': t.get('stripeSessionId'),
                'createdAt': t.get('createdAt'),
                'paidAt': t.get('paidAt')
            })
        
        return jsonify({
            'success': True,
            'data': {
                'transactions': transactions,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': total,
                    'totalPages': (total + limit - 1) // limit
                }
            }
        })
        
    except Exception as e:
        print(f"Error fetching transactions: {e}")
        return jsonify({'success': False, 'error': 'Failed to fetch transactions'}), 500


# ============== CONTACT QUERIES MANAGEMENT ==============

@admin_bp.route('/contacts', methods=['GET'])
@admin_required
def get_all_contacts():
    """Get all contact queries"""
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        status = request.args.get('status')
        skip = (page - 1) * limit
        
        query = {}
        if status and status != 'all':
            query['status'] = status
        
        contacts_cursor = CONTACT_QUERIES_Collection.find(query).sort('createdAt', -1).skip(skip).limit(limit)
        total = CONTACT_QUERIES_Collection.count_documents(query)
        
        contacts = []
        for c in contacts_cursor:
            contacts.append({
                'id': str(c['_id']),
                'name': c.get('name'),
                'email': c.get('email'),
                'phone': c.get('phone'),
                'subject': c.get('subject'),
                'message': c.get('message'),
                'status': c.get('status', 'pending'),
                'createdAt': c.get('createdAt'),
                'respondedAt': c.get('respondedAt')
            })
        
        return jsonify({
            'success': True,
            'data': {
                'contacts': contacts,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': total,
                    'totalPages': (total + limit - 1) // limit
                }
            }
        })
        
    except Exception as e:
        print(f"Error fetching contacts: {e}")
        return jsonify({'success': False, 'error': 'Failed to fetch contacts'}), 500


@admin_bp.route('/contacts/<contact_id>/status', methods=['PUT'])
@admin_required
def update_contact_status(contact_id):
    """Update contact query status"""
    try:
        data = request.get_json()
        new_status = data.get('status')
        response_note = data.get('responseNote', '')
        
        valid_statuses = ['pending', 'in_progress', 'resolved', 'closed']
        if new_status not in valid_statuses:
            return jsonify({'success': False, 'error': 'Invalid status'}), 400
        
        now = datetime.datetime.utcnow().isoformat()
        
        update = {
            '$set': {
                'status': new_status,
                'lastUpdated': now
            }
        }
        
        if new_status == 'resolved':
            update['$set']['respondedAt'] = now
            update['$set']['respondedBy'] = request.admin_id
        
        if response_note:
            update['$push'] = {
                'notes': {
                    'note': response_note,
                    'createdBy': request.admin_id,
                    'createdAt': now
                }
            }
        
        result = CONTACT_QUERIES_Collection.update_one(
            {'_id': ObjectId(contact_id)},
            update
        )
        
        if result.modified_count == 0:
            return jsonify({'success': False, 'error': 'Contact not found'}), 404
        
        return jsonify({
            'success': True,
            'message': 'Status updated successfully'
        })
        
    except Exception as e:
        print(f"Error updating contact: {e}")
        return jsonify({'success': False, 'error': 'Failed to update contact'}), 500


# ============== CONTACT FORM SUBMISSION ==============

@admin_bp.route('/public/contact', methods=['POST'])
def submit_contact_form():
    """Public endpoint for contact form submission"""
    try:
        data = request.get_json()
        
        name = data.get('name')
        email = data.get('email')
        phone = data.get('phone')
        subject = data.get('subject')
        message = data.get('message')
        
        if not name or not email or not message:
            return jsonify({'success': False, 'error': 'Name, email, and message are required'}), 400
        
        contact = {
            'name': name,
            'email': email,
            'phone': phone,
            'subject': subject,
            'message': message,
            'status': 'pending',
            'createdAt': datetime.datetime.utcnow().isoformat()
        }
        
        result = CONTACT_QUERIES_Collection.insert_one(contact)
        
        return jsonify({
            'success': True,
            'data': {
                'id': str(result.inserted_id),
                'message': 'Your message has been sent successfully'
            }
        })
        
    except Exception as e:
        print(f"Error submitting contact: {e}")
        return jsonify({'success': False, 'error': 'Failed to submit contact form'}), 500


# ============== INITIAL ADMIN SETUP ==============

@admin_bp.route('/setup', methods=['POST'])
def setup_initial_admin():
    """Create initial super admin (only works if no admins exist)"""
    # Check if any admin exists
    if ADMIN_USER_collection.count_documents({}) > 0:
        return jsonify({'success': False, 'error': 'Admin already exists'}), 400
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    
    if not email or not password:
        return jsonify({'success': False, 'error': 'Email and password required'}), 400
    
    admin = {
        'email': email.lower(),
        'password': hash_password(password),
        'name': name or 'Super Admin',
        'role': 'super_admin',
        'createdAt': datetime.datetime.utcnow().isoformat()
    }
    
    result = ADMIN_USER_collection.insert_one(admin)
    
    return jsonify({
        'success': True,
        'data': {
            'id': str(result.inserted_id),
            'message': 'Super admin created successfully'
        }
    })

