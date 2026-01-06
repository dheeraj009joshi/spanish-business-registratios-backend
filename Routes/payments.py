import datetime
import stripe
import os
from flask import Blueprint, request, jsonify
from bson import ObjectId
from functions import decode_token
from DB.db import (
    TRANSACTIONS_Collection, 
    PAYMENTS_Collection, 
    FORM_SUBMISSION_Collection,
    STUDY_USER_collection
)

payments_bp = Blueprint('payments', __name__)

# Initialize Stripe with your secret key
# In production, use environment variable
STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY', 'sk_test_your_test_key_here')
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET', 'whsec_your_webhook_secret_here')
stripe.api_key = STRIPE_SECRET_KEY

# Pricing configuration
PRICING = {
    "DIY": 99,
    "ASSISTED": 299,
    "services": {
        "ein": 50,
        "registered-agent": 99,
        "operating-agreement": 150,
        "business-license": 75,
        "expedited-processing": 100,
        "document-review": 50
    }
}


def get_user_from_token():
    """Helper to get user from Authorization header"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    user_id = decode_token(token)
    return user_id


@payments_bp.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    """Create a Stripe Checkout Session for payment"""
    user_id = get_user_from_token()
    if not user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        submission_id = data.get('submissionId')
        service_type = data.get('type', 'ASSISTED')  # DIY or ASSISTED
        additional_services = data.get('additionalServices', [])
        
        # Calculate total amount
        base_price = PRICING.get(service_type, 299)
        services_total = sum(PRICING['services'].get(s, 0) for s in additional_services)
        total_amount = base_price + services_total
        
        # Get user info
        user = STUDY_USER_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Create line items for Stripe
        line_items = [
            {
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': f'{service_type} Business Registration',
                        'description': f'Business registration service in Georgia - {service_type}',
                    },
                    'unit_amount': base_price * 100,  # Stripe uses cents
                },
                'quantity': 1,
            }
        ]
        
        # Add additional services as line items
        for service in additional_services:
            service_price = PRICING['services'].get(service, 0)
            if service_price > 0:
                service_names = {
                    'ein': 'EIN Application',
                    'registered-agent': 'Registered Agent Service (1 Year)',
                    'operating-agreement': 'Operating Agreement',
                    'business-license': 'Business License Research',
                    'expedited-processing': 'Expedited Processing',
                    'document-review': 'Document Review & Consultation'
                }
                line_items.append({
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': service_names.get(service, service),
                        },
                        'unit_amount': service_price * 100,
                    },
                    'quantity': 1,
                })
        
        # Create Stripe Checkout Session
        frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=line_items,
            mode='payment',
            success_url=f"{frontend_url}/success?session_id={{CHECKOUT_SESSION_ID}}&type={service_type.lower()}&submissionId={submission_id}",
            cancel_url=f"{frontend_url}/success?cancelled=true&type={service_type.lower()}",
            customer_email=user.get('email'),
            metadata={
                'user_id': user_id,
                'submission_id': submission_id or '',
                'service_type': service_type,
                'additional_services': ','.join(additional_services)
            }
        )
        
        # Create pending transaction record
        transaction = {
            'userId': user_id,
            'submissionId': submission_id,
            'stripeSessionId': checkout_session.id,
            'type': service_type,
            'additionalServices': additional_services,
            'amount': total_amount,
            'currency': 'usd',
            'status': 'pending',
            'createdAt': datetime.datetime.utcnow().isoformat(),
            'updatedAt': datetime.datetime.utcnow().isoformat()
        }
        TRANSACTIONS_Collection.insert_one(transaction)
        
        return jsonify({
            'success': True,
            'data': {
                'sessionId': checkout_session.id,
                'url': checkout_session.url
            }
        })
        
    except stripe.error.StripeError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        print(f"Error creating checkout session: {e}")
        return jsonify({'success': False, 'error': 'Failed to create payment session'}), 500


@payments_bp.route('/webhook', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhook events - This is the SECURE way to update payment status"""
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        # Invalid payload
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return jsonify({'error': 'Invalid signature'}), 400
    
    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        handle_successful_payment(session)
    elif event['type'] == 'checkout.session.expired':
        session = event['data']['object']
        handle_expired_payment(session)
    elif event['type'] == 'payment_intent.payment_failed':
        payment_intent = event['data']['object']
        handle_failed_payment(payment_intent)
    
    return jsonify({'received': True})


def handle_successful_payment(session):
    """Handle successful payment - Update transaction and submission status"""
    stripe_session_id = session['id']
    metadata = session.get('metadata', {})
    user_id = metadata.get('user_id')
    submission_id = metadata.get('submission_id')
    
    now = datetime.datetime.utcnow().isoformat()
    
    # Update transaction status
    TRANSACTIONS_Collection.update_one(
        {'stripeSessionId': stripe_session_id},
        {
            '$set': {
                'status': 'completed',
                'stripePaymentIntentId': session.get('payment_intent'),
                'paidAt': now,
                'updatedAt': now
            }
        }
    )
    
    # Create payment record
    payment = {
        'userId': user_id,
        'submissionId': submission_id,
        'stripeSessionId': stripe_session_id,
        'stripePaymentIntentId': session.get('payment_intent'),
        'amount': session.get('amount_total', 0) / 100,  # Convert from cents
        'currency': session.get('currency', 'usd'),
        'status': 'succeeded',
        'paymentMethod': 'card',
        'customerEmail': session.get('customer_email'),
        'createdAt': now
    }
    PAYMENTS_Collection.insert_one(payment)
    
    # Update submission status to "paid" / "processing"
    if submission_id:
        FORM_SUBMISSION_Collection.update_one(
            {'submissionId': submission_id},
            {
                '$set': {
                    'paymentStatus': 'paid',
                    'status': 'processing',
                    'paidAt': now,
                    'lastUpdated': now
                },
                '$push': {
                    'timeline': {
                        'status': 'payment_received',
                        'message': 'Payment received successfully',
                        'timestamp': now
                    }
                }
            }
        )


def handle_expired_payment(session):
    """Handle expired payment session"""
    stripe_session_id = session['id']
    now = datetime.datetime.utcnow().isoformat()
    
    TRANSACTIONS_Collection.update_one(
        {'stripeSessionId': stripe_session_id},
        {
            '$set': {
                'status': 'expired',
                'updatedAt': now
            }
        }
    )


def handle_failed_payment(payment_intent):
    """Handle failed payment"""
    now = datetime.datetime.utcnow().isoformat()
    
    # Find transaction by payment intent
    TRANSACTIONS_Collection.update_one(
        {'stripePaymentIntentId': payment_intent['id']},
        {
            '$set': {
                'status': 'failed',
                'failureMessage': payment_intent.get('last_payment_error', {}).get('message', 'Payment failed'),
                'updatedAt': now
            }
        }
    )


@payments_bp.route('/verify-session/<session_id>', methods=['GET'])
def verify_session(session_id):
    """Verify a checkout session status and update payment status if paid"""
    user_id = get_user_from_token()
    if not user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    try:
        # Get session from Stripe
        session = stripe.checkout.Session.retrieve(session_id)
        
        # Verify the session belongs to this user
        if session.metadata.get('user_id') != user_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        submission_id = session.metadata.get('submission_id')
        payment_status = session.payment_status
        
        # If payment is complete, update the database
        # This handles cases where webhook didn't fire (local dev without Stripe CLI)
        if payment_status == 'paid':
            now = datetime.datetime.utcnow().isoformat()
            
            # Update transaction status
            TRANSACTIONS_Collection.update_one(
                {'stripeSessionId': session_id},
                {
                    '$set': {
                        'status': 'completed',
                        'stripePaymentIntentId': session.payment_intent,
                        'paidAt': now,
                        'updatedAt': now
                    }
                }
            )
            
            # Update submission payment status
            if submission_id:
                # Check if already updated to avoid duplicate timeline entries
                existing = FORM_SUBMISSION_Collection.find_one({'submissionId': submission_id})
                if existing and existing.get('paymentStatus') != 'paid':
                    FORM_SUBMISSION_Collection.update_one(
                        {'submissionId': submission_id},
                        {
                            '$set': {
                                'paymentStatus': 'paid',
                                'status': 'processing',
                                'paidAt': now,
                                'lastUpdated': now
                            },
                            '$push': {
                                'timeline': {
                                    'status': 'payment_received',
                                    'message': 'Payment received successfully',
                                    'timestamp': now
                                }
                            }
                        }
                    )
        
        return jsonify({
            'success': True,
            'data': {
                'status': payment_status,
                'submissionId': submission_id,
                'amount': session.amount_total / 100 if session.amount_total else 0
            }
        })
        
    except stripe.error.StripeError as e:
        print(f"Stripe error verifying session: {e}")
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        print(f"Error verifying session: {e}")
        return jsonify({'success': False, 'error': 'Failed to verify session'}), 500


@payments_bp.route('/sync-payment/<submission_id>', methods=['POST'])
def sync_payment_status(submission_id):
    """Manually sync payment status from Stripe for a submission"""
    user_id = get_user_from_token()
    if not user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    try:
        # Find the transaction for this submission
        transaction = TRANSACTIONS_Collection.find_one({
            'submissionId': submission_id,
            'userId': user_id
        })
        
        if not transaction:
            return jsonify({'success': False, 'error': 'No transaction found for this submission'}), 404
        
        stripe_session_id = transaction.get('stripeSessionId')
        if not stripe_session_id:
            return jsonify({'success': False, 'error': 'No Stripe session found'}), 404
        
        # Get session from Stripe
        session = stripe.checkout.Session.retrieve(stripe_session_id)
        
        now = datetime.datetime.utcnow().isoformat()
        
        if session.payment_status == 'paid':
            # Update transaction
            TRANSACTIONS_Collection.update_one(
                {'_id': transaction['_id']},
                {
                    '$set': {
                        'status': 'completed',
                        'stripePaymentIntentId': session.payment_intent,
                        'paidAt': now,
                        'updatedAt': now
                    }
                }
            )
            
            # Update submission
            FORM_SUBMISSION_Collection.update_one(
                {'submissionId': submission_id},
                {
                    '$set': {
                        'paymentStatus': 'paid',
                        'status': 'processing',
                        'paidAt': now,
                        'lastUpdated': now
                    },
                    '$push': {
                        'timeline': {
                            'status': 'payment_synced',
                            'message': 'Payment status synced from Stripe',
                            'timestamp': now
                        }
                    }
                }
            )
            
            return jsonify({
                'success': True,
                'message': 'Payment status synced successfully',
                'data': {
                    'paymentStatus': 'paid',
                    'amount': session.amount_total / 100 if session.amount_total else 0
                }
            })
        else:
            return jsonify({
                'success': True,
                'message': 'Payment not yet completed',
                'data': {
                    'paymentStatus': session.payment_status
                }
            })
            
    except stripe.error.StripeError as e:
        print(f"Stripe error syncing payment: {e}")
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        print(f"Error syncing payment: {e}")
        return jsonify({'success': False, 'error': 'Failed to sync payment'}), 500


@payments_bp.route('/user-transactions', methods=['GET'])
def get_user_transactions():
    """Get all transactions for the authenticated user"""
    user_id = get_user_from_token()
    if not user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        skip = (page - 1) * limit
        
        transactions_cursor = TRANSACTIONS_Collection.find(
            {'userId': user_id}
        ).sort('createdAt', -1).skip(skip).limit(limit)
        
        total = TRANSACTIONS_Collection.count_documents({'userId': user_id})
        
        transactions = []
        for t in transactions_cursor:
            transactions.append({
                'id': str(t['_id']),
                'submissionId': t.get('submissionId'),
                'type': t.get('type'),
                'amount': t.get('amount'),
                'currency': t.get('currency'),
                'status': t.get('status'),
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

