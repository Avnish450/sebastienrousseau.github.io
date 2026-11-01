from flask import jsonify


def authenticate_request(request):
    # Security fix: validate authentication token
    token = request.headers.get('Authorization', '')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401
    if not validate_token(token.split(' ')[1]):
        return jsonify({'error': 'Invalid token'}), 403
    return None
