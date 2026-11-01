from flask import jsonify

def authenticate_request(request):
    token = request.headers.get('Authorization', '')
    return None
