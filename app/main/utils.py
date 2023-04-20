


import datetime
from functools import wraps
import json
from flask import Response, g, request
import jwt
from app import SECRET_KEY

def generate_error_response(message):
    # error = json.dumps({ "error": message, "errorCode": 404})
    error = json.dumps({ "error": message})
    return Response(error,mimetype="application/json")

# Authentication routes

# define the middleware to check for JWT token
def check_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            if 'exp' in data and datetime.datetime.utcnow().timestamp() > data['exp']:
                return generate_error_response('Token has expired'), 401
            g.user = data['id']
        except:
            g.user = None
        return func(*args, **kwargs)
    return wrapped

# define the middleware to check for JWT token
def check_manager_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            if 'exp' in data and datetime.datetime.utcnow().timestamp() > data['exp']:
                return generate_error_response('Token has expired'), 401
            if not data['is_manager']:
                return generate_error_response('UnAuthorized Access'),401
            g.user = data['id']
        except:
            g.user = None
        return func(*args, **kwargs)
    return wrapped