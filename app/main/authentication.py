import datetime
import json
from flask import Response, request
import jwt
from . import main
from app import db,SECRET_KEY
from app.models import User,Manager
from .utils import generate_error_response
from werkzeug.security import generate_password_hash, check_password_hash

@main.route("/", methods = ["GET"])
def home():
    return "hello world"

@main.route("/login", methods = ["GET"])
def login():
    if "email" in request.json and "password" in request.json:
            # if manager trying to login
            if "is_manager" in request.json and request.json["is_manager"] == True:
                manager = Manager.query.filter_by(email=request.json["email"]).first()
                if not manager or not check_password_hash(manager.password, request.json["password"]):
                    return generate_error_response("Invalid Credentials"), 401
                token = jwt.encode({
                    'id': manager.id,
                    'is_manager': True,
                    'exp': datetime.datetime.utcnow().timestamp() + 3600
                }, SECRET_KEY)
                return Response(json.dumps({'access_token': token, 'manager': manager.to_dict(), "is_manager":True})), 200
            else:  # user is trying to login
                user = User.query.filter_by(email=request.json["email"]).first()
                if not user or not check_password_hash(user.password, request.json["password"]):
                    return generate_error_response("Invalid Credentials"), 401
                token = jwt.encode({
                    'id': user.id,
                    'is_manager': False,
                    'exp': datetime.datetime.utcnow().timestamp() + 3600
                }, SECRET_KEY)
                return Response(json.dumps({'access_token': token, 'user': user.to_dict(), "is_manager": False})), 200
    else:
        return generate_error_response("some fields are missing in the request")

# signup for user
@main.route("/signup", methods=["POST"])
def signup():
    if "name" in request.json and "mobile" in request.json and "age" in request.json and "email" in request.json and "address" in request.json and "date_of_birth" in request.json and "password" in request.json and "is_manager" in request.json:
        data = request.get_json()
        if data["is_manager"] == True:
            manager = Manager.query.filter_by(email=request.json["email"]).first()
            if manager:
                return generate_error_response('Email is already taken'), 400
            new_manager = Manager(name=data['name'], age=data['age'], mobile=data["mobile"], email=data["email"], address=data["address"], date_of_birth=data["date_of_birth"],password=generate_password_hash(data["password"]))
            db.session.add(new_manager)
            db.session.commit()
            return Response(json.dumps(new_manager.to_dict()), mimetype='application/json'),201
        else:
            user = User.query.filter_by(email=request.json["email"]).first()
            if user:
                return generate_error_response('Email is already taken'), 400
            new_user = User(name=data['name'], age=data['age'], mobile=data["mobile"], email=data["email"], address=data["address"], date_of_birth=data["date_of_birth"],password=generate_password_hash(data["password"]))
            db.session.add(new_user)
            db.session.commit()
            return Response(json.dumps(new_user.to_dict()), mimetype='application/json'),201

    else:
        return generate_error_response("some fields are missing in the request")

@main.route("/logout", methods = ["GET"])
def logout():
    response = json.dumps({'message': 'Logged out successfully'})
    response.set_cookie('access_token', '', expires=0, secure=True, httponly=True)
    return response, 200
