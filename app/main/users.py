import json
from operator import or_
from flask import Response, g, request
from . import main
from app import db
from app.models import User
from .utils import check_manager_token, generate_error_response,check_token
from werkzeug.security import generate_password_hash


# User routes

@main.route("/users", methods = ["GET"])
@check_token
def get_all_users():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    users = User.query.all()
    all_users = json.dumps([user.to_dict() for user in users])
    return Response(all_users, mimetype='application/json')

@main.route("/user", methods = ["GET"])
@check_token
def get_user():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    if "user_id" not in request.args:
        return generate_error_response("user_id is not found in query parameters")
    else:
        user_id =  request.args.get('user_id')
        user = User.query.get(user_id)
        if not user:
            return generate_error_response('user is not found'), 400
        return Response(json.dumps(user.to_dict()), mimetype='application/json') 

@main.route("/create-user", methods = ["POST"])
def create_user():
    if "name" in request.json and "mobile" in request.json and "age" in request.json and "email" in request.json and "address" in request.json and "date_of_birth" in request.json and "password" in request.json:
        data = request.get_json()
        user = User.query.filter_by(email=request.json["email"]).first()
        if user:
            return generate_error_response('Email is already taken'), 400
        new_user = User(name=data['name'], age=data['age'], mobile=data["mobile"], email=data["email"], address=data["address"], date_of_birth=data["date_of_birth"],password= generate_password_hash(data["password"]))
        db.session.add(new_user)
        db.session.commit()
        return Response(json.dumps(new_user.to_dict()), mimetype='application/json'),201
    else:
        return generate_error_response("some fields are missing in the request body")


@main.route("/delete-user", methods = ["DELETE"])
@check_manager_token
def delete_user():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    if "user_id" not in request.args:
        return generate_error_response("user_id is not found in query parameters")
    else:
        user_id =  request.args.get('user_id')
        user = User.query.get(user_id)
        if not user:
            return generate_error_response('user is not found'), 400
        db.session.delete(user)
        db.session.commit()
        return Response(json.dumps({'success': 'user deleted successfully',"user_id":user_id})), 200 

@main.route("/edit-user", methods = ["PATCH"])
@check_token
def edit_user():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    if "user_id" not in request.json:
        return generate_error_response("user_id is not found in the request body")
    elif "email" in request.json:
        return generate_error_response("Email cannot be changed once registered! Remove email from request body.")
    else:
        user_id = request.json.get("user_id")
        # Retrieve the record to be updated
        user = User.query.get(user_id)
        if not user:
            return generate_error_response('user is not found'), 400
        
        # Update the record attributes
        user.name = request.json.get('name',user.name)
        user.mobile = request.json.get('mobile',user.mobile)
        user.age = request.json.get('age',user.age)
        # user.email = request.json.get('email',user.email)
        user.address = request.json.get('address',user.address)
        user.date_of_birth = request.json.get('date_of_birth',user.date_of_birth)
        user.password = request.json.get('password',user.password)

        # Commit the transaction to save changes to the database
        db.session.commit()
        return Response(json.dumps({'success': 'user updated successfully',"user_id":user_id})), 200 

@main.route("/users/filter", methods = ["GET"])
@check_token
def filter_users():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    if "filter_text" not in request.json:
        return generate_error_response("filter_text is not found")
    else:
         # Get filter_text for filtering
        filter_text = request.json.get('filter_text')
        
        # Build filter criteria based on query parameters
        filters = or_(User.name.ilike(f'%{filter_text}%'),User.email.ilike(f'%{filter_text}%'))
        # Query database with filters
        users = User.query.filter(filters).all()
        if not users:
            return generate_error_response('no users is found'), 400
        # Serialize users to JSON and return as response
        return Response(json.dumps([user.to_dict() for user in users]), mimetype='application/json'), 200