import json
from operator import or_
from flask import Response, g, request
from . import main
from app import db
from app.models import Manager
from .utils import check_manager_token, generate_error_response
from werkzeug.security import generate_password_hash


# Manager routes
@main.route("/managers", methods = ["GET"])
@check_manager_token
def get_all_managers():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    managers = Manager.query.all()
    all_managers = json.dumps([manager.to_dict() for manager in managers])
    return Response(all_managers, mimetype='application/json')

@main.route("/manager", methods = ["GET"])
@check_manager_token
def get_manager():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    if "manager_id" not in request.args:
        return generate_error_response("manager_id is not found in query parameters")
    else:
        manager_id =  request.args.get('manager_id')
        manager = Manager.query.get(manager_id)
        if not manager:
            return generate_error_response('manager is not found'), 400
        return Response(json.dumps(manager.to_dict()), mimetype='application/json')  

@main.route("/managers/filter", methods = ["GET"])
@check_manager_token
def filter_managers():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    if "filter_text" not in request.json:
        return generate_error_response("filter_text is not found")
    else:
         # Get filter_text for filtering
        filter_text = request.json.get('filter_text')
        
         # Build filter criteria based on query parameters
        filters = or_(Manager.name.ilike(f'%{filter_text}%'),Manager.email.ilike(f'%{filter_text}%'))
        # Query database with filters
        managers = Manager.query.filter(filters).all()
        if not managers:
            return generate_error_response('no match is found'), 400
        # Serialize managers to JSON and return as response
        return Response(json.dumps([manager.to_dict() for manager in managers]), mimetype='application/json'), 200


@main.route("/create-manager", methods = ["POST"])
def create_manager():
    if "name" in request.json and "mobile" in request.json and "age" in request.json and "email" in request.json and "address" in request.json and "date_of_birth" in request.json and "password" in request.json:
        data = request.get_json()
        manager = Manager.query.filter_by(email=request.json["email"]).first()
        if manager:
            return generate_error_response('Email is already taken'), 400
        new_manager = Manager(name=data['name'], age=data['age'], mobile=data["mobile"], email=data["email"], address=data["address"], date_of_birth=data["date_of_birth"],password=generate_password_hash(data["password"]))
        db.session.add(new_manager)
        db.session.commit()
        return Response(json.dumps(new_manager.to_dict()), mimetype='application/json'),201
    else:
        return generate_error_response("some fields are missing in the request body")

@main.route("/delete-manager", methods = ["DELETE"])
@check_manager_token
def delete_manager():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    if "manager_id" not in request.args:
        return generate_error_response("manager_id is not found in query parameters")
    else:
        manager_id =  request.args.get('manager_id')
        manager = Manager.query.get(manager_id)
        if not manager:
            return generate_error_response('manager is not found'), 400
        db.session.delete(manager)
        db.session.commit()
        return Response(json.dumps({'success': 'Manager deleted successfully','manager_id':manager_id})), 200 

@main.route("/edit-manager", methods = ["PATCH"])
@check_manager_token
def edit_manager():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    if "manager_id" not in request.json:
        return generate_error_response("manager_id is not found in the request body")
    elif "email" in request.json:
        return generate_error_response("Email cannot be changed once registered! Remove email from request body.")
    else:
        manager_id = request.json.get("manager_id")
        # Retrieve the record to be updated
        manager = Manager.query.get(manager_id)
        if not manager:
            return generate_error_response('manager is not found'), 400
        
        manager = Manager.query.filter_by(email=request.json["email"]).filter_by(id != manager_id).first()
        if manager:
            return generate_error_response('Email is already taken'), 400
        # Update the record attributes
        manager.name = request.json.get('name',manager.name)
        manager.mobile = request.json.get('mobile',manager.mobile)
        manager.age = request.json.get('age',manager.age)
        # manager.email = request.json.get('email',manager.email)
        manager.address = request.json.get('address',manager.address)
        manager.date_of_birth = request.json.get('date_of_birth',manager.date_of_birth)
        manager.password = request.json.get('password',manager.password)

        # Commit the transaction to save changes to the database
        db.session.commit()
        return Response(json.dumps({'success': 'manager updated successfully',"manager_id":manager_id})), 200 
