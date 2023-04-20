
import datetime
import json
from flask import Response, request
import jwt
from . import main
from app import db
from app.models import Category
from .utils import generate_error_response

@main.route("/categories", methods = ["GET"])
def get_all_categories():
    categories = Category.query.all()
    all_categories = json.dumps([category.to_dict() for category in categories])
    return Response(all_categories, mimetype='application/json')

@main.route("/category", methods = ["GET"])
def get_category():
    if "category_id" not in request.args:
        return generate_error_response("category_id is not found in query parameters")
    else:
        category_id =  request.args.get('category_id')
        category = Category.query.get(category_id)
        if not category:
            return generate_error_response('category is not found'), 400
        return Response(json.dumps(category.to_dict()), mimetype='application/json') 
    

@main.route("/create-category", methods = ["POST"])
def create_category():
    if "name" in request.json:
        data = request.get_json()
        new_category = Category(name=data['name'])
        db.session.add(new_category)
        db.session.commit()
        return Response(json.dumps(new_category.to_dict()), mimetype='application/json'),201
    else:
        return generate_error_response("some fields are missing in the request body")


@main.route("/delete-category", methods = ["DELETE"])
def delete_category():
    if "category_id" not in request.args:
        return generate_error_response("category_id is not found in query parameters")
    else:
        category_id =  request.args.get('category_id')
        category = Category.query.get(category_id)
        if not category:
            return generate_error_response('category is not found'), 400
        db.session.delete(category)
        db.session.commit()
        return Response(json.dumps({'success': 'category deleted successfully',"category_id":category_id})), 200 

@main.route("/edit-category", methods = ["PATCH"])
def edit_category():
    if "category_id" not in request.json:
        return generate_error_response("category_id is not found in the request body")
    else:
        category_id = request.json.get("category_id")
        # Retrieve the record to be updated
        category = Category.query.get(category_id)
        if not category:
            return generate_error_response('category is not found'), 400
        
        # Update the record attributes
        category.name = request.json.get('name',category.name)
        # Commit the transaction to save changes to the database
        db.session.commit()
        return Response(json.dumps({'success': 'category updated successfully',"category_id":category_id})), 200 