
import json
from operator import or_
from flask import Response, g, request
from . import main
from app import db
from app.models import Job
from .utils import generate_error_response
from .utils import check_manager_token


# Jobs routes
@main.route("/jobs", methods = ["GET"])
def get_all_jobs():
    jobs = Job.query.all()
    job = json.dumps([job.to_dict() for job in jobs])
    return Response(job, mimetype='application/json')

@main.route("/jobs/filter", methods = ["GET"])
def filter_jobs():
    if "filter_text" not in request.json:
        return generate_error_response("filter_text is not found")
    else:
        # Get filter_text for filtering
        filter_text = request.json.get('filter_text')
        # Build filter criteria based on query parameters
        filters = or_(Job.title.ilike(f'%{filter_text}%'),or_(Job.category_id.ilike(f'%{filter_text}%'),Job.description.ilike(f'%{filter_text}%')))
        # Query database with filters
        jobs = Job.query.filter(filters).all()
        if not jobs:
            return generate_error_response('no match is found'), 400
        # Serialize jobs to JSON and return as response
        return Response(json.dumps([job.to_dict() for job in jobs]), mimetype='application/json'), 200

@main.route("/job", methods = ["GET"])
def get_job():
    if "job_id" not in request.args:
        return generate_error_response("job_id is not found in query parameters")
    else:
        job_id =  request.args.get('job_id')
        job = Job.query.get(job_id)
        if not job:
            return generate_error_response('job is not found'), 400
        return Response(json.dumps(job.to_dict()), mimetype='application/json') 

@main.route("/create-job", methods = ["POST"])
@check_manager_token
def create_job():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    if "title" in request.json and "salary" in request.json and "company" in request.json and "category_id" in request.json and "description" in request.json and "email" in request.json and "created_by" in request.json:
        data = request.get_json()
        new_job = Job(title=data['title'], salary=data['salary'], company=data["company"], category_id=data["category_id"], description=data["description"], email=data["email"],created_by=data["created_by"])
        db.session.add(new_job)
        db.session.commit()
        return Response(json.dumps(new_job.to_dict()), mimetype='application/json'),201
    else:
        return generate_error_response("some fields are missing in the request body")

@main.route("/delete-job", methods = ["DELETE"])
@check_manager_token
def delete_job():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    if "job_id" not in request.args:
        return generate_error_response("job_id is not found in query parameters")
    else:
        job_id =  request.args.get('job_id')
        job = Job.query.get(job_id)
        if not job:
            return generate_error_response('job is not found'), 400
        db.session.delete(job)
        db.session.commit()
        return Response(json.dumps({'success': 'job deleted successfully',"job_id":job_id})), 200  

@main.route("/edit-job", methods = ["PATCH"])
@check_manager_token
def edit_job():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    if "job_id" in request.json:
        job_id = request.json.get("job_id")
        # Retrieve the record to be updated
        job = Job.query.get(job_id)
        if not job:
            return generate_error_response('job is not found'), 400
        # Update the record attributes
        job.title = request.json.get('title',job.title)
        job.salary = request.json.get('salary',job.salary)
        job.company = request.json.get('company',job.company)
        job.category_id = request.json.get('category_id',job.category_id)
        job.description = request.json.get('description',job.description)
        job.email = request.json.get('email',job.email)

        # Commit the transaction to save changes to the database
        db.session.commit()
        return Response(json.dumps({'success': 'job updated successfully',"job_id":job_id})), 200 
    else:
        return generate_error_response("job_id is not found in the request body")