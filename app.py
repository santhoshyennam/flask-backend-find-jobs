import datetime
from functools import wraps
import json
from flask import Flask, Response, g, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mscs3150'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/flaskexample'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=24)  # Set access token expiration to 7 days
db = SQLAlchemy(app)
migrate = Migrate(app,db)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    age = db.Column(db.Integer)
    mobile = db.Column(db.String(15))
    email = db.Column(db.String(50))
    date_of_birth = db.Column(db.String(20))
    address = db.Column(db.String(200))
    password = db.Column(db.String(200))
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'age': self.age,
            'mobile': self.mobile,
            'email': self.email,
            'date_of_birth': self.date_of_birth,
            'address': self.address
        }


class Job(db.Model):
    __tablename__ = 'jobs'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    salary = db.Column(db.String(20))
    company = db.Column(db.String(200))
    category = db.Column(db.String(50))
    description = db.Column(db.String(2000))
    email = db.Column(db.String(50))
    created_by = db.Column(db.Integer, db.ForeignKey('managers.id'), nullable=False)
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'salary': self.salary,
            'company': self.company,
            'category': self.category,
            'description': self.description,
            'email': self.email,
            'created_by': self.created_by
            # "manager": self.created_by.to_dict()
        }

class Manager(db.Model):
    __tablename__ = 'managers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    age = db.Column(db.Integer)
    mobile = db.Column(db.String(15))
    email = db.Column(db.String(50))
    date_of_birth = db.Column(db.String(20))
    address = db.Column(db.String(200))
    password = db.Column(db.String(200)) 
    # jobs = db.relationship('Job', backref='manager', lazy=True)
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'age': self.age,
            'mobile': self.mobile,
            'email': self.email,
            'date_of_birth': self.date_of_birth,
            'address': self.address,
            # "job": [job.to_dict() for job in self.jobs]
        }   


# Authentication routes

# define the middleware to check for JWT token
def check_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
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
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            if 'exp' in data and datetime.datetime.utcnow().timestamp() > data['exp']:
                return generate_error_response('Token has expired'), 401
            if not data['is_manager']:
                return generate_error_response('UnAuthorized Access'),401
            g.user = data['id']
        except:
            g.user = None
        return func(*args, **kwargs)
    return wrapped

@app.route("/login", methods = ["GET"])
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
                    'exp': datetime.datetime.utcnow().timestamp() + 40
                }, app.config['SECRET_KEY'])
                return Response(json.dumps({'access_token': token})), 200
            else:  # user is trying to login
                user = User.query.filter_by(email=request.json["email"]).first()
                if not user or not check_password_hash(user.password, request.json["password"]):
                    return generate_error_response("Invalid Credentials"), 401
                token = jwt.encode({
                    'id': user.id,
                    'is_manager': False,
                    'exp': datetime.datetime.utcnow().timestamp() + 40
                }, app.config['SECRET_KEY'])
                return Response(json.dumps({'access_token': token})), 200
    else:
        return generate_error_response("some fields are missing in the request")

# signup for user
@app.route("/signup", methods=["POST"])
def signup():
    if "name" in request.json and "mobile" in request.json and "age" in request.json and "email" in request.json and "address" in request.json and "date_of_birth" in request.json and "password" in request.json:
        data = request.get_json()
        user = User.query.filter_by(email=request.json["email"]).first()
        if user:
            return generate_error_response('Email is already taken'), 400
        new_user = User(name=data['name'], age=data['age'], mobile=data["mobile"], email=data["email"], address=data["address"], date_of_birth=data["date_of_birth"],password=generate_password_hash(data["password"]))
        db.session.add(new_user)
        db.session.commit()
        return Response(json.dumps(new_user.to_dict()), mimetype='application/json'),201
    else:
        return generate_error_response("some fields are missing in the request")

@app.route("/logout", methods = ["GET"])
def logout():
    response = json.dumps({'message': 'Logged out successfully'})
    response.set_cookie('access_token', '', expires=0, secure=True, httponly=True)
    return response, 200

# Jobs routes
@app.route("/jobs", methods = ["GET"])
def get_all_jobs():
    jobs = Job.query.all()
    job = json.dumps([job.to_dict() for job in jobs])
    return Response(job, mimetype='application/json')

@app.route("/jobs/filter", methods = ["GET"])
def filter_jobs():
    if "filter_text" not in request.json:
        return generate_error_response("filter_text is not found")
    else:
        # Get filter_text for filtering
        filter_text = request.json.get('filter_text')
        # Build filter criteria based on query parameters
        filters = or_(Job.title.ilike(f'%{filter_text}%'),Job.category.ilike(f'%{filter_text}%'),Job.description.ilike(f'%{filter_text}%'))
        # Query database with filters
        jobs = Job.query.filter(filters).all()
        if not jobs:
            return generate_error_response('no match is found'), 400
        # Serialize jobs to JSON and return as response
        return Response(json.dumps({'jobs': [job.to_dict() for job in jobs]}), mimetype='application/json'), 200

@app.route("/job", methods = ["GET"])
def get_job():
    if "job_id" not in request.args:
        return generate_error_response("job_id is not found in query parameters")
    else:
        job_id =  request.args.get('job_id')
        job = Job.query.get_or_404(job_id)
        if not job:
            return generate_error_response('job is not found'), 400
        return Response(json.dumps(job.to_dict()), mimetype='application/json') 

@app.route("/create-job", methods = ["POST"])
@check_manager_token
def create_job():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    if "title" in request.json and "salary" in request.json and "company" in request.json and "category" in request.json and "description" in request.json and "email" in request.json and "created_by" in request.json:
        data = request.get_json()
        new_job = Job(title=data['title'], salary=data['salary'], company=data["company"], category=data["category"], description=data["description"], email=data["email"],created_by=data["created_by"])
        db.session.add(new_job)
        db.session.commit()
        return Response(json.dumps(new_job.to_dict()), mimetype='application/json'),201
    else:
        return generate_error_response("some fields are missing in the request body")

@app.route("/delete-job", methods = ["DELETE"])
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

@app.route("/edit-job", methods = ["PATCH"])
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
        job.category = request.json.get('category',job.category)
        job.description = request.json.get('description',job.description)
        job.email = request.json.get('email',job.email)

        # Commit the transaction to save changes to the database
        db.session.commit()
        return Response(json.dumps({'success': 'job updated successfully',"job_id":job_id})), 200 
    else:
        return generate_error_response("job_id is not found in the request body")

# Manager routes
@app.route("/managers", methods = ["GET"])
@check_manager_token
def get_all_managers():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    managers = Manager.query.all()
    all_managers = json.dumps([manager.to_dict() for manager in managers])
    return Response(all_managers, mimetype='application/json')

@app.route("/manager", methods = ["GET"])
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

@app.route("/managers/filter", methods = ["GET"])
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


@app.route("/create-manager", methods = ["POST"])
@check_manager_token
def create_manager():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
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

@app.route("/delete-manager", methods = ["DELETE"])
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

@app.route("/edit-manager", methods = ["PATCH"])
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


# User routes

@app.route("/users", methods = ["GET"])
@check_token
def get_all_users():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
    users = User.query.all()
    all_users = json.dumps([user.to_dict() for user in users])
    return Response(all_users, mimetype='application/json')

@app.route("/user", methods = ["GET"])
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

@app.route("/create-user", methods = ["POST"])
@check_manager_token
def create_user():
    if not g.user:
        return generate_error_response('UnAuthorize Access'),401
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


@app.route("/delete-user", methods = ["DELETE"])
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

@app.route("/edit-user", methods = ["PATCH"])
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

@app.route("/users/filter", methods = ["GET"])
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
    
# Error Handling routes
@app.errorhandler(404)
def page_not_found(e):
    return generate_error_response(str(e)), 404

@app.errorhandler(405)
def page_not_found(e):
    return generate_error_response(str(e)), 405

@app.errorhandler(400)
def bad_request_error(error):
    return generate_error_response(str(error)), 400

@app.errorhandler(500)
def internal_server_error(e):
    return 'Internal Server Error',500

def generate_error_response(message):
    # error = json.dumps({ "error": message, "errorCode": 404})
    error = json.dumps({ "error": message})
    return Response(error,mimetype="application/json")
