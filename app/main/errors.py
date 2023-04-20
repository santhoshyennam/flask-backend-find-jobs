
from .utils import generate_error_response
from . import main


    
# Error Handling routes
@main.errorhandler(404)
def page_not_found(e):
    return generate_error_response(str(e)), 404

@main.errorhandler(405)
def page_not_found(e):
    return generate_error_response(str(e)), 405

@main.errorhandler(400)
def bad_request_error(error):
    return generate_error_response(str(error)), 400

@main.errorhandler(500)
def internal_server_error(e):
    return 'Internal Server Error',500