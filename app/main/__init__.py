from flask import Blueprint

main = Blueprint('main',__name__)

from . import errors, authentication,managers,users,utils,categories,jobs