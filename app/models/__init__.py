from flask import Blueprint

model = Blueprint('models',__name__)

from .user import User
from .manager import Manager
from .category import Category
from .job import Job