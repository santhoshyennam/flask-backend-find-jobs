from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import config

# flask db init
# flask db migrate
# flask db upgrade
# flask shell 
# pip freeze > requirements.txt
# pip install -r requirements.txt


db = SQLAlchemy()
SECRET_KEY = 'mscs3150'

def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    db.init_app(app)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
