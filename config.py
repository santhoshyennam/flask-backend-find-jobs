import datetime
import os
baseDir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = 'mscs3150'
    SQLALCHEMY_DATABASE_URI = 'mysql://root:@localhost/jobfinder'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = "Jwt-key123"
    JWT_ACCESS_TOKEN_EXPIRES = datetime.timedelta(hours=24)
    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True

class ProductionConfig(Config):
    DEBUG = False

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}