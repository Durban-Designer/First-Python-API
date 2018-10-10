# project/server/config.py

import os
basedir = os.path.abspath(os.path.dirname(__file__))
postgres_local_base = 'postgresql:///'
database_name = 'testDB'


class BaseConfig:
    SECRET_KEY = os.getenv('SECRET_KEY', 'TheKeyToDataYes')
    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = postgres_local_base + database_name


class ProductionConfig(BaseConfig):
    SECRET_KEY = 'TheKeyToDataYes'
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'postgresql:///minify'
