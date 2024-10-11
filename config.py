# config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_default_secret_key')
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:admin@localhost:5432/dropslim'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'calebewerneck@gmail.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'ukhu fpee aljp tuwn')  # Use uma variável de ambiente
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
