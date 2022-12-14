from flask_login import UserMixin
from db import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # Primary keys are requred by SQLAlchemy
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))