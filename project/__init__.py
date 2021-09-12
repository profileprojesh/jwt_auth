from logging import DEBUG
import bcrypt
from flask import Flask, app
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_manager
db = SQLAlchemy()
bcrypt = Bcrypt()

app = Flask(__name__)
app.config.from_object("config.DevelopmentConfig")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'




"""
This function is used to just create database tables and after that it should be commented out and uncomment the code below this function
"""
# def create_app():
#     db.init_app(app)
#     login_manager = LoginManager()
#     login_manager.login_view = 'views.login_view'
#     login_manager.init_app(app)
#     bcrypt.init_app(app)

#     from project.views import auth_blueprint
#     app.register_blueprint(auth_blueprint)
#     return app




db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = 'views.login_view'
login_manager.init_app(app)
bcrypt.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'views.login_view'
login_manager.init_app(app)

from .models import User
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


from project.views import auth_blueprint
app.register_blueprint(auth_blueprint)
