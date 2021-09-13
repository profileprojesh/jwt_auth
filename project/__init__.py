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




def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
    app.config.from_object("config.DevelopmentConfig")
    db.init_app(app)
    return app


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = 'views.login_view'
login_manager.init_app(app)
bcrypt.init_app(app)

from .models import User
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
from project.views import auth_blueprint
app.register_blueprint(auth_blueprint)



