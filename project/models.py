import jwt
import datetime
from flask_login import UserMixin

from . import db, bcrypt, app

class User(UserMixin,db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    address = db.Column(db.String(255))

    def __init__(self,email, password,name,address):
        self.email = email
        self.password = bcrypt.generate_password_hash(password,app.config.get('BCRYPT_LOG_ROUNDS')).decode()
        self.name = name
        self.address = address
    


    def encode_auth_token(self,user_id, key):
        try:
            payload = {
                'sub':user_id,
                'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
            }
            return jwt.encode(
                payload,
                key,
                algorithm="RS256"
            )
        except Exception as e:
            return e
    

    @staticmethod
    def decode_auth_token(auth_token, public_key):
        try:
            payload = jwt.decode(auth_token,public_key, algorithms="RS256")
            return payload['sub']
        
        except jwt.ExpiredSignatureError:
            return 'expired'
        except jwt.InvalidTokenError:
            return 'invalid'


class UserKeys(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user = db.Column(db.String(255), unique=True, nullable=False)
    private_key = db.Column(db.String(500), nullable=False)
    public_key = db.Column(db.String(500), nullable=False)

    def __init__(self,user,private_key, public_key):
        self.user = user
        self.private_key = private_key
        self.public_key = public_key
    
    def __repr__(self):
        return self.user
    



