from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
from flask_login import login_user, logout_user, current_user
from functools import wraps

from . import bcrypt, db
from .models import User, UserKeys
from .generate_rsaKey import get_keys

auth_blueprint = Blueprint('auth', __name__)


# register view where user is registered to database
class RegisterAPI(MethodView):
    """
    User Registration Resources
    """
    def post(self):
        post_data = request.get_json()
        # check if user already exists
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
            try:
                user = User(
                    email=post_data.get('email'),
                    password=post_data.get('password'),
                    name=post_data.get('name'),
                    address=post_data.get('address'),
                )
                db.session.add(user)
                db.session.commit()
                responseObject = {
                    'status': 'success',
                    'message': 'Sucessfully registered',
                }

                return make_response(jsonify(responseObject)), 201
            except Exception:
                responseObject = {
                    'status': 'fail',
                    'message': 'some error occured. Please try again'
                }

                return make_response(jsonify(responseObject)), 401

        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please log in'
            }
            return make_response(jsonify(responseObject)), 202


# view to handle login of user, verifying credientals and if valid it generates private and public key where public key is sent as response 
class LoginAPI(MethodView):
    def post(self):
        # get the post data
        post_data = request.get_json()
        if current_user.is_authenticated and current_user.email == post_data.get('email'):
            return make_response(jsonify("You are already been logged in")), 200
        if current_user.is_authenticated:
            logout_user()
        try:
            # fetch the user data
            user = User.query.filter_by(
                email=post_data.get('email')
            ).first()
            if user and bcrypt.check_password_hash(user.password, post_data.get('password')):
                user_key = UserKeys.query.filter_by(user=user.email).first()
                if user_key:
                    print("user present in database")
                    private_key = user_key.private_key
                    login_user(user)
                else:
                    private_key, public_key = get_keys()
                    login_user(user)
                    userkey = UserKeys(
                        user=user.email,
                        private_key=private_key,
                        public_key=public_key
                    )
                    db.session.add(userkey)
                    db.session.commit()
                auth_token = user.encode_auth_token(user.email,key=private_key)
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Sucessfully logged in',
                        'auth_token': auth_token
                    }
                    resp = make_response(jsonify(responseObject))
                    resp.headers['Authorization'] = auth_token
                    return (resp)
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(responseObject)), 404

        except Exception as e:
            return make_response(jsonify(e)),404


# This endpoint is used to check if app running status.
@auth_blueprint.route('/auth/check')
def check_api():
    return jsonify({'message': 'Running properly'})


# view to show profile of logged in user
class UserAPI(MethodView):

    def get(self):
        if current_user.is_anonymous:
            return make_response(jsonify("You are not authorised to view this page")), 404
        auth_header = request.headers.get('Authorization')
        user_id = current_user.email
        user_key = UserKeys.query.filter_by(user=user_id).first()
        if not user_key:
            return make_response(jsonify({"message":"User could not be found"})), 401
        public_key = user_key.public_key
        if auth_header:
            auth_token = auth_header
            resp = User.decode_auth_token(auth_token, public_key)
            if resp=='expired':
                db.session.delete(user_key)
                db.session.commit()
                logout_user()
                return make_response(jsonify({"message":"Your session has been expired. Please login again!"})), 401
            user = User.query.filter_by(email=resp).first()
            if resp =="invalid":
                 return make_response(jsonify({"message":"The token you have provided is invalid!"})), 403

            if user:
                responseObject = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'name': user.name,
                        'address': user.address
                    }
                }
                return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'some error has occued in accessing this page'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Auth token is not present in header'

            }
            return make_response(jsonify(responseObject)), 401


@auth_blueprint.route('/auth/logout', methods=['GET'])
def logout():
    if current_user.is_anonymous:
        return make_response(jsonify({"message":"Please login first to logout!!"})), 201

    user_id = current_user.email
    user_key = UserKeys.query.filter_by(user=user_id).first()
    if user_key:
        db.session.delete(user_key)
        db.session.commit()
    logout_user()
    return make_response(jsonify("You have been sucessfully logged out")), 200

        



# define tha API resources
registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
profile_view = UserAPI.as_view('user_api')

auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)

auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/profile',
    view_func=profile_view,
    methods=['GET']
)
