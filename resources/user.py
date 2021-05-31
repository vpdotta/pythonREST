import traceback

from flask_restful import Resource, reqparse
from flask import make_response, render_template
from flask_jwt_extended import create_access_token, jwt_required, get_jwt
from hmac import compare_digest

from blacklist import BLACKLIST
from models.user import UserModel

attrs = reqparse.RequestParser()
attrs.add_argument('login', type=str, required=True, help="The field 'login' cannot be left blank.")
attrs.add_argument('password', type=str, required=True, help="The field 'password' cannot be left blank.")
attrs.add_argument('email', type=str)
attrs.add_argument('active', type=bool)


class User(Resource):
    # /users/{user_id}
    def get(self, user_id):
        user = UserModel.find_user(user_id)
        if user:
            return user.json()
        return {'message': 'User not found.'}, 404

    @jwt_required()
    def delete(self, user_id):
        user = UserModel.find_user(user_id)
        if user:
            user.delete_user()
            return {'message': 'User deleted.'}
        return {'message': 'User not found.'}, 404


class UserRegister(Resource):
    # /register
    def post(self):
        data = attrs.parse_args()
        if not data.get('email') or data.get('email') is None:
            return {"message": "The field 'email' cannot be left blank."}, 400

        if UserModel.find_by_email(data['email']):
            return {"message": "The email '{}' already exists.".format(data['email'])}, 400

        if UserModel.find_by_login(data['login']):
            return {"message": "The login '{}' already exists.".format(data['login'])}, 400  # Bad Request

        user = UserModel(**data)
        user.active = False
        try:
            user.save_user()
            user.send_confirmation_email()
        except:
            user.delete_user()
            traceback.print_exc()
            return {'message': 'An internal server error has ocurred.'}, 500
        return {'message': 'User created successfully!'}, 201  # Created


class UserLogin(Resource):
    # /login
    @classmethod
    def post(cls):
        data = attrs.parse_args()

        user = UserModel.find_by_login(data['login'])

        if user and compare_digest(user.password, data['password']):
            token = create_access_token(identity=user.user_id)
            return {'access_token': token}, 200
        return {'message': 'The username or password is incorrect.'}, 401  # Unauthorized


class UserLogout(Resource):
    # /logout
    @jwt_required
    def post(self):
        jwt_id = get_jwt()['jti']  # JWT Token Identifier
        BLACKLIST.add(jwt_id)
        return {'message': 'Logged out successfully!'}, 200


class UserConfirm(Resource):
    # /confirm/{user_id}
    @classmethod
    def get(cls, user_id):
        user = UserModel.find_user(user_id)

        if not user:
            return {"message": "User id '{}' not found.".format(user_id)}, 404

        user.active = True
        user.save_user()
        # return {"message": "User id '{}' confirmed successfully.".format(user_id)}, 200
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('user_confirm.html', email=user.email, user=user.login), 200, headers)
