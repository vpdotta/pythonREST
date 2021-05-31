from flask_restful import Resource, reqparse
from models.user import UserModel
from flask_jwt_extended import create_access_token, jwt_required
from hmac import compare_digest

attrs = reqparse.RequestParser()
attrs.add_argument('login', type=str, required=True, help="The field 'login' cannot be left blank.")
attrs.add_argument('password', type=str, required=True, help="The field 'password' cannot be left blank.")

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

        if UserModel.find_by_login(data['login']):
            return {"message": "The login '{}' already exists.".format(data['login'])}

        user = UserModel(**data)
        user.save_user()
        return {'message': 'User created successfully!'}, 201 # Created

class UserLogin(Resource):
    # /login
    @classmethod
    def post(cls):
        data = attrs.parse_args()

        user = UserModel.find_by_login(data['login'])

        if user and compare_digest(user.password, data['password']):
            token = create_access_token(identity=user.user_id)
            return {'access_token': token}, 200
        return {'message': 'The username or password is incorrect.'}, 401 # Unauthorized
