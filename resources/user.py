from flask.views import MethodView
from flask_smorest import Blueprint, abort
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from passlib.hash import pbkdf2_sha256
from flask_jwt_extended import create_access_token

from db import db
from models import UserModel
from schema import UserSchema

blp = Blueprint("Users", __name__, description="Operations on users")


@blp.route("/user/<int:user_id>")
class User(MethodView):
    @blp.response(200, UserSchema)
    def get(cls, user_id):
        user = UserModel.query.get_or_404(user_id)
        return user

    @blp.response(200, UserSchema)
    def delete(self, user_id):
        user = UserModel.query.get_or_404(user_id)

        db.session.delete(user)
        db.session.commit()
        return {"message": "User deleted.", "user": user}


@blp.route("/register")
class RegisterUser(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        user = UserModel(
            username=user_data["username"],
            password=pbkdf2_sha256.hash(user_data["password"]),
        )

        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            abort(400, message="An user with that name already exists.")
        except SQLAlchemyError:
            abort(500, message="An error occurred while registering the user.")

        return {"message": "User created successfully."}, 201


@blp.route("/login")
class LoginUser(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        user = UserModel.query.filter(
            UserModel.username == user_data["username"]
        ).first()

        if user and pbkdf2_sha256.verify(user_data["password"], user.password):
            access_token = create_access_token(identity=user.id)
            return {"access_token": access_token}

        abort(401, message="Invalid credentials.")
