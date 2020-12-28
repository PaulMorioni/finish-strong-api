from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_restful import Resource, Api
from flask_marshmallow import Marshmallow

db = SQLAlchemy()
ma = Marshmallow()


def create_app():
    app = Flask(__name__)
    CORS(app, resources={r"/api/*"})
    app.config.from_pyfile('config.py')
    db.init_app(app)
    ma.init_app(app)
    from .controller import main
    app.register_blueprint(main)

    return app
