import os
from flask import Flask
from app.routes import main
from app.auth import auth_bp

def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv("SECRET_KEY", "fallback-key")
    app.register_blueprint(main)
    app.register_blueprint(auth_bp)
    return app