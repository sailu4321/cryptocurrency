from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate  # ✅ Import Flask-Migrate

db = SQLAlchemy()
migrate = Migrate()  # ✅ Create a Migrate instance

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wallet.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    migrate.init_app(app, db)  # ✅ Initialize Flask-Migrate with app and db

    from .routes import main
    app.register_blueprint(main)

    return app  # ✅ Removed db.create_all() — not needed with migrations
