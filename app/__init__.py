from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
import os

# Initialize database
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    # CORS(app)
    CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}}, 
     supports_credentials=True, 
     expose_headers=["Authorization"])

    # Configure the SQLite database
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # Configure your app here (e.g., database URI, secret key, etc.)
    app.config['JWT_SECRET_KEY'] = 'jude'  # Change this to a random secret key
    # app.config['UPLOAD_FOLDER'] = 'uploads/resumes'
    # app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads/resumes')
    app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'uploads', 'resumes')

    app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 16MB max file size

    # Initialize JWTManager
    jwt = JWTManager(app)

    # Initialize the database with the app
    db.init_app(app)
    migrate = Migrate(app, db)

    # Import models and register blueprints
    from .models import User  # Import models after initializing db to avoid circular import
    from .routes import main
    app.register_blueprint(main)

    # Create the database and tables
    with app.app_context():
        db.create_all()

    # Ensure the upload folder exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    return app


