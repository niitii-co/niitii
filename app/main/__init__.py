from flask import Blueprint

# blueprints define routes and error handlers. Blueprints are dormant until registered with an application.
bp = Blueprint('main', __name__)

# imported at the bottom to avoid circular dependency. app/main/routes will need to import main blueprint object
from app.main import routes

