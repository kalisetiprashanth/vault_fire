from app import create_app
from scripts.seed import seed_if_empty

application = create_app()
with application.app_context():
    seed_if_empty(application)
