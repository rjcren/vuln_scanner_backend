from app import create_app
from app.extensions import celery

app = create_app('development')
app.app_context().push()