# test/unit/test_tasks.py
import pytest
from app import create_app
from app.extensions import db
from app.models import ScanTask, User

@pytest.fixture
def test_app():
    app = create_app("testing")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True

    with app.app_context():
        db.create_all()
        yield app

@pytest.fixture
def client(test_app):
    return test_app.test_client()

def test_create_task(client):
    user_response = client.post('/api/v1/auth/register', json={
        'username': 'taskuser',
        'password': 'password123',
        'role': 'user'
    })
    user_id = user_response.get_json()['user_id']

    response = client.post('/api/v1/tasks', json={
        'target_url': 'http://example.com',
        'scan_type': 'quick'
    })
    assert response.status_code == 202
    assert ScanTask.query.count() == 1

def test_get_tasks(client):
    client.post('/api/v1/auth/register', json={
        'username': 'taskuser',
        'password': 'password123',
        'role': 'user'
    })
    client.post('/api/v1/tasks', json={
        'target_url': 'http://example.com',
        'scan_type': 'quick'
    })
    
    response = client.get('/api/v1/tasks')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['tasks']) == 1
