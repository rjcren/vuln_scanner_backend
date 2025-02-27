# /c:/Users/ren/Desktop/graduation-project/code/vuln_scanner_backend/tests/integration/test_auth_flow.py
import pytest
from app import create_app
from app.extensions import db
from app.models import User

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

def test_register(client):
    response = client.post('/api/v1/auth/register', json={
        'username': 'testuser',
        'password': 'password123'
    })
    assert response.status_code == 201
    data = response.get_json()
    assert 'user_id' in data

def test_login(client):
    client.post('/api/v1/auth/register', json={
        'username': 'testuser',
        'password': 'password123'
    })
    response = client.post('/api/v1/auth/login', json={
        'username': 'testuser',
        'password': 'password123'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert 'token' in data
