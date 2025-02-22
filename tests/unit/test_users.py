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

def test_create_user(client):
    response = client.post('/api/v1/auth/register', json={
        'username': 'newuser',
        'password': 'password123',
        'role': 'user'
    })
    assert response.status_code == 201
    assert User.query.count() == 1

def test_invalid_login(client):
    response = client.post('/api/v1/auth/login', json={
        'username': 'wronguser',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
