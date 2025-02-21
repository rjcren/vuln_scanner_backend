import pytest
from app import create_app
from app.extensions import db
from app.models import UserFeedback, User, ScanTask

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

@pytest.fixture
def test_user(test_app):
    with test_app.app_context():
        user = User(username="testuser", password="password123", role_id=1)
        db.session.add(user)
        db.session.commit()
        return user

@pytest.fixture
def test_task(test_app, test_user):
    with test_app.app_context():
        task = ScanTask(user_id=test_user.user_id, target_url="http://example.com", status="completed")
        db.session.add(task)
        db.session.commit()
        return task

def test_create_feedback(client, test_user, test_task):
    response = client.post('/api/v1/feedback', json={
        'user_id': test_user.user_id,
        'task_id': test_task.task_id,
        'vul_description': 'Test vulnerability description',
        'status': 'pending'
    })
    assert response.status_code == 201
    data = response.get_json()
    assert 'feedback_id' in data
    assert UserFeedback.query.count() == 1

def test_update_feedback_status(client, test_user, test_task):
    feedback = UserFeedback(user_id=test_user.user_id, task_id=test_task.task_id, vul_description='Test vulnerability description', status='pending')
    db.session.add(feedback)
    db.session.commit()

    response = client.put(f'/api/v1/feedback/{feedback.feedback_id}', json={
        'status': 'resolved'
    })
    assert response.status_code == 200
    updated_feedback = UserFeedback.query.get(feedback.feedback_id)
    assert updated_feedback.status == 'resolved'

def test_get_feedback(client, test_user, test_task):
    feedback = UserFeedback(user_id=test_user.user_id, task_id=test_task.task_id, vul_description='Test vulnerability description', status='pending')
    db.session.add(feedback)
    db.session.commit()

    response = client.get(f'/api/v1/feedback/{feedback.feedback_id}')
    assert response.status_code == 200
    data = response.get_json()
    assert data['vul_description'] == 'Test vulnerability description'
    assert data['status'] == 'pending'
