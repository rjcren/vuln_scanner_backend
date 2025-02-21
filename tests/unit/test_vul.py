# /c:/Users/ren/Desktop/graduation-project/code/vuln_scanner_backend/tests/unit/test_vul.py

import pytest
from app import create_app
from app.extensions import db
from app.models import Vulnerability, ScanTask, User

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

def test_create_vulnerability(client, test_task):
    response = client.post('/api/v1/vulnerabilities', json={
        'task_id': test_task.task_id,
        'cve_id': 'CVE-2023-1234',
        'severity': 'high',
        'description': 'Test vulnerability'
    })
    assert response.status_code == 201
    data = response.get_json()
    assert 'vul_id' in data
    assert Vulnerability.query.count() == 1

def test_get_vulnerability(client, test_task):
    # Create a vulnerability first
    client.post('/api/v1/vulnerabilities', json={
        'task_id': test_task.task_id,
        'cve_id': 'CVE-2023-1234',
        'severity': 'high',
        'description': 'Test vulnerability'
    })

    response = client.get(f'/api/v1/vulnerabilities/{test_task.task_id}')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['vulnerabilities']) == 1

def test_update_vulnerability(client, test_task):
    # Create a vulnerability first
    create_response = client.post('/api/v1/vulnerabilities', json={
        'task_id': test_task.task_id,
        'cve_id': 'CVE-2023-1234',
        'severity': 'high',
        'description': 'Test vulnerability'
    })
    vul_id = create_response.get_json()['vul_id']

    response = client.put(f'/api/v1/vulnerabilities/{vul_id}', json={
        'severity': 'critical',
        'description': 'Updated vulnerability'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['severity'] == 'critical'
    assert data['description'] == 'Updated vulnerability'

def test_delete_vulnerability(client, test_task):
    # Create a vulnerability first
    create_response = client.post('/api/v1/vulnerabilities', json={
        'task_id': test_task.task_id,
        'cve_id': 'CVE-2023-1234',
        'severity': 'high',
        'description': 'Test vulnerability'
    })
    vul_id = create_response.get_json()['vul_id']

    response = client.delete(f'/api/v1/vulnerabilities/{vul_id}')
    assert response.status_code == 204
    assert Vulnerability.query.count() == 0
