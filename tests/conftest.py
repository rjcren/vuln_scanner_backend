import pytest
from app import create_app
from app.extensions import db

@pytest.fixture(scope='session')
def test_app():
    """Create and configure a new app instance for testing."""
    app = create_app("testing")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True

    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture(scope='session')
def client(test_app):
    """Create a test client for the app."""
    return test_app.test_client()

@pytest.fixture(scope='session')
def runner(test_app):
    """Create a test runner for the app."""
    return test_app.test_cli_runner()
