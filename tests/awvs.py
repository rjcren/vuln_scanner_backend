from celery import chord
import pytest
from app import create_app
from app.celery_task.celery_tasks import save_awvs_vuls
from app.services.scanner.AWVS import AWVS

@pytest.fixture
def client():
    yield create_app("testing")

def test_save(client):
    task_id = 111
    scan_id = "4545f213-7a96-4db2-bb86-8e9388c3da17"
    assert save_awvs_vuls.s(task_id, scan_id) == True

