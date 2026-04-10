"""Basic smoke tests for the scheduling app."""
import os, pytest, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

os.environ.setdefault('DB_PATH', '/tmp/test_ci.db')
os.environ.setdefault('FLASK_ENV', 'dev')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')

import app as application

@pytest.fixture
def client():
    application.app.config['TESTING'] = True
    application.app.config['SECRET_KEY'] = 'test'
    application.init_db()
    with application.app.test_client() as c:
        yield c

def test_home_serves_html(client):
    r = client.get('/')
    assert r.status_code == 200
    assert b'<!DOCTYPE html>' in r.data

def test_public_config(client):
    r = client.get('/api/public/config')
    assert r.status_code == 200
    d = r.get_json()
    assert 'line_enabled' in d

def test_public_event_no_event(client):
    r = client.get('/api/public/event')
    assert r.status_code == 200

def test_admin_login_wrong_password(client):
    r = client.post('/api/admin/login', json={'password': 'wrong'})
    assert r.status_code in (400, 401)

def test_admin_login_correct(client):
    r = client.post('/api/admin/login', json={'password': 'admin123'})
    assert r.status_code == 200
    assert r.get_json()['success'] == True

def test_admin_requires_auth(client):
    r = client.get('/api/admin/bookings')
    assert r.status_code == 401

def test_admin_bookings_with_auth(client):
    client.post('/api/admin/login', json={'password': 'admin123'})
    r = client.get('/api/admin/bookings')
    assert r.status_code == 200
    assert isinstance(r.get_json(), list)

def test_user_requires_auth(client):
    r = client.get('/api/user/event')
    assert r.status_code == 401

def test_admin_event_save(client):
    client.post('/api/admin/login', json={'password': 'admin123'})
    r = client.post('/api/admin/event', json={
        'name': 'CI Test Event',
        'startDate': '2026-06-01',
        'endDate': '2026-06-30',
        'scheduleMode': 'uniform',
        'slotStart': '09:00',
        'slotEnd': '17:00',
        'slotDuration': 30,
        'maxSlotsPerUser': 3,
        'daySchedules': [{'dayOfWeek': 5, 'slotStart': '09:00', 'slotEnd': '17:00', 'slotDuration': 30}],
        'excludedDates': []
    })
    assert r.status_code == 200
    assert 'id' in r.get_json()

def test_all_availability_no_event(client):
    with application.app.test_client() as c:
        with c.session_transaction() as s:
            s['user_id'] = 999
        r = c.get('/api/user/all-availability?eventId=999')
        assert r.status_code in (200, 400)
