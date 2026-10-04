import json

import pytest

from security_dashboard.state_store import StateStore
from security_dashboard.web_server import create_app


@pytest.fixture
def store():
    return StateStore()


@pytest.fixture
def client(store):
    app = create_app(store, stream_hz=50.0)
    app.config.update(TESTING=True)
    return app.test_client()


def test_index_serves_dashboard(client):
    response = client.get('/')
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'UAV Security Dashboard' in body
    assert '/api/stream' in body


def test_state_endpoint_returns_store_snapshot(client, store):
    store.ingest_status('[UNTRUSTED] GPS:0.10')
    store.ingest_trust_scores({
        'scores': {'gps': 0.1}, 'overall_trust': 0.1, 'flags': [],
    })

    payload = client.get('/api/state').get_json()
    assert payload['status_line'] == '[UNTRUSTED] GPS:0.10'
    assert payload['overall_trust'] == 0.1
    assert 'trajectory' in payload and 'events' in payload


def test_health_reports_receive_counters(client, store):
    assert client.get('/api/health').get_json()['receiving_trust_scores'] is False

    store.ingest_trust_scores({'scores': {'gps': 1.0}, 'overall_trust': 1.0})
    health = client.get('/api/health').get_json()
    assert health['ok'] is True
    assert health['receiving_trust_scores'] is True
    assert health['counts']['trust_scores'] == 1


def test_stream_emits_sse_frames(client, store):
    store.ingest_trust_scores({'scores': {'gps': 0.42}, 'overall_trust': 0.42})

    response = client.get('/api/stream')
    assert response.status_code == 200
    assert response.mimetype == 'text/event-stream'

    # The generator is infinite by design; pull a single frame and close it.
    frame = next(response.response)
    text = frame.decode() if isinstance(frame, bytes) else frame
    assert text.startswith('data: ')
    assert text.endswith('\n\n')

    payload = json.loads(text[len('data: '):].strip())
    assert payload['overall_trust'] == 0.42
    response.close()


def _next_frame(stream):
    frame = next(stream)
    text = frame.decode() if isinstance(frame, bytes) else frame
    return json.loads(text[len('data: '):].strip())


def test_stream_reflects_live_updates(client, store):
    store.ingest_trust_scores({'scores': {'gps': 1.0}, 'overall_trust': 1.0})

    response = client.get('/api/stream')
    stream = response.response
    assert _next_frame(stream)['overall_trust'] == 1.0

    store.ingest_trust_scores({'scores': {'gps': 0.2}, 'overall_trust': 0.2})

    # The stream samples the store on a timer rather than being change-driven,
    # and the test client primes one frame at request time, so the update lands
    # within the next frame or two rather than necessarily the very next one.
    values = [_next_frame(stream)['overall_trust'] for _ in range(3)]
    assert 0.2 in values
    response.close()


def test_unknown_static_file_is_404(client):
    assert client.get('/static/nope.js').status_code == 404
