import json

import pytest

from security_dashboard.state_store import StateStore


class FakeClock:
    """Deterministic clock so event timestamps are assertable."""

    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def store(clock):
    return StateStore(clock=clock)


def trust_payload(scores=None, flags=None, response=None, ml=None):
    payload = {
        'timestamp_us': 1,
        'scores': scores or {'gps': 1.0, 'imu': 1.0, 'barometer': 1.0,
                             'attitude': 1.0, 'commands': 1.0},
        'overall_trust': min((scores or {'gps': 1.0}).values()),
    }
    payload['flags'] = flags or []
    if response is not None:
        payload['response'] = response
    if ml is not None:
        payload['ml_anomaly'] = ml
    return payload


def flag(component='gps', check_type='pos_jump', severity='severe', reason='jumped 90m'):
    return {'component': component, 'check_type': check_type, 'severity': severity,
            'reason': reason, 'value': 90.0, 'threshold': 50.0}


def events_of_kind(store, kind):
    return [e for e in store.snapshot()['events'] if e['kind'] == kind]


# --- scores and history -------------------------------------------------

def test_scores_and_overall_recorded(store):
    store.ingest_trust_scores(trust_payload())
    snap = store.snapshot()
    assert snap['trust_scores']['gps'] == 1.0
    assert snap['overall_trust'] == 1.0
    assert len(snap['score_history']['gps']) == 1
    assert len(snap['overall_history']) == 1


def test_score_history_accumulates_with_timestamps(store, clock):
    store.ingest_trust_scores(trust_payload({'gps': 1.0}))
    clock.advance(0.1)
    store.ingest_trust_scores(trust_payload({'gps': 0.5}))

    history = store.snapshot()['score_history']['gps']
    assert [point[1] for point in history] == [1.0, 0.5]
    assert history[0][0] == pytest.approx(0.0)
    assert history[1][0] == pytest.approx(0.1)


def test_unknown_component_does_not_create_history_bucket(store):
    store.ingest_trust_scores(trust_payload({'gps': 1.0, 'lidar': 0.2}))
    assert 'lidar' not in store.snapshot()['score_history']


# --- flag de-duplication ------------------------------------------------

def test_flag_logged_once_while_it_stays_active(store, clock):
    for _ in range(25):
        store.ingest_trust_scores(trust_payload(flags=[flag()]))
        clock.advance(0.1)

    assert len(events_of_kind(store, 'flag')) == 1


def test_flag_cleared_event_on_disappearance(store):
    store.ingest_trust_scores(trust_payload(flags=[flag()]))
    store.ingest_trust_scores(trust_payload(flags=[]))

    cleared = events_of_kind(store, 'flag_cleared')
    assert len(cleared) == 1
    assert 'GPS' in cleared[0]['text']
    assert store.snapshot()['active_flags'] == []


def test_severity_change_is_a_new_event(store):
    store.ingest_trust_scores(trust_payload(flags=[flag(severity='minor')]))
    store.ingest_trust_scores(trust_payload(flags=[flag(severity='severe')]))

    # Escalation matters operationally, so it is reported rather than
    # collapsed into the existing minor flag.
    assert len(events_of_kind(store, 'flag')) == 2


def test_distinct_components_logged_separately(store):
    store.ingest_trust_scores(trust_payload(
        flags=[flag('gps'), flag('imu', 'accel_range')]))
    assert len(events_of_kind(store, 'flag')) == 2


# --- response action de-duplication -------------------------------------

def test_sticky_action_logged_once(store, clock):
    response = {'actions': ['COMMAND_RTH'], 'reasons': ['trust collapsed'],
                'response_level': 4, 'incident_active': True}
    for _ in range(30):
        store.ingest_trust_scores(trust_payload(response=response))
        clock.advance(0.1)

    responses = events_of_kind(store, 'response')
    assert len(responses) == 1
    assert 'COMMAND_RTH' in responses[0]['text']
    assert 'trust collapsed' in responses[0]['text']


def test_none_and_flag_only_are_not_logged_as_responses(store):
    store.ingest_trust_scores(trust_payload(response={
        'actions': ['NONE', 'FLAG_ONLY'], 'reasons': ['', ''],
        'response_level': 0, 'incident_active': False}))

    assert events_of_kind(store, 'response') == []
    assert store.snapshot()['active_actions'] == []


def test_action_cancellation_logged(store):
    store.ingest_trust_scores(trust_payload(response={
        'actions': ['COMMAND_HOVER'], 'reasons': ['degraded'],
        'response_level': 2, 'incident_active': True}))
    store.ingest_trust_scores(trust_payload(response={
        'actions': [], 'reasons': [], 'response_level': 0, 'incident_active': False}))

    cleared = events_of_kind(store, 'response_cleared')
    assert len(cleared) == 1
    assert 'COMMAND_HOVER' in cleared[0]['text']


def test_response_level_and_incident_tracked(store):
    store.ingest_trust_scores(trust_payload(response={
        'actions': ['COMMAND_LAND'], 'reasons': ['lost'],
        'response_level': 5, 'incident_active': True}))
    snap = store.snapshot()
    assert snap['response_level'] == 5
    assert snap['incident_active'] is True


# --- positions ----------------------------------------------------------

def gps_snapshot(lat=47.1, lon=8.5, alt=500.0, **extra):
    payload = {
        'timestamp_us': 1,
        'gps': {'lat': lat, 'lon': lon, 'alt': alt, 'fix_type': 3,
                'satellites_used': 12},
    }
    payload.update(extra)
    return payload


def test_vehicle_fields_from_snapshot(store):
    store.ingest_snapshot(gps_snapshot(
        vehicle_status={'arming_state': 2, 'nav_state': 4},
        battery={'remaining': 0.85}))

    snap = store.snapshot()
    assert snap['vehicle']['arming_state'] == 2
    assert snap['vehicle']['satellites_used'] == 12
    assert snap['counts']['snapshots'] == 1


def test_first_fix_becomes_trajectory_origin(store):
    store.ingest_snapshot(gps_snapshot())
    assert store.snapshot()['trajectory'][0][1:] == [0.0, 0.0, 0.0]


def test_gps_offset_converts_to_metres(store):
    store.ingest_snapshot(gps_snapshot())
    # ~50 m north and 10 m of altitude gain from the origin fix.
    store.ingest_snapshot(gps_snapshot(lat=47.1 + 50.0 / 111320.0, alt=510.0))

    north, east, down = store.snapshot()['trajectory'][1][1:]
    assert north == pytest.approx(50.0, abs=0.5)
    assert east == pytest.approx(0.0, abs=0.5)
    assert down == pytest.approx(-10.0, abs=0.01)


def test_snapshot_without_gps_fix_adds_no_trajectory_point(store):
    store.ingest_snapshot({'timestamp_us': 1, 'gps': {}})
    store.ingest_snapshot({'timestamp_us': 2, 'gps': {'lat': 0.0, 'lon': 0.0}})
    assert store.snapshot()['trajectory'] == []


def test_perceived_track_is_gps_not_local_pos(store):
    """The overlay only reveals a spoof if the perceived track follows the
    (spoofable) GPS fields rather than the EKF local position."""
    store.ingest_snapshot(gps_snapshot(local_pos={'x': 0.0, 'y': 0.0, 'z': 0.0}))
    store.ingest_snapshot(gps_snapshot(
        lat=47.1 + 50.0 / 111320.0, local_pos={'x': 0.0, 'y': 0.0, 'z': 0.0}))

    assert store.snapshot()['trajectory'][1][1] == pytest.approx(50.0, abs=0.5)


def test_external_true_position_preferred_over_local_pos(store):
    store.ingest_true_position(50.0, 0.0, 0.0)
    store.ingest_snapshot(gps_snapshot(local_pos={'x': 9.0, 'y': 9.0, 'z': 9.0}))

    true_track = store.snapshot()['true_trajectory']
    assert len(true_track) == 1
    assert true_track[0][1] == 50.0


def test_true_position_decimated_to_match_perceived_rate(store, clock):
    # 50 Hz in should come out at ~10 Hz, so both history windows cover the
    # same wall-clock span rather than truth being truncated five times sooner.
    for i in range(250):
        store.ingest_true_position(float(i), 0.0, 0.0)
        clock.advance(0.02)

    from security_dashboard.state_store import TRUE_POS_MIN_INTERVAL_S
    track = store.snapshot()['true_trajectory']

    # Every sample is still counted, but stored points are spaced by at least
    # the decimation interval (quantised up to the next input tick, so the
    # effective rate is somewhat under 1/TRUE_POS_MIN_INTERVAL_S).
    assert store.snapshot()['counts']['true_pos'] == 250
    assert all(track[i + 1][0] - track[i][0] >= TRUE_POS_MIN_INTERVAL_S
               for i in range(len(track) - 1))
    assert len(track) < 250 / 4


def test_local_pos_used_as_truth_without_px4_msgs(store):
    store.ingest_snapshot(gps_snapshot(local_pos={'x': 7.0, 'y': 8.0, 'z': -3.0}))
    assert store.snapshot()['true_trajectory'][0][1:] == [7.0, 8.0, -3.0]


# --- actuation coalescing -----------------------------------------------

def test_repeated_actuation_coalesces_into_one_counted_event(store, clock):
    # COMMAND_HOVER is re-sent every cycle because PX4 needs a continuous
    # offboard setpoint stream; the log should show one line, not 50.
    for _ in range(50):
        store.ingest_mitigation_intent({'action': 'COMMAND_HOVER', 'reason': 'low trust'})
        clock.advance(0.1)

    actuations = events_of_kind(store, 'actuation')
    assert len(actuations) == 1
    assert '(x50)' in actuations[0]['text']


def test_interleaved_actuations_tracked_separately(store, clock):
    for _ in range(10):
        store.ingest_mitigation_intent({'action': 'COMMAND_HOVER', 'reason': 'a'})
        store.ingest_mitigation_intent({'action': 'ISOLATE_GPS', 'reason': 'b'})
        clock.advance(0.1)

    actuations = events_of_kind(store, 'actuation')
    assert len(actuations) == 2
    assert {'COMMAND_HOVER', 'ISOLATE_GPS'} == {a['text'].split()[0] for a in actuations}


def test_actuation_after_quiet_gap_is_a_new_event(store, clock):
    from security_dashboard.state_store import ACTUATION_COALESCE_S
    store.ingest_mitigation_intent({'action': 'COMMAND_RTH', 'reason': 'first'})
    clock.advance(ACTUATION_COALESCE_S + 1.0)
    store.ingest_mitigation_intent({'action': 'COMMAND_RTH', 'reason': 'second'})

    assert len(events_of_kind(store, 'actuation')) == 2


def test_history_windows_are_bounded(store, clock):
    from security_dashboard.state_store import SCORE_HISTORY_MAXLEN
    for _ in range(SCORE_HISTORY_MAXLEN + 120):
        store.ingest_trust_scores(trust_payload({'gps': 0.9}))
        clock.advance(0.1)

    assert len(store.snapshot()['score_history']['gps']) == SCORE_HISTORY_MAXLEN


def test_event_log_is_bounded_and_newest_first(store, clock):
    from security_dashboard.state_store import EVENT_LOG_MAXLEN
    for i in range(EVENT_LOG_MAXLEN + 40):
        store.ingest_mitigation_intent({'action': f'ACT_{i}', 'reason': 'x'})
        clock.advance(0.1)

    events = store.snapshot()['events']
    assert len(events) == EVENT_LOG_MAXLEN
    assert events[0]['seq'] > events[-1]['seq']


# --- serialisation ------------------------------------------------------

def test_snapshot_is_json_serialisable(store):
    store.ingest_trust_scores(trust_payload(
        flags=[flag()],
        response={'actions': ['COMMAND_RTH'], 'reasons': ['r'],
                  'response_level': 4, 'incident_active': True},
        ml={'is_anomaly': True, 'anomaly_score': -0.3, 'confidence': 0.8,
            'top_features': ['gps_speed']}))
    store.ingest_snapshot({'timestamp_us': 1, 'local_pos': {'x': 1.0, 'y': 2.0, 'z': 3.0}})
    store.ingest_status('[TRUSTED] GPS:1.00')

    encoded = json.dumps(store.snapshot())
    assert '[TRUSTED] GPS:1.00' in encoded


def test_malformed_payload_does_not_raise(store):
    store.ingest_trust_scores({})
    snap = store.snapshot()
    assert snap['trust_scores'] == {}
    assert snap['overall_trust'] is None
