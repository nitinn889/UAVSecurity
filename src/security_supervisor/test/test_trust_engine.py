"""Unit tests for TrustEngine (Phase 3). Pure Python — no ROS 2 runtime needed.

Run with: cd ~/uav_security_ws && python -m pytest src/security_supervisor/test/ -v
"""
import copy
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..', 'security_supervisor'))

from trust_engine import TrustEngine  # noqa: E402

BASE_TS = 1_700_000_000_000_000  # arbitrary epoch, microseconds
DT_US = 100_000  # 10 Hz

CLEAN_SNAPSHOT = {
    'gps': {
        'lat': 47.398, 'lon': 8.546, 'alt': 0.2,
        'vel_n': 0.0, 'vel_e': 0.0, 'vel_d': 0.0,
        'fix_type': 3, 'satellites_used': 10,
    },
    'local_pos': {'x': 0.0, 'y': 0.0, 'z': -0.2, 'vx': 0.0, 'vy': 0.0, 'vz': 0.0},
    'attitude': {
        'roll': 0.0, 'roll_rate': 0.0,
        'pitch': 0.0, 'pitch_rate': 0.0,
        'yaw': 0.0, 'yaw_rate': 0.0,
    },
    'imu': {'ax': 0.0, 'ay': 0.0, 'az': -9.81, 'gx': 0.0, 'gy': 0.0, 'gz': 0.0},
    'baro': {'pressure': 101325.0, 'temperature': 15.0, 'altitude': 0.2},
    'battery': {'voltage': 16.2, 'current': -1.0, 'remaining': 1.0},
    'vehicle_status': {'arming_state': 1, 'nav_state': 4},
    'last_command': None,
}


def make_snapshot(index=0, **section_overrides):
    """A deep copy of CLEAN_SNAPSHOT at update `index` (10 Hz), with any
    section dicts shallow-merged from section_overrides, e.g.
    make_snapshot(1, gps={'vel_n': 25.0})."""
    snap = copy.deepcopy(CLEAN_SNAPSHOT)
    snap['timestamp_us'] = BASE_TS + index * DT_US
    for section, overrides in section_overrides.items():
        if snap.get(section) is None:
            snap[section] = {}
        snap[section].update(overrides)
    return snap


def flags_for(report, component=None, check_type=None, severity=None):
    result = report.flags
    if component is not None:
        result = [f for f in result if f.component == component]
    if check_type is not None:
        result = [f for f in result if f.check_type == check_type]
    if severity is not None:
        result = [f for f in result if f.severity == severity]
    return result


# ----------------------------------------------------------------------
def test_physics_gps_velocity_spike():
    engine = TrustEngine()
    report = engine.update(make_snapshot(0, gps={'vel_n': 25.0}))

    assert report.scores['gps'] < 1.0
    physics_flags = flags_for(report, component='gps', check_type='physics')
    assert len(physics_flags) > 0


def test_physics_gps_position_jump():
    engine = TrustEngine()
    engine.update(make_snapshot(0))  # baseline, establishes prior position

    # ~200m north, computed with the standard 111,320 m/degree-latitude
    # approximation (exact enough given the 50m threshold).
    lat_shift = 200.0 / 111320.0
    report = engine.update(make_snapshot(1, gps={'lat': 47.398 + lat_shift}))

    assert report.scores['gps'] < 0.7
    assert len(flags_for(report, component='gps', check_type='physics')) > 0


def test_cross_sensor_gps_baro_divergence():
    engine = TrustEngine()
    report = engine.update(make_snapshot(0, gps={'alt': 100.0}, baro={'altitude': 50.0}))

    cross_flags = flags_for(report, component='gps', check_type='cross_sensor')
    assert len(cross_flags) > 0
    # NOTE: per trust_config.yaml's own tiers (15-30m minor, 30-60m moderate,
    # >60m severe — see Task 3), a 50m divergence lands in the *moderate*
    # band, not severe. The Task 7 spec's test description asked for
    # severity='severe' at 50m, which contradicts the tiers it itself
    # defines in Task 3. Implemented faithfully to the Task 3 tiers; flagged
    # to the user rather than silently loosening the tier boundaries.
    assert any(f.severity == 'moderate' for f in cross_flags)


def test_cross_sensor_gps_ekf_velocity():
    engine = TrustEngine()
    report = engine.update(make_snapshot(
        0, gps={'vel_n': 5.0}, local_pos={'vx': 0.5}))

    cross_flags = flags_for(report, component='gps', check_type='cross_sensor')
    assert len(cross_flags) > 0


def test_temporal_frozen_gps():
    engine = TrustEngine()
    all_flags = []
    for i in range(25):
        report = engine.update(make_snapshot(
            i,
            local_pos={'vx': 2.0},
            vehicle_status={'arming_state': 2, 'nav_state': 14},
        ))
        all_flags.extend(report.flags)

    frozen_flags = [f for f in all_flags if 'frozen' in f.reason.lower()]
    assert len(frozen_flags) > 0
    assert any(f.severity == 'severe' for f in frozen_flags)


def test_command_flood():
    engine = TrustEngine()
    all_flags = []
    for i in range(25):
        ts = BASE_TS + i * 300_000  # 0.3s apart -> 7.2s span, within the 10s window
        cmd_id = 176 if i % 2 == 0 else 192  # both whitelisted, neither is ARM
        snap = make_snapshot(0)
        snap['timestamp_us'] = ts
        snap['last_command'] = {
            'command': cmd_id, 'param1': 0.0, 'param2': 0.0, 'msg_timestamp': ts,
        }
        report = engine.update(snap)
        all_flags.extend(report.flags)

    flood_flags = [f for f in all_flags
                   if f.component == 'commands' and f.severity == 'severe']
    assert len(flood_flags) > 0


def test_recovery():
    engine = TrustEngine()

    # Drive gps score down with repeated severe violations (isolated to the
    # horizontal-speed check: vel_n=70 -> ratio 3.5x threshold -> severe).
    for i in range(3):
        report = engine.update(make_snapshot(i, gps={'vel_n': 70.0}))
    score_after_bad = report.scores['gps']
    assert score_after_bad < 0.5

    for i in range(3, 23):
        report = engine.update(make_snapshot(i))  # clean

    assert report.scores['gps'] > score_after_bad


def test_clean_flight_no_command_flags():
    """Regression test: a normal flight (arm -> set_mode -> takeoff -> land,
    with mode changes and landing happening well after flight_warmup_seconds)
    must not raise any 'commands' temporal flags. All four command IDs used
    here (400 ARM, 176 SET_MODE, 21 LAND_START, 20 RETURN_TO_LAUNCH) are in
    allowed_command_ids, so the warm-up novelty check must treat them as
    expected no matter when they first appear -- see the exemption in
    TrustEngine._temporal_commands()."""
    engine = TrustEngine()

    def send(index, command, param1=0.0, param2=0.0):
        ts = BASE_TS + index * DT_US
        snap = make_snapshot(index)
        snap['last_command'] = {
            'command': command, 'param1': param1, 'param2': param2,
            'msg_timestamp': ts,
        }
        return engine.update(snap)

    all_flags = []
    all_flags.extend(send(0, 400, param1=1.0).flags)  # ARM, at t=0

    # Well past flight_warmup_seconds (5.0s) -- 10 Hz updates, 100 updates = 10s.
    for i in range(1, 100):
        all_flags.extend(engine.update(make_snapshot(i)).flags)

    all_flags.extend(send(100, 176, param1=1.0, param2=6.0).flags)  # SET_MODE (offboard)
    for i in range(101, 150):
        all_flags.extend(engine.update(make_snapshot(i)).flags)

    all_flags.extend(send(150, 21).flags)  # LAND_START
    for i in range(151, 160):
        all_flags.extend(engine.update(make_snapshot(i)).flags)

    all_flags.extend(send(160, 20).flags)  # RETURN_TO_LAUNCH
    for i in range(161, 170):
        all_flags.extend(engine.update(make_snapshot(i)).flags)

    command_flags = [f for f in all_flags if f.component == 'commands']
    assert command_flags == []


def test_score_bounds():
    engine = TrustEngine()

    for i in range(5):
        report = engine.update(make_snapshot(i, gps={'vel_n': 70.0}))
        for score in report.scores.values():
            assert 0.0 <= score <= 1.0

    for i in range(5, 60):
        report = engine.update(make_snapshot(i))
        for score in report.scores.values():
            assert 0.0 <= score <= 1.0

    for i in range(60, 65):
        report = engine.update(make_snapshot(i, imu={'ax': 100.0, 'ay': 100.0, 'az': 100.0}))
        for score in report.scores.values():
            assert 0.0 <= score <= 1.0
