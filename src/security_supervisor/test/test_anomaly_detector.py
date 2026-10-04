"""Unit tests for FeatureEngineer + AnomalyDetector (Phase 4). Pure Python —
no ROS 2 runtime needed, but requires the trained model in
~/uav_security_ws/models/ (built by scripts/train_anomaly_detector.py).

Run with: cd ~/uav_security_ws && python -m pytest src/security_supervisor/test/ -v
"""
import copy
import os
import random
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..', 'security_supervisor'))

from anomaly_detector import AnomalyDetector  # noqa: E402
from feature_engineer import FeatureEngineer, FEATURE_NAMES  # noqa: E402

MODEL_DIR = os.path.expanduser('~/uav_security_ws/models')

BASE_TS = 1_700_000_000_000_000
DT_US = 100_000

CLEAN_SNAPSHOT = {
    'gps': {
        'lat': 47.398, 'lon': 8.546, 'alt': 5.0,
        'vel_n': 0.0, 'vel_e': 0.0, 'vel_d': 0.0,
        'fix_type': 3, 'satellites_used': 10,
    },
    'local_pos': {'x': 0.0, 'y': 0.0, 'z': -5.0, 'vx': 0.0, 'vy': 0.0, 'vz': 0.0},
    'attitude': {
        'roll': 0.0, 'roll_rate': 0.0,
        'pitch': 0.0, 'pitch_rate': 0.0,
        'yaw': 0.1, 'yaw_rate': 0.0,
    },
    'imu': {'ax': 0.0, 'ay': 0.0, 'az': -9.81, 'gx': 0.0, 'gy': 0.0, 'gz': 0.0},
    'baro': {'pressure': 101000.0, 'temperature': 15.0, 'altitude': 5.0},
    'vehicle_status': {'arming_state': 2, 'nav_state': 14},
    'last_command': None,
}


def make_snapshot(index=0, **section_overrides):
    snap = copy.deepcopy(CLEAN_SNAPSHOT)
    snap['timestamp_us'] = BASE_TS + index * DT_US
    for section, overrides in section_overrides.items():
        if snap.get(section) is None:
            snap[section] = {}
        snap[section].update(overrides)
    return snap


def noisy_clean_snapshot(index, rng):
    return make_snapshot(
        index,
        gps={
            'lat': 47.398 + rng.gauss(0, 1e-7), 'lon': 8.546 + rng.gauss(0, 1e-7),
            'alt': 5.0 + rng.gauss(0, 0.05),
            'vel_n': rng.gauss(0, 0.1), 'vel_e': rng.gauss(0, 0.1), 'vel_d': rng.gauss(0, 0.05),
        },
        local_pos={
            'vx': rng.gauss(0, 0.1), 'vy': rng.gauss(0, 0.1), 'vz': rng.gauss(0, 0.05),
        },
        attitude={'roll': rng.gauss(0, 0.01), 'pitch': rng.gauss(0, 0.01)},
        imu={
            'ax': rng.gauss(0, 0.05), 'ay': rng.gauss(0, 0.05),
            'az': -9.81 + rng.gauss(0, 0.05),
        },
        baro={'pressure': 101000.0 + rng.gauss(0, 5), 'altitude': 5.0 + rng.gauss(0, 0.05)},
    )


def gps_spoofed_snapshot(index, rng, spoofed=False):
    """A GPS spoof that perturbs both position and velocity together, as a
    single spoofed source would — not just gps_lat_delta in isolation."""
    lat = 47.398 + (0.01 if spoofed else 0.0) + rng.gauss(0, 1e-7)
    vel_n = 15.0 if spoofed else rng.gauss(0, 0.1)
    return make_snapshot(
        index,
        gps={
            'lat': lat, 'lon': 8.546 + rng.gauss(0, 1e-7), 'alt': 5.0 + rng.gauss(0, 0.05),
            'vel_n': vel_n, 'vel_e': rng.gauss(0, 0.1), 'vel_d': rng.gauss(0, 0.05),
        },
        local_pos={
            'vx': rng.gauss(0, 0.1), 'vy': rng.gauss(0, 0.1), 'vz': rng.gauss(0, 0.05),
        },
        attitude={'roll': rng.gauss(0, 0.01), 'pitch': rng.gauss(0, 0.01)},
        imu={
            'ax': rng.gauss(0, 0.05), 'ay': rng.gauss(0, 0.05),
            'az': -9.81 + rng.gauss(0, 0.05),
        },
        baro={'pressure': 101000.0 + rng.gauss(0, 5), 'altitude': 5.0 + rng.gauss(0, 0.05)},
    )


@pytest.fixture
def detector():
    return AnomalyDetector(MODEL_DIR)


# ----------------------------------------------------------------------
def test_feature_vector_length():
    fe = FeatureEngineer()
    window = [make_snapshot(i) for i in range(30)]
    vector = fe.compute(window)
    assert len(vector) == 23


def test_feature_names_match_length():
    fe = FeatureEngineer()
    assert len(fe.feature_names) == 23


def test_cold_start_returns_none(detector):
    for i in range(29):
        result = detector.update(make_snapshot(i))
        assert result is None


def test_clean_data_low_anomaly_rate(detector):
    rng = random.Random(1)
    results = []
    for w in range(100):
        result = None
        for i in range(30):
            result = detector.update(noisy_clean_snapshot(w * 30 + i, rng))
        results.append(result)

    assert all(r is not None for r in results)
    anomaly_rate = sum(r.is_anomaly for r in results) / len(results)
    assert anomaly_rate < 0.20


def test_attacked_data_higher_anomaly_rate(detector):
    rng = random.Random(2)
    results = []
    for w in range(50):
        result = None
        for i in range(29):
            detector.update(gps_spoofed_snapshot(w * 30 + i, rng, spoofed=False))
        result = detector.update(gps_spoofed_snapshot(w * 30 + 29, rng, spoofed=True))
        results.append(result)

    assert all(r is not None for r in results)
    anomaly_rate = sum(r.is_anomaly for r in results) / len(results)
    assert anomaly_rate > 0.30


def test_top_features_returned(detector):
    rng = random.Random(3)
    result = None
    for i in range(30):
        result = detector.update(noisy_clean_snapshot(i, rng))

    assert result is not None
    assert isinstance(result.top_features, list)
    assert len(result.top_features) == 3
    assert all(name in FEATURE_NAMES for name in result.top_features)


def test_confidence_bounds(detector):
    rng = random.Random(4)
    for w in range(20):
        result = None
        for i in range(30):
            spoofed = w % 2 == 0 and i == 29
            result = detector.update(gps_spoofed_snapshot(w * 30 + i, rng, spoofed=spoofed))
        assert result is not None
        assert 0.0 <= result.confidence <= 1.0
