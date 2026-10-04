"""Regression tests for the ml_confidence_min gate (Phase 9 bug fix).

Background: the IsolationForest was trained with contamination=0.1, so
is_anomaly=true fires on ~10% of ordinary flight data by construction, and
the training set is "mostly-hover" (models/training_report.json) -- so the
takeoff climb of a perfectly clean flight lands in that engineered tail.
Those borderline hits used to decay gps/imu far enough to trip COMMAND_RTH,
which response_engine never cancels, pinning a clean flight in a permanent
false escalation.

Replaying all 43 logged flights measured every clean-flight ML hit at
confidence <= 0.5444 and zero hits during any of the six attack scenarios,
so the gate at 0.6 drops all observed false positives and no true ones.
"""
import math
import os
import sys

import yaml

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..', 'security_supervisor'))

from response_engine import ResponseAction, ResponseEngine  # noqa: E402
from trust_engine import TrustEngine  # noqa: E402

CONFIG_PATH = os.path.expanduser('~/uav_security_ws/config/trust_config.yaml')

# The confidence band every observed clean-flight false positive fell into.
OBSERVED_FALSE_POSITIVE_BAND = (0.5000, 0.5444)


def _cfg():
    with open(CONFIG_PATH) as handle:
        return yaml.safe_load(handle)


class _Anomaly:
    """Stand-in for anomaly_detector.AnomalyResult."""

    def __init__(self, confidence, top_features=None):
        self.is_anomaly = True
        self.anomaly_score = -0.01
        self.confidence = confidence
        self.top_features = top_features or ['accel_magnitude', 'gps_vert_speed', 'gyro_magnitude']
        self.timestamp_us = 0


def _gate_allows(confidence):
    """Mirrors supervisor_node._snapshot_cb's gate condition."""
    return confidence >= _cfg()['ml_confidence_min']


def test_config_defines_gate():
    assert 'ml_confidence_min' in _cfg()


def test_gate_is_above_observed_false_positive_band():
    """If someone lowers this below the measured FP ceiling, the clean-flight
    RTH regression comes straight back."""
    assert _cfg()['ml_confidence_min'] > OBSERVED_FALSE_POSITIVE_BAND[1]


def test_observed_false_positive_confidences_are_gated_out():
    lo, hi = OBSERVED_FALSE_POSITIVE_BAND
    for conf in (lo, 0.51, 0.52, 0.53, hi):
        assert not _gate_allows(conf), f'confidence {conf} should be gated out'


def test_high_confidence_anomaly_still_applies():
    """The gate must suppress noise without disabling the ML layer, so a
    genuinely confident detection still gets through."""
    for conf in (0.6, 0.75, 0.9, 1.0):
        assert _gate_allows(conf)


def test_borderline_ml_anomaly_does_not_escalate_a_clean_flight():
    """End-to-end: clean sensor data + a borderline ML hit must not produce
    any escalating response action.

    This is the exact shape of the observed bug -- TrustEngine itself raised
    zero flags for the whole flight, and the escalation came entirely from
    ML-driven score decay.
    """
    engine = TrustEngine()
    responder = ResponseEngine(engine.cfg)
    anomaly = _Anomaly(confidence=OBSERVED_FALSE_POSITIVE_BAND[1])

    escalating = set()
    for i in range(100):
        report = engine.update(_clean_snapshot(i))
        assert report.flags == [], 'clean data must not raise rule-based flags'

        if _gate_allows(anomaly.confidence):
            _apply_ml_penalty(engine, report, anomaly)

        decision = responder.decide(report, anomaly, i * 0.1)
        for action in decision.actions:
            if action not in (ResponseAction.NONE, ResponseAction.FLAG_ONLY):
                escalating.add(action)

    assert escalating == set(), f'clean flight escalated: {sorted(a.value for a in escalating)}'
    assert engine.scores['gps'] == 1.0
    assert engine.scores['imu'] == 1.0


def test_confident_ml_anomaly_still_decays_score():
    """Guards the other direction: the gate must not silently neuter the
    fusion layer for results that clear it."""
    engine = TrustEngine()
    anomaly = _Anomaly(confidence=0.9)

    engine.update(_clean_snapshot(0))
    report = engine.update(_clean_snapshot(1))
    assert _gate_allows(anomaly.confidence)
    _apply_ml_penalty(engine, report, anomaly)

    assert engine.scores['imu'] < 1.0


# ----------------------------------------------------------------------
def _apply_ml_penalty(engine, report, anomaly):
    """Mirrors supervisor_node._apply_ml_penalty (which needs rclpy to import)."""
    cfg = engine.cfg
    prefixes = [('gps_', 'gps'), ('ekf_', 'gps'), ('imu_', 'imu'), ('accel_', 'imu'),
                ('gyro_', 'imu'), ('baro_', 'barometer'), ('attitude_', 'attitude')]
    components = {f.component for f in report.flags}
    for feature in anomaly.top_features:
        for prefix, component in prefixes:
            if feature.startswith(prefix):
                components.add(component)
                break

    penalty = anomaly.confidence * cfg['ml_trust_penalty_scale']
    for component in components:
        if component in report.scores:
            value = max(cfg['score_min'], min(cfg['score_max'], report.scores[component] - penalty))
            report.scores[component] = value
            engine.scores[component] = value
    report.overall_trust = min(report.scores.values())


def _clean_snapshot(index):
    """A hovering vehicle with entirely nominal sensor readings.

    The IMU carries a small deterministic jitter on purpose: a perfectly
    constant accelerometer is what a *failed* sensor looks like, and
    TrustEngine's frozen-IMU check correctly flags it. Real SITL data always
    has sensor noise, so flat values would make this a fixture artifact
    rather than a clean flight.
    """
    base_ts = 1_700_000_000_000_000
    jitter = math.sin(index * 0.7) * 0.02
    return {
        'timestamp_us': base_ts + index * 100_000,
        'gps': {'lat': 47.398 + index * 1e-7, 'lon': 8.546 + index * 1e-7, 'alt': 5.0,
                'vel_n': 0.05, 'vel_e': 0.03, 'vel_d': 0.0},
        'local_pos': {'x': 0.0, 'y': 0.0, 'z': -5.0, 'vx': 0.05, 'vy': 0.03, 'vz': 0.0},
        'attitude': {'roll': 0.0, 'roll_rate': 0.0, 'pitch': 0.0,
                     'pitch_rate': 0.0, 'yaw': 0.0, 'yaw_rate': 0.0},
        'imu': {'ax': jitter, 'ay': -jitter, 'az': -9.81 + jitter,
                'gx': jitter * 0.1, 'gy': 0.0, 'gz': -jitter * 0.1},
        'baro': {'pressure': 101325.0 + jitter, 'temperature': 15.0, 'altitude': 5.0},
        'battery': {'voltage': 16.2, 'current': -1.0, 'remaining': 0.9},
        'vehicle_status': {'arming_state': 2, 'nav_state': 4},
        'last_command': None,
    }
