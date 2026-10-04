"""Unit tests for attack_injector's pure attack-math functions (Phase 5).
No ROS 2 runtime needed -- these test the math extracted from injector_node.py.

Run with: cd ~/uav_security_ws && python -m pytest src/attack_injector/test/ -v
"""
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..', 'attack_injector'))

import attack_math as am  # noqa: E402


def test_gps_offset_conversion():
    expected = 50.0 / 111111.0
    result = am.meters_to_lat_degrees(50.0)
    assert abs(result - expected) / expected < 0.001


def test_gps_ramp_fraction():
    ramp_s = 3.0
    assert am.gps_spoof_ramp_fraction(0.0, ramp_s) == 0.0
    assert am.gps_spoof_ramp_fraction(ramp_s / 2, ramp_s) == 0.5
    assert am.gps_spoof_ramp_fraction(ramp_s, ramp_s) == 1.0


def test_frozen_gps_produces_identical_lat_lon():
    captured = {
        'latitude_deg': 47.398123, 'longitude_deg': 8.546456, 'altitude_msl_m': 5.2,
        'vel_n_m_s': 0.1, 'vel_e_m_s': -0.2, 'vel_d_m_s': 0.0,
    }
    outputs = [am.freeze_gps_reading(captured) for _ in range(10)]
    lats = {o['latitude_deg'] for o in outputs}
    lons = {o['longitude_deg'] for o in outputs}
    assert len(lats) == 1
    assert len(lons) == 1


def test_cmd_inject_uses_invalid_id():
    cmd = am.build_invalid_command(timestamp_us=1000)
    assert cmd['command'] == 999


def test_cmd_inject_arm_has_valid_id():
    cmd = am.build_arm_flood_command(timestamp_us=1000)
    assert cmd['command'] == 400


def test_detection_latency_calculation():
    latency = am.detection_latency_s(attack_start_us=1000, first_detection_us=1500)
    assert abs(latency - 0.0005) < 1e-9


def test_report_fields_present():
    report = {
        'attack_type': 'gps_spoof',
        'attack_start_us': 123456789,
        'attack_end_us': 234567890,
        'attack_duration_s': 15.0,
        'first_detection_us': 123458000,
        'detection_latency_s': 0.12,
        'total_flags_during_attack': 47,
        'flags_by_type': {'physics': 12, 'cross_sensor': 30, 'temporal': 5},
        'ml_anomaly_detections': 8,
        'score_minimums': {'gps': 0.12, 'imu': 0.98, 'barometer': 1.0,
                            'attitude': 1.0, 'commands': 1.0},
        'post_attack_recovery_time_s': 4.2,
        'false_positives_pre_attack': 0,
    }
    for field in am.REPORT_REQUIRED_FIELDS:
        assert field in report
