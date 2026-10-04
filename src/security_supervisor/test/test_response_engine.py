"""Unit tests for ResponseEngine (Phase 6). Pure Python — no ROS 2 runtime.

Run with: cd ~/uav_security_ws && python -m pytest src/security_supervisor/test/ -v
"""
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..', 'security_supervisor'))

from trust_engine import AnomalyFlag, TrustReport  # noqa: E402
from response_engine import ResponseAction, ResponseEngine  # noqa: E402

COMPONENTS = ('gps', 'imu', 'barometer', 'attitude', 'commands')

CONFIG = {
    'status_trusted_min': 0.7,
    'status_untrusted_max': 0.4,
    'incident_window_s': 30.0,
    'response_hover_cancel_trust_min': 0.6,
    'response_hover_cancel_consecutive_updates': 5,
    'response_gps_rotate_key_confidence_min': 0.6,
    'response_land_confidence_min': 0.8,
    'response_degraded_max': 0.7,
    'response_hover_max': 0.5,
    'response_rth_max': 0.3,
}


class FakeAnomalyResult:
    """Duck-typed stand-in: ResponseEngine only ever reads .confidence."""
    def __init__(self, confidence):
        self.confidence = confidence


def make_report(scores=None, flags=None, timestamp_us=1_000_000):
    full_scores = {c: 1.0 for c in COMPONENTS}
    if scores:
        full_scores.update(scores)
    flags = flags or []
    return TrustReport(
        scores=full_scores,
        flags=flags,
        overall_trust=min(full_scores.values()),
        timestamp_us=timestamp_us,
    )


def flag(component, check_type='physics', severity='moderate', reason='test flag'):
    return AnomalyFlag(component=component, check_type=check_type, severity=severity,
                        reason=reason, value=1.0, threshold=1.0)


# ----------------------------------------------------------------------
def test_none_on_clean_data():
    engine = ResponseEngine(CONFIG)
    report = make_report()
    decision = engine.decide(report, None, current_time_s=0.0)
    assert decision.actions in ([ResponseAction.NONE], [])


def test_flag_only_on_gps_physics():
    engine = ResponseEngine(CONFIG)
    report = make_report(scores={'gps': 0.85}, flags=[flag('gps', 'physics')])
    decision = engine.decide(report, None, current_time_s=0.0)
    assert ResponseAction.FLAG_ONLY in decision.actions


def test_reduce_gps_weight_on_degraded():
    engine = ResponseEngine(CONFIG)
    report = make_report(scores={'gps': 0.55}, flags=[flag('gps', 'physics')])
    decision = engine.decide(report, None, current_time_s=0.0)
    assert ResponseAction.REDUCE_GPS_WEIGHT in decision.actions


def test_isolate_gps_on_untrusted_cross_sensor():
    engine = ResponseEngine(CONFIG)
    report = make_report(scores={'gps': 0.25}, flags=[flag('gps', 'cross_sensor')])
    decision = engine.decide(report, None, current_time_s=0.0)
    assert ResponseAction.ISOLATE_GPS in decision.actions


def test_reject_command_on_whitelist_violation():
    engine = ResponseEngine(CONFIG)
    report = make_report(
        scores={'commands': 0.9},
        flags=[flag('commands', 'physics', reason='Command id 999 not in allowed whitelist')])
    decision = engine.decide(report, None, current_time_s=0.0)
    assert ResponseAction.REJECT_COMMAND in decision.actions


def test_hover_on_low_overall_trust():
    engine = ResponseEngine(CONFIG)
    report = make_report(scores={c: 0.35 for c in COMPONENTS})
    decision = engine.decide(report, None, current_time_s=0.0)
    assert ResponseAction.COMMAND_HOVER in decision.actions


def test_rth_on_critical_trust():
    engine = ResponseEngine(CONFIG)
    report = make_report(scores={c: 0.25 for c in COMPONENTS})
    decision = engine.decide(report, None, current_time_s=0.0)
    assert ResponseAction.COMMAND_RTH in decision.actions


def test_land_on_zero_trust_high_confidence():
    engine = ResponseEngine(CONFIG)
    report = make_report(scores={c: 0.0 for c in COMPONENTS})
    decision = engine.decide(report, FakeAnomalyResult(confidence=0.9), current_time_s=0.0)
    assert ResponseAction.COMMAND_LAND in decision.actions


def test_escalation_guard_no_de_escalation():
    engine = ResponseEngine(CONFIG)
    hover_report = make_report(scores={c: 0.35 for c in COMPONENTS})
    decision = engine.decide(hover_report, None, current_time_s=0.0)
    assert decision.response_level >= 3

    clean_report = make_report()
    decision = engine.decide(clean_report, None, current_time_s=1.0)
    assert decision.response_level >= 3


def test_hysteresis_hover_cancel():
    engine = ResponseEngine(CONFIG)
    hover_report = make_report(scores={c: 0.35 for c in COMPONENTS})
    engine.decide(hover_report, None, current_time_s=0.0)

    clean_report = make_report(scores={c: 0.75 for c in COMPONENTS})
    decision = None
    for i in range(5):
        decision = engine.decide(clean_report, None, current_time_s=1.0 + i * 0.1)

    assert ResponseAction.COMMAND_HOVER not in decision.actions


def test_rth_never_cancelled():
    engine = ResponseEngine(CONFIG)
    rth_report = make_report(scores={c: 0.25 for c in COMPONENTS})
    engine.decide(rth_report, None, current_time_s=0.0)

    clean_report = make_report()
    decision = None
    for i in range(20):
        decision = engine.decide(clean_report, None, current_time_s=1.0 + i * 0.1)

    assert ResponseAction.COMMAND_RTH in decision.actions
