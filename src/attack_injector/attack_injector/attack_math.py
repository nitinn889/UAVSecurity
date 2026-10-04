"""Pure attack-math functions used by injector_node.py, extracted so they
are unit-testable without any ROS 2 runtime (see test/test_injector.py)."""

METERS_PER_DEGREE_LAT = 111111.0

INVALID_COMMAND_ID = 999
ARM_COMMAND_ID = 400

REPORT_REQUIRED_FIELDS = [
    'attack_type',
    'attack_start_us',
    'attack_end_us',
    'attack_duration_s',
    'first_detection_us',
    'detection_latency_s',
    'total_flags_during_attack',
    'flags_by_type',
    'ml_anomaly_detections',
    'score_minimums',
    'post_attack_recovery_time_s',
    'false_positives_pre_attack',
]


def meters_to_lat_degrees(meters: float) -> float:
    """Northward offset in meters -> latitude degrees (lon offset is 0 for
    a pure-northward spoof, per Task 2)."""
    return meters / METERS_PER_DEGREE_LAT


def gps_spoof_ramp_fraction(elapsed_s: float, ramp_s: float) -> float:
    """0.0 at elapsed_s=0, linearly rising to 1.0 at elapsed_s=ramp_s, then
    held at 1.0 (hold phase) for elapsed_s beyond ramp_s."""
    if ramp_s <= 0:
        return 1.0
    return max(0.0, min(1.0, elapsed_s / ramp_s))


def apply_gps_position_spoof(lat_deg: float, offset_deg: float, fraction: float) -> float:
    return lat_deg + offset_deg * fraction


def freeze_gps_reading(captured: dict) -> dict:
    """Returns an identical copy of the captured GPS reading every time --
    the whole point of a freeze attack is that repeated calls are identical."""
    return dict(captured)


def build_command_injection(command_id: int, param1: float, timestamp_us: int,
                             target_system: int = 1, target_component: int = 1,
                             source_system: int = 99, source_component: int = 0) -> dict:
    return {
        'command': command_id,
        'param1': param1,
        'param2': 0.0,
        'target_system': target_system,
        'target_component': target_component,
        'source_system': source_system,
        'source_component': source_component,
        'from_external': True,
        'timestamp': timestamp_us,
    }


def build_invalid_command(timestamp_us: int) -> dict:
    return build_command_injection(INVALID_COMMAND_ID, 0.0, timestamp_us)


def build_arm_flood_command(timestamp_us: int) -> dict:
    return build_command_injection(ARM_COMMAND_ID, 1.0, timestamp_us)


def detection_latency_s(attack_start_us: int, first_detection_us: int) -> float:
    return (first_detection_us - attack_start_us) / 1e6


def amplify_imu_axis(value: float, scale: float) -> float:
    return value * scale
