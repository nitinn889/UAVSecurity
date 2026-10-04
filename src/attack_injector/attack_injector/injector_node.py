"""Attack injection / red-team evaluation node (Phase 5).

Shadows the real PX4 sensor stream (GPS, IMU) on /security/spoofed/* topics
and injects forged commands directly on /fmu/in/vehicle_command, on demand,
for one attack scenario per node instance (see the 'attack_type' parameter).
Also acts as the evaluation harness: it watches /security/trust_scores for
detection events and writes a per-attack JSON report on shutdown.

State machine (all times measured on this node's own ROS clock):
  PRE_ATTACK (attack_delay_s)  -> ACTIVE (attack_duration_s)
    -> POST_ATTACK (10s recovery window) -> DONE (node exits)
"""
import json
import math
import os
import random
from collections import deque
from datetime import datetime, timezone

import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, QoSReliabilityPolicy, QoSHistoryPolicy, QoSDurabilityPolicy
from std_msgs.msg import String

from px4_msgs.msg import SensorGps, SensorCombined, VehicleCommand

from attack_injector import attack_math as am

STATE_PRE_ATTACK = 'pre_attack'
STATE_ACTIVE = 'active'
STATE_POST_ATTACK = 'post_attack'
STATE_DONE = 'done'

POST_ATTACK_WINDOW_S = 10.0
TELEMETRY_BUFFER_MAXLEN = 50
TICK_HZ = 10.0

TOPIC_GPS = '/fmu/out/vehicle_gps_position'
TOPIC_SENSOR_COMBINED = '/fmu/out/sensor_combined'
TOPIC_VEHICLE_COMMAND = '/fmu/in/vehicle_command'
TOPIC_SPOOFED_GPS = '/security/spoofed/gps'
TOPIC_SPOOFED_IMU = '/security/spoofed/imu'
TOPIC_REPLAY_SNAPSHOT = '/security/replay/sensor_snapshot'

VALID_ATTACK_TYPES = (
    'gps_spoof', 'gps_freeze', 'cmd_inject', 'imu_noise', 'telemetry_replay', 'gps_deny',
)

FLAG_CHECK_TYPES = ('physics', 'cross_sensor', 'temporal')
COMPONENTS = ('gps', 'imu', 'barometer', 'attitude', 'commands')
DEGRADED_THRESHOLD = 0.7


class InjectorNode(Node):
    def __init__(self):
        super().__init__('injector_node')

        self.declare_parameter('attack_type', 'gps_spoof')
        self.declare_parameter('attack_duration_s', 15.0)
        self.declare_parameter('attack_delay_s', 5.0)
        self.declare_parameter('gps_spoof_offset_m', 50.0)
        self.declare_parameter('gps_spoof_ramp_s', 3.0)
        self.declare_parameter('imu_noise_scale', 8.0)
        self.declare_parameter('cmd_inject_rate_hz', 3.0)
        self.declare_parameter('log_dir', '~/uav_security_ws/data/attack_logs')

        self.attack_type = self.get_parameter('attack_type').value
        if self.attack_type not in VALID_ATTACK_TYPES:
            raise ValueError(
                f"attack_type must be one of {VALID_ATTACK_TYPES}, got '{self.attack_type}'")
        self.attack_duration_s = float(self.get_parameter('attack_duration_s').value)
        self.attack_delay_s = float(self.get_parameter('attack_delay_s').value)
        self.gps_spoof_offset_m = float(self.get_parameter('gps_spoof_offset_m').value)
        self.gps_spoof_ramp_s = float(self.get_parameter('gps_spoof_ramp_s').value)
        self.imu_noise_scale = float(self.get_parameter('imu_noise_scale').value)
        self.cmd_inject_rate_hz = float(self.get_parameter('cmd_inject_rate_hz').value)
        self.log_dir = os.path.expanduser(self.get_parameter('log_dir').value)

        qos_best_effort = QoSProfile(
            reliability=QoSReliabilityPolicy.BEST_EFFORT,
            durability=QoSDurabilityPolicy.VOLATILE,
            history=QoSHistoryPolicy.KEEP_LAST,
            depth=1,
        )

        # --- Always-active subscriptions (Task 1) ---
        self.create_subscription(SensorGps, TOPIC_GPS, self._gps_cb, qos_best_effort)
        self.create_subscription(SensorCombined, TOPIC_SENSOR_COMBINED, self._imu_cb, qos_best_effort)
        self.create_subscription(String, '/security/sensor_snapshot', self._snapshot_cb, 10)
        self.create_subscription(String, '/security/trust_scores', self._trust_scores_cb, 10)
        self.create_subscription(String, '/security/response_actions', self._response_actions_cb, 10)

        # --- Conditional publications ---
        self.spoofed_gps_pub = self.create_publisher(SensorGps, TOPIC_SPOOFED_GPS, qos_best_effort)
        self.spoofed_imu_pub = self.create_publisher(SensorCombined, TOPIC_SPOOFED_IMU, qos_best_effort)
        self.replay_pub = self.create_publisher(String, TOPIC_REPLAY_SNAPSHOT, 10)
        self.command_pub = self.create_publisher(VehicleCommand, TOPIC_VEHICLE_COMMAND, 10)

        # --- State machine ---
        self.state = STATE_PRE_ATTACK
        self.node_start_time = self.get_clock().now()
        self.attack_start_us = None
        self.attack_end_us = None
        self._active_start_time = None  # rclpy Time, for gps_spoof ramp elapsed calc

        # --- gps_freeze state ---
        self._frozen_gps_reading = None

        # --- telemetry_replay state ---
        self._replay_buffer = deque(maxlen=TELEMETRY_BUFFER_MAXLEN)
        self._replay_index = 0

        # --- cmd_inject state ---
        self._arm_flood_offsets_s = sorted(
            random.uniform(0.0, self.attack_duration_s) for _ in range(3))
        self._arm_flood_fired = [False, False, False]
        self._last_invalid_cmd_time = None

        # --- Task 10: detection event tracking ---
        self.total_flags_during_attack = 0
        self.flags_by_type = {t: 0 for t in FLAG_CHECK_TYPES}
        self.ml_anomaly_detections = 0
        self.score_minimums = {c: 1.0 for c in COMPONENTS}
        self.first_detection_us = None
        self.false_positives_pre_attack = 0
        self.recovery_started_us = None
        self.post_attack_recovery_time_s = None
        self._recovered = False

        # --- Task 6 (Phase 6): response action tracking ---
        self.response_actions_fired = set()
        self.first_response_action_us = None
        self.highest_response_level_reached = 0
        self.hover_commanded = False
        self.rth_commanded = False
        self.land_commanded = False

        self.get_logger().info(
            f'injector_node up: attack_type={self.attack_type} '
            f'delay={self.attack_delay_s}s duration={self.attack_duration_s}s')

        self.create_timer(1.0 / TICK_HZ, self._tick)
        self.create_timer(
            1.0 / self.cmd_inject_rate_hz if self.cmd_inject_rate_hz > 0 else 1.0,
            self._cmd_inject_tick)

        self._done = False

    # ------------------------------------------------------------------
    # State machine
    # ------------------------------------------------------------------
    def _elapsed_since_start_s(self) -> float:
        return (self.get_clock().now() - self.node_start_time).nanoseconds / 1e9

    def _now_us(self) -> int:
        return int(self.get_clock().now().nanoseconds / 1000)

    def _tick(self):
        elapsed = self._elapsed_since_start_s()

        if self.state == STATE_PRE_ATTACK and elapsed >= self.attack_delay_s:
            self.state = STATE_ACTIVE
            self.attack_start_us = self._now_us()
            self._active_start_time = self.get_clock().now()
            self.get_logger().info(f'ATTACK START: {self.attack_type} at t={self.attack_start_us}')

        elif self.state == STATE_ACTIVE and elapsed >= self.attack_delay_s + self.attack_duration_s:
            self.state = STATE_POST_ATTACK
            self.attack_end_us = self._now_us()
            self.recovery_started_us = self.attack_end_us
            self.get_logger().info(f'ATTACK END: {self.attack_type} at t={self.attack_end_us}')

        elif (self.state == STATE_POST_ATTACK
              and elapsed >= self.attack_delay_s + self.attack_duration_s + POST_ATTACK_WINDOW_S):
            self.state = STATE_DONE
            self._done = True

        if self.state == STATE_ACTIVE and self.attack_type == 'telemetry_replay':
            self._replay_tick()

    def _active_elapsed_s(self) -> float:
        if self._active_start_time is None:
            return 0.0
        return (self.get_clock().now() - self._active_start_time).nanoseconds / 1e9

    # ------------------------------------------------------------------
    # GPS shadow topic (gps_spoof, gps_freeze, gps_deny)
    # ------------------------------------------------------------------
    def _gps_cb(self, msg: SensorGps):
        if self.attack_type == 'gps_spoof' and self.state == STATE_ACTIVE:
            fraction = am.gps_spoof_ramp_fraction(self._active_elapsed_s(), self.gps_spoof_ramp_s)
            offset_deg = am.meters_to_lat_degrees(self.gps_spoof_offset_m)
            msg.latitude_deg = am.apply_gps_position_spoof(msg.latitude_deg, offset_deg, fraction)
            self.spoofed_gps_pub.publish(msg)

        elif self.attack_type == 'gps_freeze' and self.state == STATE_ACTIVE:
            if self._frozen_gps_reading is None:
                self._frozen_gps_reading = am.freeze_gps_reading({
                    'latitude_deg': msg.latitude_deg,
                    'longitude_deg': msg.longitude_deg,
                    'altitude_msl_m': msg.altitude_msl_m,
                    'vel_n_m_s': msg.vel_n_m_s,
                    'vel_e_m_s': msg.vel_e_m_s,
                    'vel_d_m_s': msg.vel_d_m_s,
                })
                self.get_logger().info(f'GPS frozen at {self._frozen_gps_reading}')
            frozen = am.freeze_gps_reading(self._frozen_gps_reading)
            msg.latitude_deg = frozen['latitude_deg']
            msg.longitude_deg = frozen['longitude_deg']
            msg.altitude_msl_m = frozen['altitude_msl_m']
            msg.vel_n_m_s = frozen['vel_n_m_s']
            msg.vel_e_m_s = frozen['vel_e_m_s']
            msg.vel_d_m_s = frozen['vel_d_m_s']
            msg.timestamp = self._now_us()  # re-stamped with current time, per Task 3
            self.spoofed_gps_pub.publish(msg)

        elif self.attack_type == 'gps_deny' and self.state == STATE_ACTIVE:
            pass  # do not republish -- this is the attack

        else:
            # Not this node's attack, or not currently active: pass through
            # unmodified so pre-/post-attack monitoring sees real GPS data.
            self.spoofed_gps_pub.publish(msg)

    # ------------------------------------------------------------------
    # IMU shadow topic (imu_noise)
    # ------------------------------------------------------------------
    def _imu_cb(self, msg: SensorCombined):
        if self.attack_type == 'imu_noise' and self.state == STATE_ACTIVE:
            accel = msg.accelerometer_m_s2
            msg.accelerometer_m_s2 = [
                am.amplify_imu_axis(float(accel[0]), self.imu_noise_scale),
                am.amplify_imu_axis(float(accel[1]), self.imu_noise_scale),
                am.amplify_imu_axis(float(accel[2]), self.imu_noise_scale),
            ]
        self.spoofed_imu_pub.publish(msg)

    # ------------------------------------------------------------------
    # Telemetry replay (buffer + loop republish)
    # ------------------------------------------------------------------
    def _snapshot_cb(self, msg: String):
        if self.attack_type != 'telemetry_replay':
            return
        if self.state in (STATE_PRE_ATTACK,):
            self._replay_buffer.append(msg.data)

    def _replay_tick(self):
        if not self._replay_buffer:
            return
        data = self._replay_buffer[self._replay_index % len(self._replay_buffer)]
        self._replay_index += 1
        out = String()
        out.data = data
        self.replay_pub.publish(out)

    # ------------------------------------------------------------------
    # Command injection
    # ------------------------------------------------------------------
    def _cmd_inject_tick(self):
        if self.attack_type != 'cmd_inject' or self.state != STATE_ACTIVE:
            return
        cmd_dict = am.build_invalid_command(self._now_us())
        self._publish_command(cmd_dict)

        active_elapsed = self._active_elapsed_s()
        for i, offset in enumerate(self._arm_flood_offsets_s):
            if not self._arm_flood_fired[i] and active_elapsed >= offset:
                self._arm_flood_fired[i] = True
                arm_cmd = am.build_arm_flood_command(self._now_us())
                self._publish_command(arm_cmd)
                self.get_logger().info(f'ARM flood command #{i + 1}/3 injected')

    def _publish_command(self, cmd_dict: dict):
        msg = VehicleCommand()
        msg.command = cmd_dict['command']
        msg.param1 = cmd_dict['param1']
        msg.param2 = cmd_dict['param2']
        msg.target_system = cmd_dict['target_system']
        msg.target_component = cmd_dict['target_component']
        msg.source_system = cmd_dict['source_system']
        msg.source_component = cmd_dict['source_component']
        msg.from_external = cmd_dict['from_external']
        msg.timestamp = cmd_dict['timestamp']
        self.command_pub.publish(msg)

    # ------------------------------------------------------------------
    # Phase 6 Task 6: response action tracking
    # ------------------------------------------------------------------
    def _response_actions_cb(self, msg: String):
        if self.state not in (STATE_ACTIVE, STATE_POST_ATTACK):
            return
        try:
            payload = json.loads(msg.data)
        except json.JSONDecodeError:
            return

        actions = payload.get('actions', [])
        level = payload.get('response_level', 0)
        non_none_actions = [a for a in actions if a != 'NONE']

        if non_none_actions and self.first_response_action_us is None:
            self.first_response_action_us = self._now_us()
            self.get_logger().info(f'First response action at t={self.first_response_action_us}: {non_none_actions}')

        self.response_actions_fired.update(non_none_actions)
        self.highest_response_level_reached = max(self.highest_response_level_reached, level)

        if 'COMMAND_HOVER' in actions:
            self.hover_commanded = True
        if 'COMMAND_RTH' in actions:
            self.rth_commanded = True
        if 'COMMAND_LAND' in actions:
            self.land_commanded = True

    # ------------------------------------------------------------------
    # Task 10: detection event logging
    # ------------------------------------------------------------------
    def _trust_scores_cb(self, msg: String):
        try:
            report = json.loads(msg.data)
        except json.JSONDecodeError:
            return

        scores = report.get('scores', {})
        flags = report.get('flags', [])
        ml_anomaly = report.get('ml_anomaly')
        # Use OUR OWN receive-time clock for latency/recovery measurements,
        # not the message's embedded timestamp_us: telemetry_replay's whole
        # point is that field is stale (deliberately not real elapsed time),
        # so trusting it would make detection latency measure the replay
        # buffer's age instead of how fast the system actually reacted.
        receive_us = self._now_us()

        degraded = any(v < DEGRADED_THRESHOLD for v in scores.values())
        ml_flagged = bool(ml_anomaly and ml_anomaly.get('is_anomaly'))
        is_detection_event = degraded or bool(flags) or ml_flagged

        if self.state == STATE_PRE_ATTACK:
            if is_detection_event:
                self.false_positives_pre_attack += 1
            return

        if self.state == STATE_ACTIVE:
            if is_detection_event and self.first_detection_us is None:
                self.first_detection_us = receive_us
                self.get_logger().info(f'First detection at t={receive_us}')

            self.total_flags_during_attack += len(flags)
            for flag in flags:
                check_type = flag.get('check_type')
                if check_type in self.flags_by_type:
                    self.flags_by_type[check_type] += 1
            if ml_flagged:
                self.ml_anomaly_detections += 1
            for component, score in scores.items():
                if component in self.score_minimums:
                    self.score_minimums[component] = min(self.score_minimums[component], score)
            return

        if self.state == STATE_POST_ATTACK and not self._recovered:
            all_recovered = all(v > DEGRADED_THRESHOLD for v in scores.values())
            if all_recovered and self.attack_end_us is not None:
                # A message already in flight when the state transitioned
                # can carry a receive time from just before attack_end_us
                # (normal pipeline latency, not an actual negative recovery
                # time) -- floor at 0.0.
                self.post_attack_recovery_time_s = max(0.0, (receive_us - self.attack_end_us) / 1e6)
                self._recovered = True

    # ------------------------------------------------------------------
    def write_report(self):
        os.makedirs(self.log_dir, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        path = os.path.join(self.log_dir, f'attack_report_{self.attack_type}_{stamp}.json')

        detection_latency = None
        if self.first_detection_us is not None and self.attack_start_us is not None:
            detection_latency = am.detection_latency_s(self.attack_start_us, self.first_detection_us)

        first_response_latency = None
        if self.first_response_action_us is not None and self.attack_start_us is not None:
            first_response_latency = am.detection_latency_s(self.attack_start_us, self.first_response_action_us)

        report = {
            'attack_type': self.attack_type,
            'attack_start_us': self.attack_start_us,
            'attack_end_us': self.attack_end_us,
            'attack_duration_s': self.attack_duration_s,
            'first_detection_us': self.first_detection_us,
            'detection_latency_s': detection_latency,
            'total_flags_during_attack': self.total_flags_during_attack,
            'flags_by_type': self.flags_by_type,
            'ml_anomaly_detections': self.ml_anomaly_detections,
            'score_minimums': self.score_minimums,
            'post_attack_recovery_time_s': self.post_attack_recovery_time_s,
            'false_positives_pre_attack': self.false_positives_pre_attack,
            'response_actions_fired': sorted(self.response_actions_fired),
            'first_response_action_latency_s': first_response_latency,
            'highest_response_level_reached': self.highest_response_level_reached,
            'hover_commanded': self.hover_commanded,
            'rth_commanded': self.rth_commanded,
            'land_commanded': self.land_commanded,
        }
        with open(path, 'w') as handle:
            json.dump(report, handle, indent=2)

        self.get_logger().info(f'Attack report written to {path}')
        print(f'REPORT_PATH:{path}')
        return path


def main(args=None):
    rclpy.init(args=args)
    node = InjectorNode()
    try:
        while rclpy.ok() and not node._done:
            rclpy.spin_once(node, timeout_sec=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        node.write_report()
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == '__main__':
    main()
