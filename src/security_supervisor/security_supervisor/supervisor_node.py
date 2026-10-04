import json
import os
import secrets

import rclpy
from rclpy.executors import MultiThreadedExecutor
from rclpy.node import Node
from rclpy.parameter import Parameter
from rclpy.parameter_client import AsyncParameterClient
from std_msgs.msg import Bool, String

from security_supervisor.anomaly_detector import AnomalyDetector
from security_supervisor.crypto_channel import CryptoError, ReplayError
from security_supervisor.crypto_config import build_channel
from security_supervisor.data_logger import DataLogger
from security_supervisor.response_engine import ResponseAction, ResponseEngine
from security_supervisor.trust_engine import AnomalyFlag, TrustEngine

TRUST_SCORES_RATE_HZ = 10.0
STATUS_RATE_HZ = 1.0
RESPONSE_ACTIONS_RATE_HZ = 10.0
WATCHDOG_RATE_HZ = 1.0

DEFAULT_MODEL_DIR = os.path.expanduser('~/uav_security_ws/models')

# Phase 6 Task 4: how long without a /security/replay/sensor_snapshot
# message before we conclude the injector's replay attack has ended and
# ask sensor_monitor to fall back to live data.
REPLAY_WATCHDOG_TIMEOUT_S = 3.0

COMPONENT_LABELS = {
    'gps': 'GPS', 'imu': 'IMU', 'barometer': 'BARO',
    'attitude': 'ATT', 'commands': 'CMD',
}

# Maps a feature_engineer.py feature name to the TrustEngine component it
# implies, so an ML anomaly's top_features can attribute its penalty to the
# right component even when TrustEngine itself didn't flag anything this
# cycle. 'attitude_*' isn't in the Task 5 spec's mapping list (which only
# gives gps_*, imu_*/accel_*/gyro_*, baro_*, ekf_*) — added since otherwise
# an anomaly driven purely by roll/pitch features couldn't be attributed to
# any component at all.
FEATURE_COMPONENT_PREFIXES = [
    ('gps_', 'gps'),
    ('ekf_', 'gps'),
    ('imu_', 'imu'),
    ('accel_', 'imu'),
    ('gyro_', 'imu'),
    ('baro_', 'barometer'),
    ('attitude_', 'attitude'),
]

ARMING_STATE_ARMED = 2  # px4_msgs.msg.VehicleStatus.ARMING_STATE_ARMED


def feature_to_component(feature_name: str):
    for prefix, component in FEATURE_COMPONENT_PREFIXES:
        if feature_name.startswith(prefix):
            return component
    return None


def _flag_to_dict(flag: AnomalyFlag) -> dict:
    return {
        'component': flag.component,
        'check_type': flag.check_type,
        'severity': flag.severity,
        'reason': flag.reason,
        'value': flag.value,
        'threshold': flag.threshold,
    }


class TrustMonitor(Node):
    """Subscribes to /security/sensor_snapshot, runs it through TrustEngine
    (rule-based) + AnomalyDetector (ML), fuses the two, decides + executes
    a response via ResponseEngine, and publishes /security/trust_scores
    (10 Hz), /security/status (1 Hz), and /security/response_actions (10 Hz)."""

    def __init__(self, model_dir: str = DEFAULT_MODEL_DIR):
        super().__init__('trust_monitor')

        self.trust_engine = TrustEngine()
        self.anomaly_detector = AnomalyDetector(model_dir)
        self.response_engine = ResponseEngine(self.trust_engine.cfg)

        self.latest_report = None
        self.latest_anomaly = None
        self.latest_decision = None
        self.latest_snapshot = None

        # Task 3 action state.
        self.gps_isolated = False
        self.imu_isolated = False
        self.is_airborne = False
        self._rth_published = False
        self._land_published = False

        # Task 4 telemetry-replay watchdog state.
        self._last_replay_msg_time = None
        self._replay_ever_seen = False
        self._replay_fallback_triggered = False
        self._sensor_monitor_param_client = AsyncParameterClient(self, 'sensor_monitor')

        qos = 10
        self.snapshot_sub = self.create_subscription(
            String, '/security/sensor_snapshot', self._snapshot_cb, qos)
        self.replay_watchdog_sub = self.create_subscription(
            String, '/security/replay/sensor_snapshot', self._replay_watchdog_cb, qos)

        self.trust_scores_pub = self.create_publisher(String, '/security/trust_scores', qos)
        self.status_pub = self.create_publisher(String, '/security/status', qos)
        self.response_actions_pub = self.create_publisher(String, '/security/response_actions', qos)

        self.gps_isolated_pub = self.create_publisher(Bool, '/security/gps_isolated', qos)
        self.imu_isolated_pub = self.create_publisher(Bool, '/security/imu_isolated', qos)
        self.degraded_mode_pub = self.create_publisher(Bool, '/security/degraded_mode', qos)
        self.key_rotation_pub = self.create_publisher(String, '/security/key_rotation', qos)
        self.rejected_commands_pub = self.create_publisher(String, '/security/rejected_commands', qos)

        # Phase 7: this node runs on the Raspberry Pi, which does not build
        # px4_msgs. Mitigations that need a real /fmu/in/* write are emitted
        # as JSON intents here and translated back into px4_msgs by
        # actuator_node, which stays on the PC next to the DDS agent.
        self.mitigation_intent_pub = self.create_publisher(
            String, '/security/mitigation_intent', qos)

        # Phase 9: opens sealed snapshots from sensor_monitor (PC->Pi) and
        # seals mitigation intents for actuator_node (Pi->PC).
        self.channel, self.crypto_cfg = build_channel('supervisor', logger=self.get_logger())
        self.crypto_events_pub = self.create_publisher(String, '/security/crypto_events', qos)
        self._crypto_replays = 0
        self._crypto_auth_failures = 0
        events_hz = float(self.crypto_cfg.get('events_rate_hz') or 0.0)
        if events_hz > 0:
            self.create_timer(1.0 / events_hz, self._publish_crypto_events)

        self.create_timer(1.0 / TRUST_SCORES_RATE_HZ, self._publish_trust_scores)
        self.create_timer(1.0 / STATUS_RATE_HZ, self._publish_status)
        self.create_timer(1.0 / RESPONSE_ACTIONS_RATE_HZ, self._publish_response_actions)
        self.create_timer(1.0 / WATCHDOG_RATE_HZ, self._check_replay_watchdog)

        self.get_logger().info(
            f'trust_monitor up: /security/sensor_snapshot -> '
            f'/security/trust_scores @ {TRUST_SCORES_RATE_HZ:.0f} Hz, '
            f'/security/status @ {STATUS_RATE_HZ:.0f} Hz, '
            f'/security/response_actions @ {RESPONSE_ACTIONS_RATE_HZ:.0f} Hz '
            f'(TrustEngine + AnomalyDetector[{model_dir}] + ResponseEngine)')

    # ------------------------------------------------------------------
    def _snapshot_cb(self, msg):
        payload, crypto_error = self.channel.open_with_status(msg.data)

        if isinstance(crypto_error, ReplayError):
            # Authentic bytes, stale sequence number -- i.e. replayed
            # telemetry. Whether that is fatal is a deployment choice; see
            # crypto.drop_replayed in security_config.yaml for why the
            # default still forwards it to the trust pipeline.
            self._crypto_replays += 1
            self.get_logger().warning(f'[t={self._now_us()}] CRYPTO REPLAY: {crypto_error}')
            if self.crypto_cfg.get('drop_replayed'):
                return
        elif isinstance(crypto_error, CryptoError):
            # Forged, tampered, or sealed under a key we do not hold. There
            # is no safe interpretation of these bytes, so they never reach
            # TrustEngine regardless of configuration.
            self._crypto_auth_failures += 1
            self.get_logger().error(
                f'[t={self._now_us()}] CRYPTO REJECT: {crypto_error}')
            return

        try:
            snapshot = json.loads(payload)
        except json.JSONDecodeError:
            self.get_logger().warning('Discarded malformed sensor_snapshot')
            return

        self.latest_snapshot = snapshot
        vstatus = snapshot.get('vehicle_status')
        if vstatus is not None:
            self.is_airborne = vstatus.get('arming_state') == ARMING_STATE_ARMED

        trust_report = self.trust_engine.update(snapshot)
        anomaly_result = self.anomaly_detector.update(snapshot)

        if (anomaly_result is not None and anomaly_result.is_anomaly
                and anomaly_result.confidence >= self.trust_engine.cfg['ml_confidence_min']):
            self._apply_ml_penalty(trust_report, anomaly_result)

        now_s = self.get_clock().now().nanoseconds / 1e9
        decision = self.response_engine.decide(trust_report, anomaly_result, now_s)
        self._execute_actions(decision)

        self.latest_report = trust_report
        self.latest_anomaly = anomaly_result
        self.latest_decision = decision

    def _apply_ml_penalty(self, trust_report, anomaly_result):
        cfg = self.trust_engine.cfg
        flagged_components = {f.component for f in trust_report.flags}
        implied_components = {feature_to_component(f) for f in anomaly_result.top_features}
        implied_components.discard(None)
        components_to_penalize = flagged_components | implied_components

        ml_penalty = anomaly_result.confidence * cfg['ml_trust_penalty_scale']

        for component in components_to_penalize:
            if component not in trust_report.scores:
                continue
            new_score = trust_report.scores[component] - ml_penalty
            new_score = max(cfg['score_min'], min(cfg['score_max'], new_score))
            trust_report.scores[component] = new_score
            # Write back into the engine's own persistent state too, so the
            # penalty isn't silently discarded on the next update() cycle
            # (TrustReport.scores is a fresh dict copy, not a live view).
            self.trust_engine.scores[component] = new_score

        trust_report.overall_trust = min(trust_report.scores.values())

    # ------------------------------------------------------------------
    # Task 3: action execution
    # ------------------------------------------------------------------
    def _execute_actions(self, decision):
        dispatch = {
            ResponseAction.NONE: lambda reason: None,
            ResponseAction.FLAG_ONLY: self._action_flag_only,
            ResponseAction.REDUCE_GPS_WEIGHT: self._action_reduce_gps_weight,
            ResponseAction.REJECT_COMMAND: self._action_reject_command,
            ResponseAction.ISOLATE_GPS: self._action_isolate_gps,
            ResponseAction.ISOLATE_IMU: self._action_isolate_imu,
            ResponseAction.ROTATE_ENCRYPTION_KEY: self._action_rotate_key,
            ResponseAction.ENTER_DEGRADED_MODE: self._action_degraded_mode,
            ResponseAction.COMMAND_HOVER: self._action_hover,
            ResponseAction.COMMAND_RTH: self._action_rth,
            ResponseAction.COMMAND_LAND: self._action_land,
        }
        for action, reason in zip(decision.actions, decision.reasons):
            dispatch[action](reason)

    def _now_us(self):
        return int(self.get_clock().now().nanoseconds / 1000)

    def _action_flag_only(self, reason):
        self.get_logger().info(f'[t={self._now_us()}] FLAG: {reason}')

    def _publish_intent(self, action, reason, **params):
        payload = {'timestamp_us': self._now_us(), 'action': action, 'reason': reason}
        if params:
            payload['params'] = params
        msg = String()
        msg.data = self.channel.seal(json.dumps(payload))
        self.mitigation_intent_pub.publish(msg)

    def _action_reduce_gps_weight(self, reason):
        # 0.5 simulates de-weighting by halving the declared GPS accuracy.
        self._publish_intent('REDUCE_GPS_WEIGHT', reason, gps_accuracy_scale=0.5)
        self.get_logger().warning(f'[t={self._now_us()}] GPS weight reduced -- EKF de-weighting GPS ({reason})')

    def _action_isolate_gps(self, reason):
        self.gps_isolated = True
        self.gps_isolated_pub.publish(Bool(data=True))
        self.get_logger().warning(
            f'[t={self._now_us()}] GPS ISOLATED -- switching to IMU-dead-reckoning navigation ({reason})')

    def _action_isolate_imu(self, reason):
        self.imu_isolated = True
        self.imu_isolated_pub.publish(Bool(data=True))
        self.get_logger().warning(
            f'[t={self._now_us()}] IMU ISOLATED -- attitude reference flagged unreliable ({reason})')

    def _action_reject_command(self, reason):
        last_cmd = (self.latest_snapshot or {}).get('last_command') or {}
        rejected = {
            'timestamp_us': self._now_us(),
            'rejected_cmd_id': last_cmd.get('command'),
            'param1': last_cmd.get('param1'),
            'param2': last_cmd.get('param2'),
            'reason': reason,
        }
        msg = String()
        msg.data = json.dumps(rejected)
        self.rejected_commands_pub.publish(msg)
        self.get_logger().warning(f'[t={self._now_us()}] Command rejected: {rejected}')

    def _action_rotate_key(self, reason):
        # Advances this channel's key epoch. Every subsequent intent is
        # sealed under HKDF(root_key, epoch), and receivers derive the same
        # key from the epoch carried in the envelope header -- so no key
        # material is transmitted and no handshake is needed. The published
        # message is advisory (for the dashboard/logs); the rotation itself
        # is what the epoch bump accomplishes.
        new_epoch = self.channel.rotate()
        payload = {
            'timestamp_us': self._now_us(),
            'epoch': new_epoch,
            'nonce': secrets.token_hex(16),
            'reason': reason,
        }
        msg = String()
        msg.data = json.dumps(payload)
        self.key_rotation_pub.publish(msg)
        self.get_logger().info(
            f'[t={self._now_us()}] Encryption key rotated to epoch {new_epoch} ({reason})')

    def _action_degraded_mode(self, reason):
        self.degraded_mode_pub.publish(Bool(data=True))
        self.get_logger().warning(
            f'[t={self._now_us()}] DEGRADED MODE ACTIVE -- velocity/altitude limits engaged ({reason})')

    def _action_hover(self, reason):
        if not self.is_airborne:
            self.get_logger().info(
                f'[t={self._now_us()}] HOVER decided but vehicle not airborne -- skipping publish ({reason})')
            return
        self._publish_intent('COMMAND_HOVER', reason)
        self.get_logger().warning(
            f'[t={self._now_us()}] HOVER COMMANDED -- holding position due to security threat ({reason})')

    def _action_rth(self, reason):
        if self._rth_published:
            return
        self._rth_published = True
        self._publish_intent('COMMAND_RTH', reason)
        self.get_logger().error(f'[t={self._now_us()}] RETURN TO HOME COMMANDED -- threat level critical ({reason})')

    def _action_land(self, reason):
        if self._land_published:
            return
        self._land_published = True
        self._publish_intent('COMMAND_LAND', reason)
        self.get_logger().error(f'[t={self._now_us()}] EMERGENCY LAND COMMANDED -- trust fully lost ({reason})')

    # ------------------------------------------------------------------
    # Task 4: telemetry replay watchdog
    # ------------------------------------------------------------------
    def _replay_watchdog_cb(self, msg):
        self._last_replay_msg_time = self.get_clock().now().nanoseconds / 1e9
        self._replay_ever_seen = True
        self._replay_fallback_triggered = False

    def _check_replay_watchdog(self):
        if not self._replay_ever_seen or self._replay_fallback_triggered:
            return
        if self._last_replay_msg_time is None:
            return
        now_s = self.get_clock().now().nanoseconds / 1e9
        if (now_s - self._last_replay_msg_time) > REPLAY_WATCHDOG_TIMEOUT_S:
            self._replay_fallback_triggered = True
            future = self._sensor_monitor_param_client.set_parameters(
                [Parameter('use_replay_telemetry', Parameter.Type.BOOL, False)])
            future.add_done_callback(self._replay_fallback_done)
            self.get_logger().warning(
                'Telemetry replay stream ended -- reverting sensor_monitor to live sensor data')

    def _replay_fallback_done(self, future):
        try:
            result = future.result()
            ok = bool(result.results) and result.results[0].successful
            if not ok:
                self.get_logger().error(
                    f'Failed to set sensor_monitor.use_replay_telemetry=false: '
                    f'{result.results[0].reason if result.results else "no response"}')
        except Exception as exc:  # noqa: BLE001 -- log and move on, don't crash the node
            self.get_logger().error(f'Error reverting sensor_monitor to live telemetry: {exc}')

    # ------------------------------------------------------------------
    # Publishers
    # ------------------------------------------------------------------
    def _publish_crypto_events(self):
        stats = self.channel.stats()
        stats['timestamp_us'] = self._now_us()
        stats['replays_forwarded'] = (
            0 if self.crypto_cfg.get('drop_replayed') else self._crypto_replays)
        stats['rejected_auth'] = self._crypto_auth_failures
        msg = String()
        msg.data = json.dumps(stats)
        self.crypto_events_pub.publish(msg)

    def _publish_trust_scores(self):
        if self.latest_report is None:
            return
        report = self.latest_report
        payload = {
            'timestamp_us': report.timestamp_us,
            'scores': report.scores,
            'overall_trust': report.overall_trust,
            'flags': [_flag_to_dict(f) for f in report.flags],
        }
        if self.latest_anomaly is not None:
            payload['ml_anomaly'] = {
                'is_anomaly': self.latest_anomaly.is_anomaly,
                'anomaly_score': self.latest_anomaly.anomaly_score,
                'confidence': self.latest_anomaly.confidence,
                'top_features': self.latest_anomaly.top_features,
            }
        if self.latest_decision is not None:
            payload['response'] = self._decision_to_dict(self.latest_decision)

        msg = String()
        msg.data = json.dumps(payload)
        self.trust_scores_pub.publish(msg)

    def _publish_response_actions(self):
        if self.latest_decision is None:
            return
        msg = String()
        msg.data = json.dumps(self._decision_to_dict(self.latest_decision))
        self.response_actions_pub.publish(msg)

    @staticmethod
    def _decision_to_dict(decision):
        return {
            'actions': [a.value for a in decision.actions],
            'reasons': decision.reasons,
            'response_level': decision.response_level,
            'incident_active': decision.incident_active,
        }

    def _publish_status(self):
        if self.latest_report is None:
            return
        report = self.latest_report
        overall_label = self.trust_engine.status_label(report.overall_trust)

        parts = [f'{COMPONENT_LABELS[c]}:{report.scores[c]:.2f}' for c in report.scores]
        line = f'[{overall_label}] ' + ' '.join(parts)

        if report.flags:
            worst = max(report.flags, key=lambda f: ('minor', 'moderate', 'severe').index(f.severity))
            line += f' | FLAG: {worst.component} {worst.check_type} {worst.severity}'

        if self.latest_decision is not None and self.latest_decision.response_level > 0:
            line += f' | RESPONSE: level={self.latest_decision.response_level} {[a.value for a in self.latest_decision.actions]}'

        msg = String()
        msg.data = line
        self.status_pub.publish(msg)


def main(args=None):
    """data_logger + trust_monitor (TrustEngine + AnomalyDetector +
    ResponseEngine), spun concurrently in one process via a
    MultiThreadedExecutor.

    Phase 5 note: sensor_monitor is no longer bundled here -- it runs as
    its own separate node/process (see attack_injector's launch files),
    since it now needs independent 'use_spoofed_gps'/'use_spoofed_imu'/
    'use_replay_telemetry' parameters per attack scenario. Bundling both
    would create two same-named 'sensor_monitor' nodes both publishing
    /security/sensor_snapshot whenever supervisor_node and a standalone
    sensor_monitor run together, which is exactly what Phase 5's launch
    files do. Always launch sensor_monitor alongside this."""
    rclpy.init(args=args)

    data_logger = DataLogger()
    trust_monitor = TrustMonitor()

    executor = MultiThreadedExecutor()
    executor.add_node(data_logger)
    executor.add_node(trust_monitor)

    try:
        executor.spin()
    except KeyboardInterrupt:
        pass
    finally:
        executor.shutdown()
        data_logger.close()
        data_logger.destroy_node()
        trust_monitor.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == '__main__':
    main()
