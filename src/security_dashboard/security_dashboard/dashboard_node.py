"""Real-time security dashboard (Phase 8).

Bridges the /security/* topics into a StateStore and serves that store to a
browser over HTTP + SSE. Runs rclpy in the main thread and Flask in a daemon
thread, so Ctrl-C shuts the whole thing down cleanly.

px4_msgs is imported lazily and optionally: when present (i.e. on the PC) the
dashboard also plots the true EKF position alongside the perceived one, which
is what makes a GPS spoof legible -- the perceived track visibly peels away
from the true track as the GPS trust score collapses. On a machine without
px4_msgs (the Pi) the dashboard still works, just without that overlay.
"""

import json
import threading

import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, QoSDurabilityPolicy, QoSHistoryPolicy, QoSReliabilityPolicy
from std_msgs.msg import Bool, String

from security_supervisor.crypto_config import build_channel

from security_dashboard.state_store import StateStore
from security_dashboard.web_server import create_app

TOPIC_TRUST_SCORES = '/security/trust_scores'
TOPIC_STATUS = '/security/status'
TOPIC_RESPONSE_ACTIONS = '/security/response_actions'
TOPIC_MITIGATION_INTENT = '/security/mitigation_intent'
TOPIC_SENSOR_SNAPSHOT = '/security/sensor_snapshot'
TOPIC_TRUE_LOCAL_POS = '/fmu/out/vehicle_local_position_v1'

DEFAULT_PORT = 8080
DEFAULT_HOST = '0.0.0.0'


class DashboardNode(Node):
    """Subscribes to security event/status topics and presents them for
    operator visibility (trust scores, anomaly flags, response actions)."""

    def __init__(self):
        super().__init__('dashboard_node')

        self.declare_parameter('port', DEFAULT_PORT)
        self.declare_parameter('host', DEFAULT_HOST)
        self.declare_parameter('stream_hz', 10.0)
        self.declare_parameter('show_true_position', True)

        self.store = StateStore()

        # /security/sensor_snapshot and /security/mitigation_intent are
        # sealed by their publishers (Phase 9), so the dashboard needs the
        # same channel to read them.
        self.channel, self.crypto_cfg = build_channel(
            'dashboard', logger=self.get_logger())

        qos = 10
        self.create_subscription(String, TOPIC_TRUST_SCORES, self._trust_cb, qos)
        self.create_subscription(String, TOPIC_STATUS, self._status_cb, qos)
        self.create_subscription(String, TOPIC_RESPONSE_ACTIONS, self._response_cb, qos)
        self.create_subscription(String, TOPIC_MITIGATION_INTENT, self._intent_cb, qos)
        self.create_subscription(String, TOPIC_SENSOR_SNAPSHOT, self._snapshot_cb, qos)

        self.create_subscription(Bool, '/security/gps_isolated', self._make_bool_cb('GPS'), qos)
        self.create_subscription(Bool, '/security/imu_isolated', self._make_bool_cb('IMU'), qos)

        self._true_pos_enabled = self._maybe_subscribe_true_position()

        port = self.get_parameter('port').value
        host = self.get_parameter('host').value
        self.get_logger().info(
            f'dashboard up: http://{"localhost" if host == "0.0.0.0" else host}:{port} '
            f'(true-position overlay: {"on" if self._true_pos_enabled else "off"})')

    def _maybe_subscribe_true_position(self):
        if not self.get_parameter('show_true_position').value:
            return False
        try:
            from px4_msgs.msg import VehicleLocalPosition
        except ImportError:
            self.get_logger().info(
                'px4_msgs unavailable -- running without the true-position overlay')
            return False

        # /fmu/out/* is published BEST_EFFORT; a RELIABLE subscription silently
        # receives nothing.
        px4_qos = QoSProfile(
            reliability=QoSReliabilityPolicy.BEST_EFFORT,
            durability=QoSDurabilityPolicy.VOLATILE,
            history=QoSHistoryPolicy.KEEP_LAST,
            depth=1,
        )
        self.create_subscription(
            VehicleLocalPosition, TOPIC_TRUE_LOCAL_POS, self._true_pos_cb, px4_qos)
        return True

    # ------------------------------------------------------------------
    def _decode(self, msg, what, sealed=False):
        data = msg.data
        if sealed:
            # The dashboard is a read-only observer, so a replay here is the
            # supervisor's call to make, not ours -- take the payload and
            # display it rather than blanking the UI.
            data, error = self.channel.open_with_status(data)
            if data is None:
                self.get_logger().warning(f'Discarded undecryptable {what}: {error}')
                return None
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            self.get_logger().warning(f'Discarded malformed {what}')
            return None

    def _trust_cb(self, msg):
        payload = self._decode(msg, 'trust_scores')
        if payload is not None:
            self.store.ingest_trust_scores(payload)

    def _status_cb(self, msg):
        self.store.ingest_status(msg.data)

    def _response_cb(self, msg):
        payload = self._decode(msg, 'response_actions')
        if payload is not None:
            self.store.ingest_response_actions(payload)

    def _intent_cb(self, msg):
        payload = self._decode(msg, 'mitigation_intent', sealed=True)
        if payload is not None:
            self.store.ingest_mitigation_intent(payload)

    def _snapshot_cb(self, msg):
        payload = self._decode(msg, 'sensor_snapshot', sealed=True)
        if payload is not None:
            self.store.ingest_snapshot(payload)

    def _true_pos_cb(self, msg):
        self.store.ingest_true_position(float(msg.x), float(msg.y), float(msg.z))

    def _make_bool_cb(self, label):
        """/security/*_isolated carries a latched level, republished every cycle
        while isolation holds -- so only the false -> true edge is an event."""
        state = {'active': False}

        def callback(msg):
            if bool(msg.data) and not state['active']:
                self.store.ingest_mitigation_intent(
                    {'action': f'ISOLATE_{label}', 'reason': 'sensor isolated'})
            state['active'] = bool(msg.data)
        return callback


def main(args=None):
    rclpy.init(args=args)
    node = DashboardNode()

    app = create_app(node.store, stream_hz=node.get_parameter('stream_hz').value)
    host = node.get_parameter('host').value
    port = node.get_parameter('port').value

    server = threading.Thread(
        target=lambda: app.run(host=host, port=port, threaded=True,
                               debug=False, use_reloader=False),
        daemon=True)
    server.start()

    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == '__main__':
    main()
