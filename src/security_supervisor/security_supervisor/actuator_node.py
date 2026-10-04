"""PC-side actuator for mitigation intents decided by supervisor_node.

Phase 7 moved supervisor_node onto the Raspberry Pi, which deliberately does
not build px4_msgs. Since rclpy publishers need a real IDL type (a dict or
dataclass cannot be published, and PX4's DDS bridge only deserializes the
genuine message), the Pi emits mitigation *intents* as JSON on
/security/mitigation_intent and this node -- which stays on the PC alongside
the DDS agent -- translates each one into the real px4_msgs write to /fmu/in/*.

Intent payload: {"timestamp_us": int, "action": str, "reason": str,
                 "params": {...}}   # params optional, action-specific

Deduplication of one-shot actions (RTH, LAND) and the airborne guard on
HOVER both stay on the supervisor side, which owns that state.
"""

import json

import rclpy
from rclpy.node import Node
from std_msgs.msg import String

from px4_msgs.msg import TrajectorySetpoint, VehicleCommand

from security_supervisor.crypto_channel import CryptoError
from security_supervisor.crypto_config import build_channel

TOPIC_MITIGATION_INTENT = '/security/mitigation_intent'

MAV_CMD_SET_GPS_GLOBAL_ORIGIN = 821


class MitigationActuator(Node):
    def __init__(self):
        super().__init__('mitigation_actuator')

        qos = 10
        self.intent_sub = self.create_subscription(
            String, TOPIC_MITIGATION_INTENT, self._intent_cb, qos)

        self.vehicle_command_pub = self.create_publisher(
            VehicleCommand, '/fmu/in/vehicle_command', qos)
        self.trajectory_setpoint_pub = self.create_publisher(
            TrajectorySetpoint, '/fmu/in/trajectory_setpoint', qos)

        self._dispatch = {
            'REDUCE_GPS_WEIGHT': self._reduce_gps_weight,
            'COMMAND_HOVER': self._hover,
            'COMMAND_RTH': self._rth,
            'COMMAND_LAND': self._land,
        }

        # Every intent that arrives here becomes a real /fmu/in/* write, so
        # this is the one place where an unauthenticated message would turn
        # straight into vehicle actuation. Anything that fails to
        # authenticate is dropped -- including replays, which here would
        # mean re-flying a stale COMMAND_RTH/LAND.
        self.channel, self.crypto_cfg = build_channel('actuator', logger=self.get_logger())
        self.rejected_intents = 0

        self.get_logger().info(
            f'mitigation_actuator up: {TOPIC_MITIGATION_INTENT} -> '
            f'/fmu/in/vehicle_command + /fmu/in/trajectory_setpoint '
            f'(actions: {sorted(self._dispatch)})')

    def _now_us(self):
        return int(self.get_clock().now().nanoseconds / 1000)

    def _intent_cb(self, msg):
        try:
            payload = self.channel.open(msg.data)
        except CryptoError as exc:
            self.rejected_intents += 1
            self.get_logger().error(
                f'[t={self._now_us()}] REJECTED mitigation intent '
                f'({self.rejected_intents} total): {exc}')
            return

        try:
            intent = json.loads(payload)
        except json.JSONDecodeError:
            self.get_logger().warning('Discarded malformed mitigation_intent')
            return

        action = intent.get('action')
        handler = self._dispatch.get(action)
        if handler is None:
            self.get_logger().warning(f'Unknown mitigation action: {action!r}')
            return

        handler(intent.get('reason', ''), intent.get('params') or {})

    def _new_command(self, command):
        msg = VehicleCommand()
        msg.command = command
        msg.target_system = 1
        msg.target_component = 1
        msg.source_system = 1
        msg.source_component = 1
        msg.from_external = True
        msg.timestamp = self._now_us()
        return msg

    def _reduce_gps_weight(self, reason, params):
        msg = self._new_command(MAV_CMD_SET_GPS_GLOBAL_ORIGIN)
        msg.param7 = float(params.get('gps_accuracy_scale', 0.5))
        self.vehicle_command_pub.publish(msg)
        self.get_logger().warning(
            f'[t={self._now_us()}] GPS weight reduced -- EKF de-weighting GPS ({reason})')

    def _hover(self, reason, params):
        msg = TrajectorySetpoint()
        msg.position = [float('nan')] * 3
        msg.velocity = [0.0, 0.0, 0.0]
        msg.yaw = float('nan')
        msg.yawspeed = 0.0
        msg.timestamp = self._now_us()
        self.trajectory_setpoint_pub.publish(msg)
        self.get_logger().warning(
            f'[t={self._now_us()}] HOVER COMMANDED -- holding position due to security threat ({reason})')

    def _rth(self, reason, params):
        self.vehicle_command_pub.publish(
            self._new_command(VehicleCommand.VEHICLE_CMD_NAV_RETURN_TO_LAUNCH))
        self.get_logger().error(
            f'[t={self._now_us()}] RETURN TO HOME COMMANDED -- threat level critical ({reason})')

    def _land(self, reason, params):
        self.vehicle_command_pub.publish(
            self._new_command(VehicleCommand.VEHICLE_CMD_NAV_LAND))
        self.get_logger().error(
            f'[t={self._now_us()}] EMERGENCY LAND COMMANDED -- trust fully lost ({reason})')


def main(args=None):
    rclpy.init(args=args)
    node = MitigationActuator()
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
