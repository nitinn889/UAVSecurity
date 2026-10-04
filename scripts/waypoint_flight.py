#!/usr/bin/env python3
"""Square-pattern baseline flight for collecting varied position/velocity data.

Takeoff -> (North 10m, East 10m, South 10m, West 10m) x2 -> Land.

Requires PX4 SITL + Micro XRCE-DDS Agent running, px4_msgs sourced, and
COM_RC_IN_MODE=4 / NAV_DLL_ACT=0 set so PX4 will arm without RC or a GCS.
"""
import time

import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, QoSReliabilityPolicy, QoSHistoryPolicy, QoSDurabilityPolicy

from px4_msgs.msg import (
    OffboardControlMode,
    TrajectorySetpoint,
    VehicleCommand,
    VehicleLocalPosition,
    VehicleStatus,
)

ALTITUDE_M = 5.0
LEG_LENGTH_M = 10.0
LAPS = 2
ARRIVAL_TOLERANCE_M = 0.8
SETTLE_SECONDS = 1.0
LEG_TIMEOUT_S = 20.0

TOPIC_LOCAL_POS = '/fmu/out/vehicle_local_position_v1'
TOPIC_VEHICLE_STATUS = '/fmu/out/vehicle_status_v4'


def build_square_waypoints():
    """(north, east) corners for the square pattern, repeated for each lap."""
    lap = [
        (LEG_LENGTH_M, 0.0),             # north
        (LEG_LENGTH_M, LEG_LENGTH_M),    # east
        (0.0, LEG_LENGTH_M),             # south
        (0.0, 0.0),                      # west, back to start
    ]
    return lap * LAPS


class WaypointFlight(Node):
    def __init__(self):
        super().__init__('waypoint_flight')

        qos_pub = QoSProfile(
            reliability=QoSReliabilityPolicy.BEST_EFFORT,
            durability=QoSDurabilityPolicy.TRANSIENT_LOCAL,
            history=QoSHistoryPolicy.KEEP_LAST,
            depth=1,
        )
        qos_sub = QoSProfile(
            reliability=QoSReliabilityPolicy.BEST_EFFORT,
            durability=QoSDurabilityPolicy.VOLATILE,
            history=QoSHistoryPolicy.KEEP_LAST,
            depth=1,
        )

        self.offboard_mode_pub = self.create_publisher(
            OffboardControlMode, '/fmu/in/offboard_control_mode', qos_pub)
        self.setpoint_pub = self.create_publisher(
            TrajectorySetpoint, '/fmu/in/trajectory_setpoint', qos_pub)
        self.command_pub = self.create_publisher(
            VehicleCommand, '/fmu/in/vehicle_command', qos_pub)

        self.vehicle_status = VehicleStatus()
        self.local_pos = VehicleLocalPosition()
        self.create_subscription(
            VehicleStatus, TOPIC_VEHICLE_STATUS, self._status_cb, qos_sub)
        self.create_subscription(
            VehicleLocalPosition, TOPIC_LOCAL_POS, self._local_pos_cb, qos_sub)

        self.target_z = -ALTITUDE_M
        self.waypoints = build_square_waypoints()
        self.waypoint_index = 0
        self.state = 'INIT'
        self.setpoint_counter = 0
        self.state_entered_at = time.time()
        self.flight_started_at = None

        self.timer = self.create_timer(0.1, self._timer_cb)

    def _status_cb(self, msg):
        self.vehicle_status = msg

    def _local_pos_cb(self, msg):
        self.local_pos = msg

    def _set_state(self, state):
        self.state = state
        self.state_entered_at = time.time()

    def _elapsed_in_state(self):
        return time.time() - self.state_entered_at

    def _send_command(self, command, **params):
        msg = VehicleCommand()
        msg.command = command
        msg.param1 = params.get('param1', 0.0)
        msg.param2 = params.get('param2', 0.0)
        msg.target_system = 1
        msg.target_component = 1
        msg.source_system = 1
        msg.source_component = 1
        msg.from_external = True
        msg.timestamp = int(self.get_clock().now().nanoseconds / 1000)
        self.command_pub.publish(msg)

    def _publish_offboard_mode(self):
        msg = OffboardControlMode()
        msg.position = True
        msg.velocity = False
        msg.acceleration = False
        msg.attitude = False
        msg.body_rate = False
        msg.timestamp = int(self.get_clock().now().nanoseconds / 1000)
        self.offboard_mode_pub.publish(msg)

    def _publish_setpoint(self, north, east, z):
        msg = TrajectorySetpoint()
        msg.position = [float(north), float(east), float(z)]
        msg.yaw = 0.0
        msg.timestamp = int(self.get_clock().now().nanoseconds / 1000)
        self.setpoint_pub.publish(msg)

    def _distance_to(self, north, east, z):
        dx = self.local_pos.x - north
        dy = self.local_pos.y - east
        dz = self.local_pos.z - z
        return (dx * dx + dy * dy + dz * dz) ** 0.5

    def _timer_cb(self):
        self._publish_offboard_mode()

        if self.state == 'INIT':
            self._publish_setpoint(0.0, 0.0, 0.0)
            self.setpoint_counter += 1
            if self.setpoint_counter >= 10:
                self._send_command(
                    VehicleCommand.VEHICLE_CMD_DO_SET_MODE, param1=1.0, param2=6.0)
                self.get_logger().info('Offboard mode requested')
                self._set_state('WAIT_OFFBOARD')

        elif self.state == 'WAIT_OFFBOARD':
            self._publish_setpoint(0.0, 0.0, 0.0)
            if self.vehicle_status.nav_state == VehicleStatus.NAVIGATION_STATE_OFFBOARD:
                self._send_command(
                    VehicleCommand.VEHICLE_CMD_COMPONENT_ARM_DISARM, param1=1.0)
                self.get_logger().info('Arm requested')
                self._set_state('WAIT_ARMED')
            elif self._elapsed_in_state() > 10.0:
                self.get_logger().error('Timed out waiting for OFFBOARD mode')
                self._set_state('ABORT')

        elif self.state == 'WAIT_ARMED':
            self._publish_setpoint(0.0, 0.0, self.target_z)
            if self.vehicle_status.arming_state == VehicleStatus.ARMING_STATE_ARMED:
                self.flight_started_at = time.time()
                self.get_logger().info(f'Armed; climbing to {ALTITUDE_M:.0f} m')
                self._set_state('TAKEOFF')
            elif self._elapsed_in_state() > 5.0:
                # Arm can be rejected once while the mode switch settles; retry.
                self._send_command(
                    VehicleCommand.VEHICLE_CMD_COMPONENT_ARM_DISARM, param1=1.0)
                self.state_entered_at = time.time()

        elif self.state == 'TAKEOFF':
            self._publish_setpoint(0.0, 0.0, self.target_z)
            if abs(self.local_pos.z - self.target_z) < ARRIVAL_TOLERANCE_M:
                self.get_logger().info(
                    f'Reached {ALTITUDE_M:.0f} m (z={self.local_pos.z:.2f}); '
                    f'starting square pattern')
                self._set_state('WAYPOINT')
            elif self._elapsed_in_state() > LEG_TIMEOUT_S:
                self.get_logger().warning('Takeoff timed out; proceeding anyway')
                self._set_state('WAYPOINT')

        elif self.state == 'WAYPOINT':
            north, east = self.waypoints[self.waypoint_index]
            self._publish_setpoint(north, east, self.target_z)

            arrived = self._distance_to(north, east, self.target_z) < ARRIVAL_TOLERANCE_M
            timed_out = self._elapsed_in_state() > LEG_TIMEOUT_S

            if arrived and self._elapsed_in_state() > SETTLE_SECONDS:
                lap = self.waypoint_index // 4 + 1
                self.get_logger().info(
                    f'Waypoint {self.waypoint_index + 1}/{len(self.waypoints)} '
                    f'(lap {lap}) reached: N={north:.0f} E={east:.0f}')
                self.waypoint_index += 1
                if self.waypoint_index >= len(self.waypoints):
                    self._set_state('LAND')
                else:
                    self.state_entered_at = time.time()
            elif timed_out:
                self.get_logger().warning(
                    f'Waypoint {self.waypoint_index + 1} timed out; skipping')
                self.waypoint_index += 1
                if self.waypoint_index >= len(self.waypoints):
                    self._set_state('LAND')
                else:
                    self.state_entered_at = time.time()

        elif self.state == 'LAND':
            self._send_command(VehicleCommand.VEHICLE_CMD_NAV_LAND)
            duration = time.time() - self.flight_started_at if self.flight_started_at else 0.0
            self.get_logger().info(
                f'Pattern complete in {duration:.0f} s; landing')
            self._set_state('LANDING')

        elif self.state == 'LANDING':
            if self.vehicle_status.arming_state != VehicleStatus.ARMING_STATE_ARMED:
                self.get_logger().info('Landed and disarmed; flight complete')
                self._set_state('DONE')
            elif self._elapsed_in_state() > 40.0:
                self.get_logger().warning('Landing timed out')
                self._set_state('DONE')

        elif self.state in ('DONE', 'ABORT'):
            raise SystemExit(0 if self.state == 'DONE' else 1)


def main(args=None):
    rclpy.init(args=args)
    node = WaypointFlight()
    try:
        rclpy.spin(node)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == '__main__':
    main()
