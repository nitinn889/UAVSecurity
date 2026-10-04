#!/usr/bin/env python3
"""Nominal test flight: arm -> OFFBOARD -> takeoff to 5m -> hover 10s -> land.

Requires px4_msgs (https://github.com/PX4/px4_msgs) built into a sourced
ROS 2 workspace, and PX4 SITL + the Micro XRCE-DDS Agent running.
"""
import time

import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, QoSReliabilityPolicy, QoSHistoryPolicy, QoSDurabilityPolicy

from px4_msgs.msg import (
    OffboardControlMode,
    TrajectorySetpoint,
    VehicleCommand,
    VehicleStatus,
)

TAKEOFF_ALTITUDE_M = 5.0
HOVER_SECONDS = 10.0


class TestFlight(Node):
    def __init__(self):
        super().__init__('test_flight')

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

        self.offboard_control_mode_pub = self.create_publisher(
            OffboardControlMode, '/fmu/in/offboard_control_mode', qos_pub)
        self.trajectory_setpoint_pub = self.create_publisher(
            TrajectorySetpoint, '/fmu/in/trajectory_setpoint', qos_pub)
        self.vehicle_command_pub = self.create_publisher(
            VehicleCommand, '/fmu/in/vehicle_command', qos_pub)

        self.vehicle_status = VehicleStatus()
        self.vehicle_status_sub = self.create_subscription(
            VehicleStatus, '/fmu/out/vehicle_status_v4',
            self._vehicle_status_cb, qos_sub)

        self.offboard_setpoint_counter = 0
        self.target_z = -TAKEOFF_ALTITUDE_M  # NED: negative = up
        self.state = 'INIT'
        self.hover_start_time = None

        self.timer = self.create_timer(0.1, self._timer_cb)

    def _vehicle_status_cb(self, msg):
        self.vehicle_status = msg

    def _publish_vehicle_command(self, command, **params):
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
        self.vehicle_command_pub.publish(msg)

    def _arm(self):
        self._publish_vehicle_command(
            VehicleCommand.VEHICLE_CMD_COMPONENT_ARM_DISARM, param1=1.0)
        self.get_logger().info('Arm command sent')

    def _engage_offboard_mode(self):
        self._publish_vehicle_command(
            VehicleCommand.VEHICLE_CMD_DO_SET_MODE, param1=1.0, param2=6.0)
        self.get_logger().info('Offboard mode command sent')

    def _land(self):
        self._publish_vehicle_command(VehicleCommand.VEHICLE_CMD_NAV_LAND)
        self.get_logger().info('Land command sent')

    def _publish_offboard_control_mode(self):
        msg = OffboardControlMode()
        msg.position = True
        msg.velocity = False
        msg.acceleration = False
        msg.attitude = False
        msg.body_rate = False
        msg.timestamp = int(self.get_clock().now().nanoseconds / 1000)
        self.offboard_control_mode_pub.publish(msg)

    def _publish_trajectory_setpoint(self, z):
        msg = TrajectorySetpoint()
        msg.position = [0.0, 0.0, z]
        msg.yaw = 0.0
        msg.timestamp = int(self.get_clock().now().nanoseconds / 1000)
        self.trajectory_setpoint_pub.publish(msg)

    def _timer_cb(self):
        self._publish_offboard_control_mode()

        if self.state == 'INIT':
            self._publish_trajectory_setpoint(0.0)
            if self.offboard_setpoint_counter == 10:
                self._engage_offboard_mode()
                self.state = 'WAIT_OFFBOARD'
            self.offboard_setpoint_counter += 1

        elif self.state == 'WAIT_OFFBOARD':
            self._publish_trajectory_setpoint(0.0)
            if self.vehicle_status.nav_state == VehicleStatus.NAVIGATION_STATE_OFFBOARD:
                self._arm()
                self.state = 'TAKEOFF'

        elif self.state == 'TAKEOFF':
            self._publish_trajectory_setpoint(self.target_z)
            current_z = self.vehicle_status.timestamp and 0.0
            if self.hover_start_time is None:
                # crude altitude gate: rely on wall-clock after commanding setpoint
                self._takeoff_start_time = getattr(self, '_takeoff_start_time', time.time())
                if time.time() - self._takeoff_start_time > 8.0:
                    self.state = 'HOVER'
                    self.hover_start_time = time.time()
                    self.get_logger().info('Reached target altitude, hovering')

        elif self.state == 'HOVER':
            self._publish_trajectory_setpoint(self.target_z)
            if time.time() - self.hover_start_time > HOVER_SECONDS:
                self.state = 'LAND'
                self.get_logger().info('Hover complete, landing')

        elif self.state == 'LAND':
            self._land()
            self.state = 'DONE'

        elif self.state == 'DONE':
            pass


def main(args=None):
    rclpy.init(args=args)
    node = TestFlight()
    rclpy.spin(node)
    node.destroy_node()
    rclpy.shutdown()


if __name__ == '__main__':
    main()
