import json
import math

import rclpy
from rclpy.node import Node
from rcl_interfaces.msg import SetParametersResult
from rclpy.qos import QoSProfile, QoSReliabilityPolicy, QoSHistoryPolicy, QoSDurabilityPolicy
from std_msgs.msg import String

from px4_msgs.msg import (
    BatteryStatus,
    SensorCombined,
    SensorGps,
    VehicleAirData,
    VehicleAngularVelocity,
    VehicleAttitude,
    VehicleCommand,
    VehicleGlobalPosition,
    VehicleLocalPosition,
    VehicleStatus,
)

from security_supervisor.crypto_config import build_channel

SNAPSHOT_RATE_HZ = 10.0

# PX4 message versioning appends a suffix to bridged topic names; these are the
# names this PX4 build actually advertises (confirmed via `ros2 topic list`).
TOPIC_GPS = '/fmu/out/vehicle_gps_position'
TOPIC_LOCAL_POS = '/fmu/out/vehicle_local_position_v1'
TOPIC_GLOBAL_POS = '/fmu/out/vehicle_global_position'
TOPIC_SENSOR_COMBINED = '/fmu/out/sensor_combined'
TOPIC_ATTITUDE = '/fmu/out/vehicle_attitude'
TOPIC_ANGULAR_VELOCITY = '/fmu/out/vehicle_angular_velocity'
TOPIC_AIR_DATA = '/fmu/out/vehicle_air_data'
TOPIC_BATTERY = '/fmu/out/battery_status_v1'
TOPIC_VEHICLE_STATUS = '/fmu/out/vehicle_status_v4'
TOPIC_VEHICLE_COMMAND = '/fmu/in/vehicle_command'

# Phase 5 attack-injection shadow topics (see attack_injector/injector_node.py).
TOPIC_SPOOFED_GPS = '/security/spoofed/gps'
TOPIC_SPOOFED_IMU = '/security/spoofed/imu'
TOPIC_REPLAY_SNAPSHOT = '/security/replay/sensor_snapshot'


def quaternion_to_euler(q):
    """PX4 attitude quaternion [w, x, y, z] -> (roll, pitch, yaw) in radians."""
    w, x, y, z = q[0], q[1], q[2], q[3]

    sinr_cosp = 2.0 * (w * x + y * z)
    cosr_cosp = 1.0 - 2.0 * (x * x + y * y)
    roll = math.atan2(sinr_cosp, cosr_cosp)

    sinp = 2.0 * (w * y - z * x)
    pitch = math.copysign(math.pi / 2.0, sinp) if abs(sinp) >= 1.0 else math.asin(sinp)

    siny_cosp = 2.0 * (w * z + x * y)
    cosy_cosp = 1.0 - 2.0 * (y * y + z * z)
    yaw = math.atan2(siny_cosp, cosy_cosp)

    return roll, pitch, yaw


class SensorMonitor(Node):
    """Subscribes to all PX4 uXRCE-DDS sensor topics (/fmu/out/*) and republishes
    normalized sensor snapshots for downstream trust/anomaly analysis."""

    def __init__(self):
        super().__init__('sensor_monitor')

        self.declare_parameter('use_spoofed_gps', False)
        self.declare_parameter('use_spoofed_imu', False)
        self.declare_parameter('use_replay_telemetry', False)
        self.use_spoofed_gps = bool(self.get_parameter('use_spoofed_gps').value)
        self.use_spoofed_imu = bool(self.get_parameter('use_spoofed_imu').value)
        self.use_replay_telemetry = bool(self.get_parameter('use_replay_telemetry').value)
        # use_replay_telemetry specifically needs to change at runtime (Phase
        # 6 Task 4's watchdog reverts it via `ros2 param set` once the
        # replay stream ends) -- without this callback, a successful
        # SetParameters service call would update the node's internal
        # parameter store but never touch this cached bool, so
        # _publish_snapshot would keep reading stale replay data forever.
        self.add_on_set_parameters_callback(self._on_set_parameters)

        # PX4 publishes /fmu/out/* as BEST_EFFORT; a mismatched (RELIABLE) QoS
        # silently receives nothing. The injector's shadow topics mirror this
        # QoS so sensor_monitor can subscribe to either with the same profile.
        qos = QoSProfile(
            reliability=QoSReliabilityPolicy.BEST_EFFORT,
            durability=QoSDurabilityPolicy.VOLATILE,
            history=QoSHistoryPolicy.KEEP_LAST,
            depth=1,
        )

        self.latest = {
            'gps': None,
            'local_pos': None,
            'global_pos': None,
            'imu': None,
            'attitude': None,
            'angular_velocity': None,
            'baro': None,
            'battery': None,
            'vehicle_status': None,
            'last_command': None,
        }
        self.msg_counts = {key: 0 for key in self.latest}

        gps_topic = TOPIC_SPOOFED_GPS if self.use_spoofed_gps else TOPIC_GPS
        imu_topic = TOPIC_SPOOFED_IMU if self.use_spoofed_imu else TOPIC_SENSOR_COMBINED

        subscriptions = [
            (SensorGps, gps_topic, 'gps'),
            (VehicleLocalPosition, TOPIC_LOCAL_POS, 'local_pos'),
            (VehicleGlobalPosition, TOPIC_GLOBAL_POS, 'global_pos'),
            (SensorCombined, imu_topic, 'imu'),
            (VehicleAttitude, TOPIC_ATTITUDE, 'attitude'),
            (VehicleAngularVelocity, TOPIC_ANGULAR_VELOCITY, 'angular_velocity'),
            (VehicleAirData, TOPIC_AIR_DATA, 'baro'),
            (BatteryStatus, TOPIC_BATTERY, 'battery'),
            (VehicleStatus, TOPIC_VEHICLE_STATUS, 'vehicle_status'),
            (VehicleCommand, TOPIC_VEHICLE_COMMAND, 'last_command'),
        ]

        self._subs = [
            self.create_subscription(
                msg_type, topic, self._make_callback(key), qos)
            for msg_type, topic, key in subscriptions
        ]

        self.snapshot_pub = self.create_publisher(
            String, '/security/sensor_snapshot', 10)

        # Phase 9: /security/sensor_snapshot is the PC->Pi hop, so it is
        # sealed here and opened by supervisor_node / data_logger.
        self.channel, self.crypto_cfg = build_channel('sensor_monitor', logger=self.get_logger())

        self.snapshot_count = 0
        self._latest_replay_data = None

        if self.use_replay_telemetry:
            # 'use_replay_telemetry' is set once at launch, but injector_node
            # only starts publishing replayed data once its attack becomes
            # active -- before that there IS no replay data yet, and
            # injector_node itself needs real /security/sensor_snapshot
            # traffic during its pre-attack window to fill its buffer. So
            # the normal 10Hz timer always runs; it substitutes the latest
            # replayed snapshot in place of a freshly-computed one only
            # once replay data has actually started arriving.
            self.create_subscription(
                String, TOPIC_REPLAY_SNAPSHOT, self._replay_cb, 10)
        self.timer = self.create_timer(1.0 / SNAPSHOT_RATE_HZ, self._publish_snapshot)

        self.get_logger().info(
            f'sensor_monitor up: {len(subscriptions)} topics -> '
            f'/security/sensor_snapshot @ {SNAPSHOT_RATE_HZ:.0f} Hz '
            f'(gps={gps_topic}, imu={imu_topic}, '
            f'replay_telemetry={self.use_replay_telemetry})')

    def _replay_cb(self, msg):
        self._latest_replay_data = msg.data

    def _on_set_parameters(self, params):
        for param in params:
            if param.name == 'use_replay_telemetry':
                self.use_replay_telemetry = bool(param.value)
                if not self.use_replay_telemetry:
                    self._latest_replay_data = None
                self.get_logger().info(f'use_replay_telemetry set to {self.use_replay_telemetry}')
        return SetParametersResult(successful=True)

    def _make_callback(self, key):
        def callback(msg):
            self.latest[key] = msg
            self.msg_counts[key] += 1
        return callback

    def _publish_snapshot(self):
        if self.use_replay_telemetry and self._latest_replay_data is not None:
            # Republished verbatim, NOT re-sealed: the injector buffered these
            # straight off the wire, so they are still the original sealed
            # envelopes with their original sequence numbers. Re-sealing would
            # mint fresh sequence numbers and launder the replay into
            # something indistinguishable from live traffic -- forwarding them
            # untouched is both what a real replay attacker can do and what
            # lets the receiver's replay check catch it.
            msg = String()
            msg.data = self._latest_replay_data
            self.snapshot_pub.publish(msg)
            self.snapshot_count += 1
            return

        snapshot = {
            'timestamp_us': int(self.get_clock().now().nanoseconds / 1000),
            'gps': self._gps_dict(),
            'local_pos': self._local_pos_dict(),
            'attitude': self._attitude_dict(),
            'imu': self._imu_dict(),
            'baro': self._baro_dict(),
            'battery': self._battery_dict(),
            'vehicle_status': self._vehicle_status_dict(),
            'last_command': self._last_command_dict(),
        }

        msg = String()
        msg.data = self.channel.seal(json.dumps(snapshot))
        self.snapshot_pub.publish(msg)

        self.snapshot_count += 1
        if self.snapshot_count % 100 == 0:
            received = {k: v for k, v in self.msg_counts.items() if v > 0}
            self.get_logger().info(
                f'{self.snapshot_count} snapshots published; '
                f'source msg counts: {received}')

    def _gps_dict(self):
        m = self.latest['gps']
        if m is None:
            return None
        return {
            'lat': m.latitude_deg,
            'lon': m.longitude_deg,
            'alt': m.altitude_msl_m,
            'vel_n': m.vel_n_m_s,
            'vel_e': m.vel_e_m_s,
            'vel_d': m.vel_d_m_s,
            'fix_type': m.fix_type,
            'satellites_used': m.satellites_used,
        }

    def _local_pos_dict(self):
        m = self.latest['local_pos']
        if m is None:
            return None
        return {
            'x': m.x, 'y': m.y, 'z': m.z,
            'vx': m.vx, 'vy': m.vy, 'vz': m.vz,
        }

    def _attitude_dict(self):
        att = self.latest['attitude']
        rates = self.latest['angular_velocity']

        if att is None and rates is None:
            return None

        roll = pitch = yaw = None
        if att is not None:
            roll, pitch, yaw = quaternion_to_euler(att.q)

        # Prefer the dedicated angular velocity topic; fall back to raw gyro.
        # Array fields arrive as numpy float32, which json can't serialize.
        roll_rate = pitch_rate = yaw_rate = None
        if rates is not None:
            roll_rate, pitch_rate, yaw_rate = (float(v) for v in rates.xyz[:3])
        elif self.latest['imu'] is not None:
            gyro = self.latest['imu'].gyro_rad
            roll_rate, pitch_rate, yaw_rate = (float(v) for v in gyro[:3])

        return {
            'roll': roll, 'roll_rate': roll_rate,
            'pitch': pitch, 'pitch_rate': pitch_rate,
            'yaw': yaw, 'yaw_rate': yaw_rate,
        }

    def _imu_dict(self):
        m = self.latest['imu']
        if m is None:
            return None
        ax, ay, az = (float(v) for v in m.accelerometer_m_s2[:3])
        gx, gy, gz = (float(v) for v in m.gyro_rad[:3])
        return {
            'ax': ax, 'ay': ay, 'az': az,
            'gx': gx, 'gy': gy, 'gz': gz,
        }

    def _baro_dict(self):
        m = self.latest['baro']
        if m is None:
            return None
        return {
            'pressure': m.baro_pressure_pa,
            'temperature': m.ambient_temperature,
            'altitude': m.baro_alt_meter,
        }

    def _battery_dict(self):
        m = self.latest['battery']
        if m is None:
            return None
        return {
            'voltage': m.voltage_v,
            'current': m.current_a,
            'remaining': m.remaining,
        }

    def _vehicle_status_dict(self):
        m = self.latest['vehicle_status']
        if m is None:
            return None
        return {
            'arming_state': m.arming_state,
            'nav_state': m.nav_state,
        }

    def _last_command_dict(self):
        m = self.latest['last_command']
        if m is None:
            return None
        return {
            'command': m.command,
            'param1': m.param1,
            'param2': m.param2,
            # The VehicleCommand message's own timestamp, distinct from the
            # snapshot's timestamp_us. Lets downstream consumers (trust_engine)
            # detect a genuinely new command arrival vs. this same cached
            # message still being the "latest" on a later snapshot tick.
            'msg_timestamp': m.timestamp,
        }


def main(args=None):
    rclpy.init(args=args)
    node = SensorMonitor()
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
