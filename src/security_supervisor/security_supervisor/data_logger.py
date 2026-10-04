import csv
import json
import os
from datetime import datetime

import rclpy
from rclpy.node import Node
from std_msgs.msg import String

from security_supervisor.crypto_config import build_channel

FLUSH_EVERY_ROWS = 50
STATUS_EVERY_ROWS = 100

DEFAULT_LOG_DIR = os.path.expanduser('~/uav_security_ws/data/logs')

CSV_COLUMNS = [
    'timestamp_us',
    'gps_lat', 'gps_lon', 'gps_alt', 'gps_vel_n', 'gps_vel_e', 'gps_vel_d',
    'gps_fix_type', 'gps_satellites',
    'local_x', 'local_y', 'local_z', 'local_vx', 'local_vy', 'local_vz',
    'roll', 'roll_rate', 'pitch', 'pitch_rate', 'yaw', 'yaw_rate',
    'imu_ax', 'imu_ay', 'imu_az', 'imu_gx', 'imu_gy', 'imu_gz',
    'baro_pressure', 'baro_temp', 'baro_alt',
    'battery_voltage', 'battery_current', 'battery_remaining',
    'arming_state', 'nav_state',
    'last_cmd_id', 'last_cmd_param1', 'last_cmd_param2',
]

# CSV column -> (snapshot section, field within that section)
COLUMN_SOURCES = {
    'gps_lat': ('gps', 'lat'),
    'gps_lon': ('gps', 'lon'),
    'gps_alt': ('gps', 'alt'),
    'gps_vel_n': ('gps', 'vel_n'),
    'gps_vel_e': ('gps', 'vel_e'),
    'gps_vel_d': ('gps', 'vel_d'),
    'gps_fix_type': ('gps', 'fix_type'),
    'gps_satellites': ('gps', 'satellites_used'),
    'local_x': ('local_pos', 'x'),
    'local_y': ('local_pos', 'y'),
    'local_z': ('local_pos', 'z'),
    'local_vx': ('local_pos', 'vx'),
    'local_vy': ('local_pos', 'vy'),
    'local_vz': ('local_pos', 'vz'),
    'roll': ('attitude', 'roll'),
    'roll_rate': ('attitude', 'roll_rate'),
    'pitch': ('attitude', 'pitch'),
    'pitch_rate': ('attitude', 'pitch_rate'),
    'yaw': ('attitude', 'yaw'),
    'yaw_rate': ('attitude', 'yaw_rate'),
    'imu_ax': ('imu', 'ax'),
    'imu_ay': ('imu', 'ay'),
    'imu_az': ('imu', 'az'),
    'imu_gx': ('imu', 'gx'),
    'imu_gy': ('imu', 'gy'),
    'imu_gz': ('imu', 'gz'),
    'baro_pressure': ('baro', 'pressure'),
    'baro_temp': ('baro', 'temperature'),
    'baro_alt': ('baro', 'altitude'),
    'battery_voltage': ('battery', 'voltage'),
    'battery_current': ('battery', 'current'),
    'battery_remaining': ('battery', 'remaining'),
    'arming_state': ('vehicle_status', 'arming_state'),
    'nav_state': ('vehicle_status', 'nav_state'),
    'last_cmd_id': ('last_command', 'command'),
    'last_cmd_param1': ('last_command', 'param1'),
    'last_cmd_param2': ('last_command', 'param2'),
}


class DataLogger(Node):
    """Subscribes to /security/sensor_snapshot and writes each snapshot as a
    flat CSV row for offline baseline profiling and ML training."""

    def __init__(self):
        super().__init__('data_logger')

        self.declare_parameter('log_dir', DEFAULT_LOG_DIR)
        self.declare_parameter('log_prefix', 'baseline')

        log_dir = self.get_parameter('log_dir').value
        prefix = self.get_parameter('log_prefix').value
        os.makedirs(log_dir, exist_ok=True)

        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.csv_path = os.path.join(log_dir, f'{prefix}_{stamp}.csv')

        self._file = open(self.csv_path, 'w', newline='')
        self._writer = csv.DictWriter(self._file, fieldnames=CSV_COLUMNS)
        self._writer.writeheader()
        self._file.flush()

        self.row_count = 0
        self.malformed_count = 0

        self.subscription = self.create_subscription(
            String, '/security/sensor_snapshot', self._snapshot_cb, 10)

        # Logs the same sealed stream the supervisor consumes. Replay
        # tracking is off here: this is an observer, and the supervisor is
        # the component that decides what a replay means. Leaving it on
        # would just double-count the same event in a second node.
        self.channel, _cfg = build_channel(
            'data_logger', logger=self.get_logger())
        if hasattr(self.channel, 'track_replay'):
            self.channel.track_replay = False

        self.get_logger().info(f'Logging to {self.csv_path}')

    def _snapshot_cb(self, msg):
        payload, crypto_error = self.channel.open_with_status(msg.data)
        if crypto_error is not None and payload is None:
            self.malformed_count += 1
            if self.malformed_count in (1, 10, 100):
                self.get_logger().warning(
                    f'Discarded {self.malformed_count} undecryptable snapshot(s): {crypto_error}')
            return

        try:
            snapshot = json.loads(payload)
        except json.JSONDecodeError:
            self.malformed_count += 1
            if self.malformed_count in (1, 10, 100):
                self.get_logger().warning(
                    f'Discarded {self.malformed_count} malformed snapshot(s)')
            return

        self._writer.writerow(self._flatten(snapshot))
        self.row_count += 1

        if self.row_count % FLUSH_EVERY_ROWS == 0:
            self._file.flush()

        if self.row_count % STATUS_EVERY_ROWS == 0:
            self.get_logger().info(
                f'Logged {self.row_count} rows to {self.csv_path}')

    def _flatten(self, snapshot):
        """Flatten the nested snapshot into one CSV row. Sections that haven't
        received data yet are None, which csv writes as an empty cell."""
        row = {'timestamp_us': snapshot.get('timestamp_us')}

        for column, (section, field) in COLUMN_SOURCES.items():
            section_data = snapshot.get(section)
            row[column] = section_data.get(field) if section_data else None

        return row

    def close(self):
        if not self._file.closed:
            self._file.flush()
            self._file.close()
        self.get_logger().info(
            f'Closed {self.csv_path} with {self.row_count} rows')


def main(args=None):
    rclpy.init(args=args)
    node = DataLogger()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.close()
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == '__main__':
    main()
