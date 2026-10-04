"""GPS freeze attack scenario.

Requires use_spoofed_gps=true on sensor_monitor -- declared below.
"""
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument
from launch.conditions import IfCondition
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node
from launch_ros.parameter_descriptions import ParameterValue


def generate_launch_description():
    duration_arg = DeclareLaunchArgument('attack_duration_s', default_value='15.0')
    delay_arg = DeclareLaunchArgument('attack_delay_s', default_value='5.0')

    supervisor_arg = DeclareLaunchArgument(
        'run_supervisor', default_value='true',
        description="Set false when supervisor_node runs on the Raspberry Pi (Phase 7).")

    sensor_monitor = Node(
        package='security_supervisor', executable='sensor_monitor', name='sensor_monitor',
        output='screen',
        parameters=[{'use_spoofed_gps': True}],
    )
    # No 'name=' override: 'supervisor' internally creates two nodes
    # (data_logger, trust_monitor); a process-wide remap would collide them.
    supervisor = Node(
        package='security_supervisor', executable='supervisor',
        output='screen',
        condition=IfCondition(LaunchConfiguration('run_supervisor')),
    )
    # Phase 7: supervisor_node no longer publishes px4_msgs itself (it can run
    # on the Pi, which doesn't build them) -- it emits JSON mitigation intents
    # that this PC-side node turns into real /fmu/in/* writes. Unconditional:
    # required whether the supervisor runs here or on the Pi.
    actuator = Node(
        package='security_supervisor', executable='actuator', name='mitigation_actuator',
        output='screen',
    )
    injector = Node(
        package='attack_injector', executable='injector_node', name='injector_node',
        output='screen',
        parameters=[{
            'attack_type': 'gps_freeze',
            'attack_duration_s': ParameterValue(LaunchConfiguration('attack_duration_s'), value_type=float),
            'attack_delay_s': ParameterValue(LaunchConfiguration('attack_delay_s'), value_type=float),
        }],
    )

    return LaunchDescription([duration_arg, delay_arg, supervisor_arg, sensor_monitor, supervisor, actuator, injector])
