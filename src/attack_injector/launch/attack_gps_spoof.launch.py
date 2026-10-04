"""GPS position spoof attack scenario.

Starts sensor_monitor (subscribed to the injector's spoofed GPS shadow
topic), supervisor_node (TrustEngine + AnomalyDetector), and injector_node
configured for attack_type='gps_spoof'.

Requires use_spoofed_gps=true on sensor_monitor so it consumes
/security/spoofed/gps instead of the real /fmu/out/vehicle_gps_position --
declared below, not something you need to pass yourself.
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
    offset_arg = DeclareLaunchArgument('gps_spoof_offset_m', default_value='50.0')
    ramp_arg = DeclareLaunchArgument('gps_spoof_ramp_s', default_value='3.0')

    supervisor_arg = DeclareLaunchArgument(
        'run_supervisor', default_value='true',
        description="Set false when supervisor_node runs on the Raspberry Pi (Phase 7).")

    sensor_monitor = Node(
        package='security_supervisor', executable='sensor_monitor', name='sensor_monitor',
        output='screen',
        parameters=[{'use_spoofed_gps': True}],
    )
    # No 'name=' override here: 'supervisor' internally creates two nodes
    # (data_logger, trust_monitor); a process-wide __node remap would force
    # both to the same name and collide on rosout registration.
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
            'attack_type': 'gps_spoof',
            # LaunchConfiguration substitutions resolve to plain strings;
            # ParameterValue(value_type=float) casts them so they match the
            # float-typed defaults declared in injector_node.py (a bare
            # string override would raise a parameter type mismatch).
            'attack_duration_s': ParameterValue(LaunchConfiguration('attack_duration_s'), value_type=float),
            'attack_delay_s': ParameterValue(LaunchConfiguration('attack_delay_s'), value_type=float),
            'gps_spoof_offset_m': ParameterValue(LaunchConfiguration('gps_spoof_offset_m'), value_type=float),
            'gps_spoof_ramp_s': ParameterValue(LaunchConfiguration('gps_spoof_ramp_s'), value_type=float),
        }],
    )

    return LaunchDescription([
        duration_arg, delay_arg, offset_arg, ramp_arg,
        supervisor_arg, sensor_monitor, supervisor, actuator, injector,
    ])
