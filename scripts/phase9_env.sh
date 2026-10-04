#!/usr/bin/env bash
# Sets up the environment every Phase 9 tool needs, then execs its arguments.
#
#   ./scripts/phase9_env.sh python3 scripts/phase9_campaign.py --runs 5
#   ./scripts/phase9_env.sh ros2 run security_supervisor sensor_monitor
#
# Three things have to be right together or the distributed stack fails in
# ways that look like detector bugs:
#   ROS_DOMAIN_ID                 -- must match the Pi and the PX4 instance
#   FASTDDS_DEFAULT_PROFILES_FILE -- restricts DDS to the direct link and
#                                    keeps loopback (see config/fastdds_pc.xml)
#   the three workspace overlays   -- /opt/ros, px4_msgs_ws, uav_security_ws
#
# Deliberately lives in the repo rather than /tmp: an earlier version of this
# sat in /tmp and vanished with a tmp cleanup mid-campaign.

# No `set -u`: ROS 2's setup.bash references unbound variables and aborts.
source /opt/ros/lyrical/setup.bash
[ -f "$HOME/px4_msgs_ws/install/setup.bash" ] && source "$HOME/px4_msgs_ws/install/setup.bash"
[ -f "$HOME/uav_security_ws/install/setup.bash" ] && source "$HOME/uav_security_ws/install/setup.bash"

export ROS_DOMAIN_ID="${ROS_DOMAIN_ID:-42}"

PROFILE="${PROFILE:-$HOME/uav_security_ws/config/fastdds_pc.xml}"
if [ -f "$PROFILE" ]; then
    # Both names: newer Fast DDS wants FASTDDS_*, older rmw still reads
    # FASTRTPS_* and warns about it.
    export FASTDDS_DEFAULT_PROFILES_FILE="$PROFILE"
    export FASTRTPS_DEFAULT_PROFILES_FILE="$PROFILE"
fi

export PATH="/usr/bin:$PATH"
cd "$HOME/uav_security_ws" || exit 1

exec "$@"
