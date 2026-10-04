#!/usr/bin/env bash
# Bring up PX4 SITL + Gazebo + Micro XRCE-DDS Agent on ROS_DOMAIN_ID, and do
# not return until real sensor DATA is flowing on the ROS 2 side.
#
# Checking `ros2 topic list` is not enough: the XRCE agent registers every
# /fmu/* topic as soon as PX4's client connects, so the topics appear even
# when Gazebo failed to attach and PX4 is publishing nothing at all. That
# failure mode looks identical to success until a flight silently refuses to
# arm, so this waits on an actual message instead.
#
# Usage: ./phase9_sim_up.sh [--restart]
# NOTE: no `set -u` here -- ROS 2's own setup.bash references unbound
# variables (AMENT_TRACE_SETUP_FILES et al) and aborts under it.
set -o pipefail

ROS_DOMAIN_ID="${ROS_DOMAIN_ID:-42}"
export ROS_DOMAIN_ID

PX4_DIR="${PX4_DIR:-$HOME/PX4-Autopilot}"
PX4_MSGS_WS="${PX4_MSGS_WS:-$HOME/px4_msgs_ws}"
UAV_SECURITY_WS="${UAV_SECURITY_WS:-$HOME/uav_security_ws}"
DDS_PORT="${DDS_PORT:-8888}"
LOG_DIR="${LOG_DIR:-/tmp/phase9}"
READY_TIMEOUT_S="${READY_TIMEOUT_S:-120}"

mkdir -p "$LOG_DIR"

# shellcheck disable=SC1090,SC1091
source /opt/ros/lyrical/setup.bash
[ -f "$PX4_MSGS_WS/install/setup.bash" ] && source "$PX4_MSGS_WS/install/setup.bash"
[ -f "$UAV_SECURITY_WS/install/setup.bash" ] && source "$UAV_SECURITY_WS/install/setup.bash"

teardown() {
    echo "[sim_up] tearing down existing simulation..."
    pkill -9 -f "px4_sitl_default/bin/px4" 2>/dev/null
    pkill -9 -f "MicroXRCEAgent" 2>/dev/null
    pkill -9 -f "gz sim" 2>/dev/null
    pkill -9 -f "ruby.*gz sim" 2>/dev/null
    sleep 4
}

if [ "${1:-}" = "--restart" ]; then
    teardown
fi

if pgrep -f "px4_sitl_default/bin/px4" >/dev/null 2>&1; then
    echo "[sim_up] PX4 already running, reusing."
else
    echo "[sim_up] starting PX4 SITL + Gazebo (ROS_DOMAIN_ID=$ROS_DOMAIN_ID)..."
    # PX4's interactive pxh prompt redraws itself forever when stdout is not a
    # TTY, which grows the log by megabytes a minute -- discard it.
    setsid env ROS_DOMAIN_ID="$ROS_DOMAIN_ID" HEADLESS=1 \
        bash -c "cd '$PX4_DIR' && make px4_sitl gz_x500" \
        < /dev/null > /dev/null 2>&1 &
    disown
fi

if pgrep -f "MicroXRCEAgent" >/dev/null 2>&1; then
    echo "[sim_up] XRCE agent already running, reusing."
else
    # PX4's rcS copies $ROS_DOMAIN_ID into UXRCE_DDS_DOM_ID, so the agent must
    # be on the same domain or the bridged topics land somewhere nothing is
    # listening.
    sleep 6
    echo "[sim_up] starting Micro XRCE-DDS Agent on udp4:$DDS_PORT..."
    setsid env ROS_DOMAIN_ID="$ROS_DOMAIN_ID" MicroXRCEAgent udp4 -p "$DDS_PORT" \
        < /dev/null > "$LOG_DIR/agent.log" 2>&1 &
    disown
fi

echo "[sim_up] waiting for live sensor data (timeout ${READY_TIMEOUT_S}s)..."
deadline=$(( $(date +%s) + READY_TIMEOUT_S ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    if timeout 4 ros2 topic echo /fmu/out/sensor_combined --once >/dev/null 2>&1; then
        echo "[sim_up] sensor_combined is flowing."
        # A GPS fix and a barometer reading are what PX4 actually gates arming
        # on, so wait for those too rather than declaring victory on IMU alone.
        if timeout 6 ros2 topic echo /fmu/out/vehicle_gps_position --once >/dev/null 2>&1; then
            echo "[sim_up] GPS is flowing. Simulation READY on domain $ROS_DOMAIN_ID."
            exit 0
        fi
    fi
    sleep 3
done

echo "[sim_up] TIMEOUT: no live sensor data after ${READY_TIMEOUT_S}s." >&2
echo "[sim_up] PX4 running: $(pgrep -cf 'px4_sitl_default/bin/px4')" >&2
echo "[sim_up] agent running: $(pgrep -cf MicroXRCEAgent)" >&2
echo "[sim_up] gz running: $(pgrep -cf 'gz sim')" >&2
exit 1
