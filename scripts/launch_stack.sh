#!/usr/bin/env bash
# One-command launcher: PX4 SITL + Gazebo Jetty, Micro XRCE-DDS Agent, and the
# uav_security_ws / px4_msgs_ws ROS 2 environment.
set -u

PX4_DIR="${PX4_DIR:-$HOME/PX4-Autopilot}"
PX4_MSGS_WS="${PX4_MSGS_WS:-$HOME/px4_msgs_ws}"
UAV_SECURITY_WS="${UAV_SECURITY_WS:-$HOME/uav_security_ws}"
DDS_AGENT_BIN="${DDS_AGENT_BIN:-MicroXRCEAgent}"
DDS_PORT="${DDS_PORT:-8888}"

PIDS=()

cleanup() {
    echo "[launch_stack] shutting down..."
    for pid in "${PIDS[@]:-}"; do
        if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
        fi
    done
    wait 2>/dev/null
}
trap cleanup INT TERM EXIT

echo "[launch_stack] starting PX4 SITL + Gazebo (gz_x500)..."
(cd "$PX4_DIR" && make px4_sitl gz_x500) &
PIDS+=("$!")

echo "[launch_stack] waiting for PX4/Gazebo to initialize..."
sleep 15

echo "[launch_stack] starting Micro XRCE-DDS Agent on udp4:$DDS_PORT..."
"$DDS_AGENT_BIN" udp4 -p "$DDS_PORT" &
PIDS+=("$!")

sleep 3

echo "[launch_stack] sourcing ROS 2 workspaces..."
# shellcheck disable=SC1090,SC1091
source /opt/ros/lyrical/setup.bash
[ -f "$PX4_MSGS_WS/install/setup.bash" ] && source "$PX4_MSGS_WS/install/setup.bash"
[ -f "$UAV_SECURITY_WS/install/setup.bash" ] && source "$UAV_SECURITY_WS/install/setup.bash"

echo "[launch_stack] stack is up. Press Ctrl+C to stop everything."
wait
