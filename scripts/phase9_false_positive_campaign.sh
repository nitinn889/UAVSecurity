#!/usr/bin/env bash
# Clean-flight false-positive measurement, start to finish in one process.
#
# Brings up the PC-side nodes, resets the Pi supervisor, runs
# phase9_false_positive_run.py (which flies N clean flights and watches the
# /security topics), then tears the nodes down.
#
# Self-contained on purpose: the pieces have to stay alive for the whole
# measurement, and backgrounding them from separate shells loses them to
# process-group cleanup.
#
# Usage: ./phase9_false_positive_campaign.sh [flights]

FLIGHTS="${1:-5}"
WS="$HOME/uav_security_ws"
PI="${PI_HOST:-nitin@192.168.7.72}"
LOG_DIR="${LOG_DIR:-/tmp/phase9}"
mkdir -p "$LOG_DIR"

# shellcheck disable=SC1090,SC1091
source /opt/ros/lyrical/setup.bash
[ -f "$HOME/px4_msgs_ws/install/setup.bash" ] && source "$HOME/px4_msgs_ws/install/setup.bash"
[ -f "$WS/install/setup.bash" ] && source "$WS/install/setup.bash"
export ROS_DOMAIN_ID="${ROS_DOMAIN_ID:-42}"
PROFILE="$WS/config/fastdds_pc.xml"
[ -f "$PROFILE" ] && export FASTDDS_DEFAULT_PROFILES_FILE="$PROFILE" \
                  && export FASTRTPS_DEFAULT_PROFILES_FILE="$PROFILE"

PIDS=()
cleanup() {
    echo "[fp] tearing down..."
    for pid in "${PIDS[@]:-}"; do
        [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null
    done
    pkill -f "lib/security_supervisor/sensor_monitor" 2>/dev/null
    pkill -f "lib/security_supervisor/actuator" 2>/dev/null
    pkill -f "scripts/test_flight.py" 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "[fp] resetting Pi supervisor for a clean baseline..."
ssh -o ConnectTimeout=8 -o BatchMode=yes "$PI" "docker restart uav-supervisor" >/dev/null 2>&1
sleep 18

echo "[fp] starting PC-side nodes..."
ros2 run security_supervisor sensor_monitor > "$LOG_DIR/fp_sensor_monitor.log" 2>&1 &
PIDS+=("$!")
sleep 3
ros2 run security_supervisor actuator > "$LOG_DIR/fp_actuator.log" 2>&1 &
PIDS+=("$!")

# Let discovery connect the PC publisher to the restarted remote supervisor
# before the first flight, or flight 1 measures a link that is not up yet.
echo "[fp] waiting for discovery to settle..."
sleep 25

if ! grep -q "snapshots published" "$LOG_DIR/fp_sensor_monitor.log" 2>/dev/null; then
    echo "[fp] WARNING: sensor_monitor has not reported publishing yet" >&2
fi

echo "[fp] flying $FLIGHTS clean flights..."
python3 "$WS/scripts/phase9_false_positive_run.py" --flights "$FLIGHTS"
RC=$?
echo "[fp] done (rc=$RC)"
exit $RC
