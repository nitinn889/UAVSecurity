#!/usr/bin/env bash
# Verify the complete stack together: PC sim + Pi supervisor + dashboard,
# with one attack running, and confirm the dashboard actually ingests the
# encrypted traffic (not merely that its HTTP port answers).
#
# The campaign itself runs without the dashboard because it is a passive
# observer and adds a second subscriber to every topic; this check closes
# the gap by proving it works in-situ.

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

cleanup() {
    pkill -f dashboard_node 2>/dev/null
    pkill -f "lib/security_supervisor" 2>/dev/null
    pkill -f "scripts/test_flight.py" 2>/dev/null
    pkill -f injector_node 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "[fs] resetting Pi supervisor..."
ssh -o ConnectTimeout=8 -o BatchMode=yes "$PI" "docker restart uav-supervisor" >/dev/null 2>&1
sleep 18

echo "[fs] starting dashboard..."
ros2 run security_dashboard dashboard_node > "$LOG_DIR/fs_dashboard.log" 2>&1 &
sleep 8

echo "[fs] running one cmd_inject scenario with the supervisor on the Pi..."
RUN_SUPERVISOR=false ATTACK_DELAY_S=20 \
    "$WS/scripts/run_attack_scenario.sh" cmd_inject 15 > "$LOG_DIR/fs_scenario.log" 2>&1

echo
echo "=== dashboard HTTP ==="
curl -s -o /dev/null -w "  / -> HTTP %{http_code}\n" http://localhost:8080/
echo "=== dashboard state (did it ingest the encrypted stream?) ==="
curl -s http://localhost:8080/api/state 2>/dev/null | head -c 600
echo
echo "=== dashboard decrypt errors (should be none) ==="
grep -ciE "undecryptable|malformed" "$LOG_DIR/fs_dashboard.log" 2>/dev/null
echo "=== scenario verdict ==="
grep -E "Attack scenario complete|Report:" "$LOG_DIR/fs_scenario.log" 2>/dev/null | tail -2
