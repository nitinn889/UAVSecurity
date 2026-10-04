#!/usr/bin/env bash
# Run one Phase 5 attack scenario end-to-end: PX4 + Gazebo (if not already
# running), test_flight.py keeping the UAV in offboard hover, and the
# attack launch file for <attack_type>.
#
# Usage: ./run_attack_scenario.sh <attack_type> [duration_s]
#   attack_type: gps_spoof | gps_freeze | cmd_inject | imu_noise |
#                telemetry_replay | gps_deny
ATTACK_TYPE="${1:?Usage: $0 <attack_type> [duration_s]}"
DURATION_S="${2:-15.0}"

# Phase 7: set RUN_SUPERVISOR=false when supervisor_node runs on the Raspberry
# Pi, so this host launches only sensor_monitor + actuator + injector.
RUN_SUPERVISOR="${RUN_SUPERVISOR:-true}"

# Seconds between the injector starting and the attack firing. 5s is fine
# when the supervisor is a local process, but when it runs on the Pi the
# attack can begin before cross-host DDS discovery has connected this run's
# freshly-launched sensor_monitor to the (also freshly-restarted) remote
# supervisor. The supervisor then sees no telemetry for the first part of the
# attack and the run reads as a miss with zero flags, which is a measurement
# artifact rather than a detection failure. Give discovery room when the
# supervisor is remote.
ATTACK_DELAY_S="${ATTACK_DELAY_S:-5.0}"

PX4_DIR="${PX4_DIR:-$HOME/PX4-Autopilot}"
PX4_MSGS_WS="${PX4_MSGS_WS:-$HOME/px4_msgs_ws}"
UAV_SECURITY_WS="${UAV_SECURITY_WS:-$HOME/uav_security_ws}"

case "$ATTACK_TYPE" in
    gps_spoof|gps_freeze|cmd_inject|imu_noise|telemetry_replay|gps_deny) ;;
    *)
        echo "Unknown attack_type '$ATTACK_TYPE'. Must be one of: " \
             "gps_spoof gps_freeze cmd_inject imu_noise telemetry_replay gps_deny" >&2
        exit 1
        ;;
esac

# shellcheck disable=SC1091
source /opt/ros/lyrical/setup.bash
[ -f "$PX4_MSGS_WS/install/setup.bash" ] && source "$PX4_MSGS_WS/install/setup.bash"
[ -f "$UAV_SECURITY_WS/install/setup.bash" ] && source "$UAV_SECURITY_WS/install/setup.bash"
export PATH="/usr/bin:$PATH"

PIDS=()
cleanup() {
    echo "[run_attack_scenario] cleaning up..."
    for pid in "${PIDS[@]:-}"; do
        [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null
    done
}
trap cleanup EXIT

if ! pgrep -f "build/px4_sitl_default/bin/px4" >/dev/null; then
    echo "[run_attack_scenario] PX4 not running -- launching headless SITL..."
    (cd "$PX4_DIR" && HEADLESS=1 make px4_sitl gz_x500 < /dev/null > /dev/null 2>&1) &
    PIDS+=("$!")
    sleep 8
    nohup MicroXRCEAgent udp4 -p 8888 < /dev/null > /dev/null 2>&1 &
    PIDS+=("$!")
    sleep 4
else
    echo "[run_attack_scenario] PX4 already running, reusing it."
fi

echo "[run_attack_scenario] waiting for /fmu/out/sensor_combined to be live..."
for i in $(seq 1 30); do
    if timeout 3 ros2 topic hz /fmu/out/sensor_combined --window 5 2>/dev/null | grep -q "average rate"; then
        break
    fi
    sleep 1
done

echo "[run_attack_scenario] starting test_flight.py (offboard hover)..."
python3 "$UAV_SECURITY_WS/scripts/test_flight.py" < /dev/null > "$UAV_SECURITY_WS/data/attack_logs/.test_flight_${ATTACK_TYPE}.log" 2>&1 &
TEST_FLIGHT_PID=$!
PIDS+=("$TEST_FLIGHT_PID")

echo "[run_attack_scenario] waiting for hover..."
for i in $(seq 1 30); do
    if grep -q "Reached target altitude, hovering" "$UAV_SECURITY_WS/data/attack_logs/.test_flight_${ATTACK_TYPE}.log" 2>/dev/null; then
        break
    fi
    sleep 1
done

echo "[run_attack_scenario] launching attack_${ATTACK_TYPE}.launch.py (duration=${DURATION_S}s)..."
mkdir -p "$UAV_SECURITY_WS/data/attack_logs"

BEFORE_COUNT=$(ls "$UAV_SECURITY_WS/data/attack_logs"/attack_report_"${ATTACK_TYPE}"_*.json 2>/dev/null | wc -l)

ros2 launch attack_injector "attack_${ATTACK_TYPE}.launch.py" \
    "attack_duration_s:=${DURATION_S}" "run_supervisor:=${RUN_SUPERVISOR}" \
    "attack_delay_s:=${ATTACK_DELAY_S}" \
    > "$UAV_SECURITY_WS/data/attack_logs/.launch_${ATTACK_TYPE}.log" 2>&1 &
LAUNCH_PID=$!
PIDS+=("$LAUNCH_PID")

# injector_node exits on its own once done (attack_delay_s + attack_duration_s
# + 10s post-attack window), but the sibling sensor_monitor/supervisor nodes
# ros2 launch also started do NOT exit just because it did -- poll for the
# new report file rather than waiting on launch's own process to end.
DUR_S=$(python3 -c "import sys; print(int(float(sys.argv[1])))" "$DURATION_S" 2>/dev/null || echo 15)
DLY_S=$(python3 -c "import sys; print(int(float(sys.argv[1])))" "$ATTACK_DELAY_S" 2>/dev/null || echo 5)
TIMEOUT_S=$((DLY_S + DUR_S + 10 + 30))
echo "[run_attack_scenario] waiting up to ${TIMEOUT_S}s for injector_node's report..."
for i in $(seq 1 "$TIMEOUT_S"); do
    AFTER_COUNT=$(ls "$UAV_SECURITY_WS/data/attack_logs"/attack_report_"${ATTACK_TYPE}"_*.json 2>/dev/null | wc -l)
    if [ "$AFTER_COUNT" -gt "$BEFORE_COUNT" ]; then
        break
    fi
    sleep 1
done

kill "$TEST_FLIGHT_PID" 2>/dev/null
# SIGINT triggers ros2 launch's own graceful shutdown of sensor_monitor and
# supervisor; a bare SIGTERM/kill on just the launch process would not.
kill -INT "$LAUNCH_PID" 2>/dev/null
for i in $(seq 1 8); do
    kill -0 "$LAUNCH_PID" 2>/dev/null || break
    sleep 1
done
# Fallback: ros2 launch's shutdown sequence occasionally leaves sensor_monitor
# / supervisor running past its own exit; a leftover instance would collide
# (duplicate node name) with the next scenario's fresh one.
pkill -f "lib/security_supervisor/sensor_monitor" 2>/dev/null
pkill -f "lib/security_supervisor/supervisor" 2>/dev/null
pkill -f "lib/security_supervisor/actuator" 2>/dev/null
sleep 1

REPORT_PATH=$(ls -t "$UAV_SECURITY_WS/data/attack_logs"/attack_report_"${ATTACK_TYPE}"_*.json 2>/dev/null | head -1)
if [ -n "$REPORT_PATH" ]; then
    echo "Attack scenario complete. Report: ${REPORT_PATH}"
else
    echo "Attack scenario finished but no report file was found in $UAV_SECURITY_WS/data/attack_logs/." >&2
    exit 1
fi
