#!/usr/bin/env bash
# Entrypoint for the Pi supervisor container.
set -e

# shellcheck disable=SC1091
source /opt/ros/lyrical/setup.bash
# shellcheck disable=SC1091
source /ws/install/setup.bash

echo "[pi_entrypoint] ROS_DOMAIN_ID=${ROS_DOMAIN_ID:-unset}"
echo "[pi_entrypoint] config:  $(ls /root/uav_security_ws/config 2>/dev/null | tr '\n' ' ')"
echo "[pi_entrypoint] models:  $(ls /root/uav_security_ws/models 2>/dev/null | tr '\n' ' ')"

exec "$@"
