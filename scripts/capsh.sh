#!/usr/bin/env bash
set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

sudo chown -R $(id -u) /sys/kernel/debug/
trap "sudo chown -R 0 /sys/kernel/debug" EXIT
sudo -E IN_CAPSH=1 \
    capsh \
    --caps="cap_sys_ptrace,cap_sys_admin,cap_sys_resource+epi cap_setpcap,cap_setuid,cap_setgid+ep" \
    --keep=1 \
    --gid=$(id -g) \
    --uid=$(id -u) \
    --addamb=cap_sys_resource \
    --addamb=cap_sys_admin \
    --addamb=cap_sys_ptrace \
    -- -c 'direnv exec "$0" "$1"' "$DIR" "$SHELL"
