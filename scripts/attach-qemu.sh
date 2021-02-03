#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
export PYTHONPATH="$DIR/..:$PYTHONPATH"
python -m kvm_pirate "$@" "$(pidof qemu-system-x86_64)"
