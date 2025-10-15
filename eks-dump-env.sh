#!/bin/bash

for pid in /proc/[0-9]*; do
    pid_num=$(basename "$pid")
    environ_file="$pid/environ"

    # Check if we can read the environment
    if [[ -r "$environ_file" ]]; then
        echo "===== PID: $pid_num ====="
        # Convert null-separated to newline-separated
        tr '\0' '\n' < "$environ_file"
        echo
    fi
done
