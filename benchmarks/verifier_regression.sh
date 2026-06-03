#!/bin/bash
# Verifier Regression Tracking Script
# Tracks eBPF verifier complexity over time with metadata context.

OUTPUT="benchmarks/results/verifier_history.csv"
OBJ_FILE="src/user/bpf_bpfel.o"

mkdir -p benchmarks/results

if [ ! -f "$OUTPUT" ]; then
    echo "Date,Kernel,Clang,Instructions,StackDepth,PeakStates,HelperCalls" > $OUTPUT
fi

echo "[*] Collecting Verifier Metadata..."

k_ver=$(uname -r)
clang_ver=$(clang --version | head -n 1 | grep -oP 'version \K[0-9.]+')

# Dry-run verifier to get metrics
sudo mkdir -p /sys/fs/bpf/hyperion_test
VERIFIER_LOG=$(sudo bpftool prog load $OBJ_FILE /sys/fs/bpf/hyperion_test/prog type xdp 2>&1 || true)
sudo rm -f /sys/fs/bpf/hyperion_test/prog

curr_insn=$(echo "$VERIFIER_LOG" | grep -oP 'processed \K\d+(?= insns)' || echo "0")
curr_stack=$(echo "$VERIFIER_LOG" | grep -oP 'stack depth \K\d+' || echo "0")
curr_complexity=$(echo "$VERIFIER_LOG" | grep -oP 'peak_states \K\d+' || echo "0")
curr_helpers=$(llvm-objdump -d $OBJ_FILE | grep -c 'call ' || echo "0")

curr_date=$(date +"%Y-%m-%d %H:%M:%S")

echo "${curr_date},${k_ver},${clang_ver},${curr_insn},${curr_stack},${curr_complexity},${curr_helpers}" >> $OUTPUT

echo "[+] Verifier metadata recorded in $OUTPUT:"
tail -n 1 $OUTPUT
