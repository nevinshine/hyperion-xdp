#!/bin/bash
set -e

echo "=== Hyperion eBPF Verifier Budget Gate ==="

# Ensure bpftool is available
if ! command -v bpftool &> /dev/null; then
    echo "[-] Error: bpftool is required."
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "[-] Error: jq is required."
    exit 1
fi

BASELINE_FILE="ci/verifier_baseline.json"
OBJ_FILE="src/user/bpf_bpfel.o"

if [ ! -f "$OBJ_FILE" ]; then
    echo "[-] Error: BPF object file $OBJ_FILE not found. Run 'go generate' first."
    exit 1
fi

if [ ! -f "$BASELINE_FILE" ]; then
    echo "[-] Error: Baseline file $BASELINE_FILE not found."
    exit 1
fi

echo "[*] Loading baseline data..."
base_insn=$(jq -r '.instruction_count' $BASELINE_FILE)
base_stack=$(jq -r '.stack_depth' $BASELINE_FILE)
base_complexity=$(jq -r '.verifier_complexity' $BASELINE_FILE)
base_helpers=$(jq -r '.helper_calls' $BASELINE_FILE)

echo "    Baseline Instructions: $base_insn"
echo "    Baseline Stack Depth:  $base_stack bytes"
echo "    Baseline Complexity:   $base_complexity peak_states"
echo "    Baseline Helpers:      $base_helpers calls"

echo "[*] Running dry-run verifier check..."
# bpftool prog load dry-run outputs verifier log
# We need to extract processed insns and stack depth
# Example verifier output: "processed 145 insns (limit 1000000) max_states_per_insn 0 total_states 11 peak_states 11 mark_read 2"
# Example verifier output: "stack depth 32"

# Note: bpftool prog load requires a map to attach to if the program uses maps.
# The dry run might fail if maps aren't loaded. We'll use a dummy mount point.
sudo mkdir -p /sys/fs/bpf/hyperion_test

# We capture stderr because verifier logs are often printed there
VERIFIER_LOG=$(sudo bpftool prog load $OBJ_FILE /sys/fs/bpf/hyperion_test/prog type xdp 2>&1 || true)
sudo rm -f /sys/fs/bpf/hyperion_test/prog

# Extract metrics
# Look for something like "processed XXX insns"
curr_insn=$(echo "$VERIFIER_LOG" | grep -oP 'processed \K\d+(?= insns)')
curr_stack=$(echo "$VERIFIER_LOG" | grep -oP 'stack depth \K\d+')
curr_complexity=$(echo "$VERIFIER_LOG" | grep -oP 'peak_states \K\d+')
curr_helpers=$(llvm-objdump -d $OBJ_FILE | grep -c 'call ' || echo "0")

# If extraction failed (e.g., verifier rejected the program, or regex didn't match)
if [ -z "$curr_insn" ] || [ -z "$curr_stack" ] || [ -z "$curr_complexity" ]; then
    echo "[-] Error: Failed to parse verifier output or program rejected."
    echo "Verifier output:"
    echo "$VERIFIER_LOG"
    exit 1
fi

echo "    Current Instructions:  $curr_insn"
echo "    Current Stack Depth:   $curr_stack bytes"
echo "    Current Complexity:    $curr_complexity peak_states"
echo "    Current Helpers:       $curr_helpers calls"

# Calculate deltas
delta_insn=$((curr_insn - base_insn))
delta_stack=$((curr_stack - base_stack))
delta_complexity=$((curr_complexity - base_complexity))
delta_helpers=$((curr_helpers - base_helpers))

echo "[*] Deltas:"
if [ $delta_insn -gt 0 ]; then echo "    Instructions: +$delta_insn"; else echo "    Instructions: $delta_insn"; fi
if [ $delta_stack -gt 0 ]; then echo "    Stack Depth:  +$delta_stack bytes"; else echo "    Stack Depth:  $delta_stack bytes"; fi
if [ $delta_complexity -gt 0 ]; then echo "    Complexity:   +$delta_complexity states"; else echo "    Complexity:   $delta_complexity states"; fi
if [ $delta_helpers -gt 0 ]; then echo "    Helpers:      +$delta_helpers calls"; else echo "    Helpers:      $delta_helpers calls"; fi

# Calculate 10% tolerance for instructions
threshold=$((base_insn + (base_insn / 10)))

if [ "$curr_insn" -gt "$threshold" ]; then
    if [ "$VERIFIER_BUDGET_OVERRIDE" = "true" ]; then
        echo "[!] Warning: Instruction count increased by >10% ($curr_insn > $threshold), but VERIFIER_BUDGET_OVERRIDE is set."
    else
        echo "[-] ERROR: Instruction count increased by >10% ($curr_insn > $threshold)."
        echo "    This is a verifier regression. Optimize the eBPF C code or explicitly update the baseline."
        exit 1
    fi
fi

comp_threshold=$((base_complexity + (base_complexity / 10)))
# If base is 0, threshold is 0. Give a small buffer if base is very low to avoid flakiness
if [ "$comp_threshold" -lt 5 ]; then comp_threshold=$((base_complexity + 2)); fi

if [ "$curr_complexity" -gt "$comp_threshold" ]; then
    if [ "$VERIFIER_BUDGET_OVERRIDE" = "true" ]; then
        echo "[!] Warning: Verifier complexity increased by >10% ($curr_complexity > $comp_threshold), but VERIFIER_BUDGET_OVERRIDE is set."
    else
        echo "[-] ERROR: Verifier complexity increased by >10% ($curr_complexity > $comp_threshold)."
        exit 1
    fi
fi

helper_threshold=$((base_helpers + (base_helpers / 10)))
if [ "$helper_threshold" -lt 2 ]; then helper_threshold=$((base_helpers + 1)); fi

if [ "$curr_helpers" -gt "$helper_threshold" ]; then
    if [ "$VERIFIER_BUDGET_OVERRIDE" = "true" ]; then
        echo "[!] Warning: Helper usage increased by >10% ($curr_helpers > $helper_threshold), but VERIFIER_BUDGET_OVERRIDE is set."
    else
        echo "[-] ERROR: Helper usage increased by >10% ($curr_helpers > $helper_threshold)."
        exit 1
    fi
fi

if [ "$curr_stack" -gt 512 ]; then
    echo "[-] ERROR: Stack depth exceeds 512 byte eBPF limit ($curr_stack > 512)."
    exit 1
fi

echo "[+] Verifier budget check passed."
exit 0
