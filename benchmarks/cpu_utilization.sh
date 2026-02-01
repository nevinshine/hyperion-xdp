#!/bin/bash
#
# Hyperion XDP CPU Utilization Benchmark
# Monitors CPU usage during XDP processing across different modes
#
# Requirements: sysstat (mpstat), bpftool (optional)
#

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

DURATION="${DURATION:-30}"
INTERVAL="${INTERVAL:-1}"
IFACE="${IFACE:-lo}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/hyperion_cpu}"

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  Hyperion XDP CPU Utilization${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo -e "  Duration: ${DURATION}s per test"
echo -e "  Sample Interval: ${INTERVAL}s"
echo -e "  Interface: ${IFACE}"
echo -e "  Output: ${OUTPUT_DIR}"
echo ""

# Check dependencies
check_dependencies() {
    local missing=()
    
    if ! command -v mpstat &> /dev/null; then
        missing+=("sysstat")
    fi
    
    if ! command -v iperf3 &> /dev/null; then
        missing+=("iperf3")
    fi
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}[ERROR] Missing dependencies: ${missing[*]}${NC}"
        echo -e "${YELLOW}Install with: sudo apt-get install ${missing[*]}${NC}"
        exit 1
    fi
}

# Setup output directory
setup_output() {
    mkdir -p "${OUTPUT_DIR}"
    rm -f "${OUTPUT_DIR}"/*.log
    echo -e "${GREEN}Output directory: ${OUTPUT_DIR}${NC}"
}

# Monitor CPU usage
monitor_cpu() {
    local test_name=$1
    local output_file="${OUTPUT_DIR}/${test_name}_cpu.log"
    local pid_file="${OUTPUT_DIR}/${test_name}.pid"
    
    echo -e "\n${GREEN}Monitoring CPU for: ${test_name}${NC}"
    echo -e "Collecting data for ${DURATION} seconds..."
    
    # Start mpstat in background
    mpstat ${INTERVAL} $((DURATION / INTERVAL)) > "${output_file}" 2>&1 &
    echo $! > "${pid_file}"
    
    # Also monitor specific process if hyperion is running
    if pgrep -f hyperion_ctrl > /dev/null; then
        local hyperion_pid=$(pgrep -f hyperion_ctrl | head -1)
        echo -e "  Hyperion PID: ${hyperion_pid}"
        
        # Monitor specific process
        local proc_file="${OUTPUT_DIR}/${test_name}_hyperion.log"
        top -b -d ${INTERVAL} -n $((DURATION / INTERVAL)) -p ${hyperion_pid} > "${proc_file}" 2>&1 &
    fi
}

# Generate traffic load for testing
generate_load() {
    local duration=$1
    
    echo -e "${BLUE}Generating network load...${NC}"
    
    # Start iperf3 server if not running
    if ! pgrep -f "iperf3 -s" > /dev/null; then
        iperf3 -s -D > /dev/null 2>&1
        sleep 1
    fi
    
    # Generate traffic
    timeout ${duration} iperf3 -c 127.0.0.1 -t ${duration} -P 4 > /dev/null 2>&1 &
    
    # Also generate some packet-level traffic
    timeout ${duration} ping -f 127.0.0.1 > /dev/null 2>&1 &
}

# Parse and summarize CPU usage
parse_cpu_stats() {
    local log_file=$1
    local test_name=$2
    
    if [ ! -f "${log_file}" ]; then
        echo -e "${YELLOW}  No data for ${test_name}${NC}"
        return
    fi
    
    echo -e "\n${GREEN}${test_name} Results:${NC}"
    
    # Extract average CPU metrics using awk
    local avg_user=$(grep "Average" "${log_file}" | awk '{print $3}' | tail -1)
    local avg_system=$(grep "Average" "${log_file}" | awk '{print $5}' | tail -1)
    local avg_idle=$(grep "Average" "${log_file}" | awk '{print $NF}' | tail -1)
    
    if [ -n "${avg_user}" ]; then
        echo -e "  Avg User CPU: ${BLUE}${avg_user}%${NC}"
        echo -e "  Avg System CPU: ${BLUE}${avg_system}%${NC}"
        echo -e "  Avg Idle: ${BLUE}${avg_idle}%${NC}"
        
        # Calculate total usage
        local total_used=$(echo "100 - ${avg_idle}" | bc 2>/dev/null || echo "N/A")
        echo -e "  Total CPU Used: ${BLUE}${total_used}%${NC}"
    else
        echo -e "${YELLOW}  Could not parse statistics${NC}"
    fi
}

# Check for XDP program
check_xdp_program() {
    if command -v bpftool &> /dev/null; then
        echo -e "\n${BLUE}Checking XDP programs:${NC}"
        bpftool net show 2>/dev/null || echo "  No XDP programs attached"
    fi
}

# Test 1: Baseline (no XDP)
test_baseline() {
    echo -e "\n${GREEN}[1/3] Baseline Test (No XDP)${NC}"
    echo -e "${YELLOW}Ensure Hyperion is NOT running${NC}"
    echo -e "Press ENTER to continue (or Ctrl+C to skip)..."
    read -r
    
    monitor_cpu "baseline"
    generate_load ${DURATION}
    wait
    
    parse_cpu_stats "${OUTPUT_DIR}/baseline_cpu.log" "Baseline (No XDP)"
}

# Test 2: Header filtering
test_header_filtering() {
    echo -e "\n${GREEN}[2/3] Header Filtering Test${NC}"
    echo -e "${YELLOW}Start Hyperion with: sudo ./bin/hyperion_ctrl -iface ${IFACE} -sig \"\"${NC}"
    echo -e "Press ENTER when ready (or Ctrl+C to skip)..."
    read -r
    
    check_xdp_program
    monitor_cpu "header_filter"
    generate_load ${DURATION}
    wait
    
    parse_cpu_stats "${OUTPUT_DIR}/header_filter_cpu.log" "Header Filtering"
}

# Test 3: Full DPI
test_dpi() {
    echo -e "\n${GREEN}[3/3] Full DPI Test${NC}"
    echo -e "${YELLOW}Start Hyperion with: sudo ./bin/hyperion_ctrl -iface ${IFACE} -sig \"malware,hack\"${NC}"
    echo -e "Press ENTER when ready (or Ctrl+C to skip)..."
    read -r
    
    check_xdp_program
    monitor_cpu "full_dpi"
    generate_load ${DURATION}
    wait
    
    parse_cpu_stats "${OUTPUT_DIR}/full_dpi_cpu.log" "Full DPI"
}

# Generate summary report
generate_report() {
    echo -e "\n${BLUE}======================================${NC}"
    echo -e "${BLUE}  CPU Utilization Summary${NC}"
    echo -e "${BLUE}======================================${NC}"
    
    parse_cpu_stats "${OUTPUT_DIR}/baseline_cpu.log" "Baseline"
    parse_cpu_stats "${OUTPUT_DIR}/header_filter_cpu.log" "Header Filter"
    parse_cpu_stats "${OUTPUT_DIR}/full_dpi_cpu.log" "Full DPI"
    
    echo -e "\n${YELLOW}Detailed logs saved to: ${OUTPUT_DIR}/*.log${NC}"
    
    # Check if bpftool is available for BPF stats
    if command -v bpftool &> /dev/null; then
        echo -e "\n${BLUE}BPF Program Statistics:${NC}"
        bpftool prog show 2>/dev/null | grep -A5 "xdp" || echo "  No XDP programs found"
    fi
    
    echo ""
}

# Main execution
main() {
    check_dependencies
    setup_output
    
    # Cleanup function
    cleanup() {
        echo -e "\n${YELLOW}Cleaning up...${NC}"
        pkill -f iperf3 2>/dev/null || true
        pkill -f "ping -f" 2>/dev/null || true
    }
    trap cleanup EXIT
    
    test_baseline
    test_header_filtering
    test_dpi
    
    generate_report
}

main "$@"
