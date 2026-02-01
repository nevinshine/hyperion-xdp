#!/bin/bash
#
# Hyperion XDP Throughput Benchmark
# Measures packets-per-second (PPS) throughput under different filter configurations
#
# Requirements: iperf3, netperf (optional)
#

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

IFACE="${IFACE:-lo}"
DURATION="${DURATION:-10}"
SERVER_IP="${SERVER_IP:-127.0.0.1}"
TEST_PORT=5201

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  Hyperion XDP Throughput Benchmark${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo -e "  Interface: ${IFACE}"
echo -e "  Duration: ${DURATION}s per test"
echo -e "  Server: ${SERVER_IP}:${TEST_PORT}"
echo ""

# Check dependencies
check_dependencies() {
    local missing=()
    
    if ! command -v iperf3 &> /dev/null; then
        missing+=("iperf3")
    fi
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}[ERROR] Missing dependencies: ${missing[*]}${NC}"
        echo -e "${YELLOW}Install with: sudo apt-get install ${missing[*]}${NC}"
        exit 1
    fi
}

# Start iperf3 server in background
start_server() {
    echo -e "${GREEN}[1/4] Starting iperf3 server...${NC}"
    iperf3 -s -p ${TEST_PORT} -D > /dev/null 2>&1
    sleep 2
    echo -e "  Server started on port ${TEST_PORT}"
}

# Stop iperf3 server
stop_server() {
    echo -e "${YELLOW}Stopping iperf3 server...${NC}"
    pkill -9 iperf3 2>/dev/null || true
    sleep 1
}

# Run throughput test
run_test() {
    local test_name=$1
    local result_file=$2
    
    echo -e "\n${GREEN}[TEST] ${test_name}${NC}"
    echo -e "Running for ${DURATION} seconds..."
    
    # Run iperf3 client
    iperf3 -c ${SERVER_IP} -p ${TEST_PORT} -t ${DURATION} -P 4 -J > ${result_file}
    
    # Extract key metrics
    local bandwidth=$(cat ${result_file} | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d: -f2)
    local packets=$(cat ${result_file} | grep -o '"packets":[0-9]*' | head -1 | cut -d: -f2)
    
    if [ -n "$bandwidth" ]; then
        local mbps=$(echo "scale=2; ${bandwidth} / 1000000" | bc 2>/dev/null || echo "N/A")
        echo -e "  ${BLUE}Throughput: ${mbps} Mbps${NC}"
    fi
    
    if [ -n "$packets" ]; then
        local pps=$(echo "scale=0; ${packets} / ${DURATION}" | bc 2>/dev/null || echo "N/A")
        echo -e "  ${BLUE}Packet Rate: ${pps} PPS${NC}"
    fi
}

# Baseline test (no XDP)
test_baseline() {
    echo -e "\n${GREEN}[2/4] Baseline Test (No XDP)${NC}"
    run_test "Baseline" "/tmp/hyperion_baseline.json"
}

# Header filtering test
test_header_filtering() {
    echo -e "\n${GREEN}[3/4] Header Filtering Test${NC}"
    echo -e "${YELLOW}Note: This requires Hyperion to be running with basic filtering${NC}"
    echo -e "${YELLOW}Start Hyperion with: sudo ./bin/hyperion_ctrl -iface ${IFACE} -sig \"\"${NC}"
    echo -e "Press ENTER when Hyperion is ready (or Ctrl+C to skip)..."
    read -r
    
    run_test "Header Filtering" "/tmp/hyperion_header.json"
}

# DPI test
test_dpi() {
    echo -e "\n${GREEN}[4/4] Full DPI Test${NC}"
    echo -e "${YELLOW}Note: This requires Hyperion to be running with DPI signatures${NC}"
    echo -e "${YELLOW}Start Hyperion with: sudo ./bin/hyperion_ctrl -iface ${IFACE} -sig \"malware,hack\"${NC}"
    echo -e "Press ENTER when Hyperion is ready (or Ctrl+C to skip)..."
    read -r
    
    run_test "Full DPI" "/tmp/hyperion_dpi.json"
}

# Generate summary report
generate_report() {
    echo -e "\n${BLUE}======================================${NC}"
    echo -e "${BLUE}  Benchmark Summary${NC}"
    echo -e "${BLUE}======================================${NC}"
    
    for test_type in baseline header dpi; do
        result_file="/tmp/hyperion_${test_type}.json"
        if [ -f "${result_file}" ]; then
            echo -e "\n${GREEN}${test_type^} Results:${NC}"
            
            # Extract metrics using grep (portable)
            bandwidth=$(grep -o '"bits_per_second":[0-9.]*' "${result_file}" | head -1 | cut -d: -f2)
            packets=$(grep -o '"packets":[0-9]*' "${result_file}" | head -1 | cut -d: -f2)
            retransmits=$(grep -o '"retransmits":[0-9]*' "${result_file}" | head -1 | cut -d: -f2)
            
            if [ -n "$bandwidth" ]; then
                mbps=$(echo "scale=2; ${bandwidth} / 1000000" | bc 2>/dev/null || echo "N/A")
                echo "  Throughput: ${mbps} Mbps"
            fi
            
            if [ -n "$packets" ]; then
                pps=$(echo "scale=0; ${packets} / ${DURATION}" | bc 2>/dev/null || echo "N/A")
                echo "  Avg Packet Rate: ${pps} PPS"
            fi
            
            if [ -n "$retransmits" ]; then
                echo "  Retransmits: ${retransmits}"
            fi
        fi
    done
    
    echo -e "\n${YELLOW}Results saved to: /tmp/hyperion_*.json${NC}"
    echo ""
}

# Main execution
main() {
    check_dependencies
    
    # Cleanup old results
    rm -f /tmp/hyperion_*.json
    
    start_server
    
    trap stop_server EXIT
    
    test_baseline
    test_header_filtering
    test_dpi
    
    generate_report
}

main "$@"
