#!/bin/bash
# Hyperion XDP M5 Telemetry Demo Script
# This script demonstrates the telemetry features of Hyperion XDP

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║       HYPERION XDP - M5 TELEMETRY DEMONSTRATION          ║
║         5-Tuple Flow Tracking & Event Monitoring         ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] Please run as root (use sudo)${NC}"
    exit 1
fi

# Check if binary exists
if [ ! -f "bin/hyperion_ctrl" ]; then
    echo -e "${YELLOW}[*] Building Hyperion...${NC}"
    make build
fi

echo -e "${GREEN}[✓] Hyperion binary found${NC}"
echo ""

# Demo options
echo -e "${BLUE}Demo Options:${NC}"
echo "1. Basic telemetry (stdout only)"
echo "2. Telemetry with file logging"
echo "3. Signature detection demo"
echo "4. Dynamic reload demo"
echo ""
read -p "Select demo (1-4): " DEMO_CHOICE

case $DEMO_CHOICE in
    1)
        echo -e "${YELLOW}[*] Starting Hyperion with telemetry on loopback...${NC}"
        echo -e "${YELLOW}[*] Press Ctrl+C to stop${NC}"
        echo ""
        ./bin/hyperion_ctrl -iface lo -telemetry
        ;;
    2)
        LOGFILE="/tmp/hyperion_demo_$(date +%s).log"
        echo -e "${YELLOW}[*] Starting Hyperion with file logging...${NC}"
        echo -e "${YELLOW}[*] Log file: ${LOGFILE}${NC}"
        echo -e "${YELLOW}[*] Press Ctrl+C to stop${NC}"
        echo ""
        ./bin/hyperion_ctrl -iface lo -telemetry -logfile "$LOGFILE" &
        HYPERION_PID=$!
        sleep 2
        echo -e "${GREEN}[✓] Hyperion running (PID: $HYPERION_PID)${NC}"
        echo ""
        echo -e "${BLUE}[*] Monitoring log file (Ctrl+C to stop)...${NC}"
        tail -f "$LOGFILE"
        ;;
    3)
        echo -e "${YELLOW}[*] Starting signature detection demo...${NC}"
        echo -e "${YELLOW}[*] Signatures: 'hack', 'malware'${NC}"
        echo ""
        ./bin/hyperion_ctrl -iface lo -telemetry -sig "hack,malware" &
        HYPERION_PID=$!
        sleep 2
        echo -e "${GREEN}[✓] Hyperion running (PID: $HYPERION_PID)${NC}"
        echo ""
        echo -e "${BLUE}[*] Send test traffic with netcat: echo 'hack' | nc localhost 8080${NC}"
        echo -e "${YELLOW}[*] Press Ctrl+C when done${NC}"
        wait $HYPERION_PID
        ;;
    4)
        echo -e "${YELLOW}[*] Starting dynamic reload demo...${NC}"
        echo ""
        
        # Create initial signatures
        echo "test1" > signatures.txt
        echo -e "${GREEN}[✓] Created signatures.txt with 'test1'${NC}"
        
        # Start Hyperion
        ./bin/hyperion_ctrl -iface lo -telemetry &
        HYPERION_PID=$!
        sleep 2
        echo -e "${GREEN}[✓] Hyperion running (PID: $HYPERION_PID)${NC}"
        echo ""
        
        # Wait for user input
        read -p "Press Enter to update signatures and reload..."
        
        # Update signatures
        echo "test2" > signatures.txt
        echo -e "${GREEN}[✓] Updated signatures.txt with 'test2'${NC}"
        
        # Trigger reload
        echo -e "${YELLOW}[*] Sending SIGHUP to reload...${NC}"
        kill -HUP $HYPERION_PID
        sleep 1
        echo ""
        echo -e "${GREEN}[✓] Reload complete!${NC}"
        echo ""
        
        read -p "Press Enter to stop Hyperion..."
        kill -SIGTERM $HYPERION_PID
        wait $HYPERION_PID 2>/dev/null || true
        echo -e "${GREEN}[✓] Hyperion stopped${NC}"
        ;;
    *)
        echo -e "${RED}[!] Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}[✓] Demo complete${NC}"
