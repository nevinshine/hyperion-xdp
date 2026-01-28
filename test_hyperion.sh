#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}[*] Setting up Hyperion Test Arena...${NC}"

# 1. Kill any lingering nc processes (Clean Slate)
pkill nc

# 2. Start the Victim (Background Listener)
# We send it to /dev/null so it doesn't clutter the screen
nc -l -k -p 8080 > /dev/null &
VICTIM_PID=$!
echo -e "${GREEN}[+] Victim Server started (PID: $VICTIM_PID)${NC}"

# 3. Wait a moment for it to bind
sleep 1

# 4. Launch the Attack
echo -e "${RED}[>] ATTACKING: Sending 'root' payload to 127.0.0.1:8080...${NC}"
echo "root" | nc -w 1 127.0.0.1 8080

# 5. Cleanup
kill $VICTIM_PID
echo -e "${GREEN}[*] Test Complete. Check Hyperion terminal for ALERT.${NC}"
