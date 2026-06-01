#!/usr/bin/env bash

# Robust local networking namespace setup script for Hyperion XDP
set -euo pipefail

# Namespaces and interface definitions
NS_ATTACKER="attacker"
NS_VICTIM="victim"
VETH_ATK="veth-atk"
VETH_VIC="veth-vic"

IP_ATTACKER="10.0.0.1/24"
IP_VICTIM="10.0.0.2/24"

# 1. Clean up old states
echo "[*] Cleaning up old network namespaces and veth configurations..."
ip netns del "$NS_ATTACKER" 2>/dev/null || true
ip netns del "$NS_VICTIM" 2>/dev/null || true
ip link del "$VETH_ATK" 2>/dev/null || true

# 2. Build isolated network environments
echo "[*] Constructing 'attacker' and 'victim' environments..."
ip netns add "$NS_ATTACKER"
ip netns add "$NS_VICTIM"

# 3. Provision the virtual wire link
echo "[*] Provisioning veth pair link: $VETH_ATK <-> $VETH_VIC"
ip link add "$VETH_ATK" type veth peer name "$VETH_VIC"

# 4. Bind links to respective boundaries
echo "[*] Allocating interfaces to namespaces..."
ip link set "$VETH_ATK" netns "$NS_ATTACKER"
ip link set "$VETH_VIC" netns "$NS_VICTIM"

# 5. Configure network interface layers
echo "[*] Configuring IP layout and loopback links..."
# Attacker configuration
ip netns exec "$NS_ATTACKER" ip addr add "$IP_ATTACKER" dev "$VETH_ATK"
ip netns exec "$NS_ATTACKER" ip link set "$VETH_ATK" up
ip netns exec "$NS_ATTACKER" ip link set lo up

# Victim configuration
ip netns exec "$NS_VICTIM" ip addr add "$IP_VICTIM" dev "$VETH_VIC"
ip netns exec "$NS_VICTIM" ip link set "$VETH_VIC" up
ip netns exec "$NS_VICTIM" ip link set lo up

echo "[+] Success. Environment is staged."
echo " -> Attacker Namespace IP: 10.0.0.1 ($VETH_ATK)"
echo " -> Victim Namespace IP:   10.0.0.2 ($VETH_VIC)"
echo "[*] Ready to attach Hyperion XDP to target interface: $VETH_VIC"
