#!/bin/bash
# gen_configs.sh — Generate WireGuard server + client configs
#
# Run once by the instructor to produce:
#   server/wg0.conf          — goes on the target VM (10.10.10.1)
#   clients/group-NN.conf    — one per student group (10.10.10.2 .. 10.10.10.51)
#
# The server config includes all 50 peers. Each client config has
# only that group's private key + the server's public key.
#
# Usage:
#   cd wireguard/ && bash gen_configs.sh
#
# Distribute:
#   Give each group their group-NN.conf (contains their private key).
#   Never share the server private key or other groups' keys.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PEERS_FILE="keys/all_peers.txt"
SERVER_PRIV=$(cat server_private.key)
SERVER_PUB=$(cat server_public.key)

WG_PORT=51820
SERVER_IP="10.10.10.1/24"

# ── Server config ────────────────────────────────────────────────────────────

mkdir -p server clients

cat > server/wg0.conf << EOF
# WireGuard server config for MERIDIAN target VM
# Address: 10.10.10.1
# Listen on port $WG_PORT
#
# Install on target VM:
#   cp wg0.conf /etc/wireguard/wg0.conf
#   wg-quick up wg0

[Interface]
Address = $SERVER_IP
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIV

EOF

# ── Generate peer entries + client configs ───────────────────────────────────

while IFS=' ' read -r NUM PRIV PUB PSK; do
    CLIENT_IP="10.10.10.$((10#$NUM + 1))"

    # Append peer to server config
    cat >> server/wg0.conf << EOF
# Group $NUM ($CLIENT_IP)
[Peer]
PublicKey = $PUB
PresharedKey = $PSK
AllowedIPs = ${CLIENT_IP}/32

EOF

    # Write client config
    PADNUM=$(printf '%02d' "$((10#$NUM))")
    cat > "clients/group-${PADNUM}.conf" << EOF
# WireGuard config for Group $NUM
# Your IP: $CLIENT_IP → Target: 10.10.10.1
#
# Usage:
#   sudo cp group-${PADNUM}.conf /etc/wireguard/wg0.conf
#   sudo wg-quick up wg0
#
# Then connect to MERIDIAN:
#   nc 10.10.10.1 1337

[Interface]
Address = ${CLIENT_IP}/32
PrivateKey = $PRIV

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $PSK
AllowedIPs = 10.10.10.0/24
Endpoint = <SERVER_PUBLIC_IP>:$WG_PORT
PersistentKeepalive = 25
EOF

done < "$PEERS_FILE"

echo "Generated:"
echo "  server/wg0.conf           ($(grep -c '^\[Peer\]' server/wg0.conf) peers)"
echo "  clients/group-01.conf .. group-$(printf '%02d' "$(wc -l < "$PEERS_FILE")").conf"
echo ""
echo "Next steps:"
echo "  1. Set <SERVER_PUBLIC_IP> in each client config (or use 'make wg-set-endpoint IP=x.x.x.x')"
echo "  2. Copy server/wg0.conf to the target VM golden image"
echo "  3. Distribute each group-NN.conf to the corresponding group"
