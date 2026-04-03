# WireGuard VPN

The capstone uses WireGuard to connect your attack host to the MERIDIAN target.

## Network

| Host | IP | Role |
|------|----|------|
| MERIDIAN target | `10.10.10.1` | Server — runs WireGuard + all services |
| Group 01 | `10.10.10.2` | Attack host |
| Group 02 | `10.10.10.3` | Attack host |
| ... | ... | ... |
| Group 50 | `10.10.10.51` | Attack host |

## Setup

1. Your instructor will give you a `group-NN.conf` file
2. Install it:
   ```bash
   sudo cp group-NN.conf /etc/wireguard/wg0.conf
   sudo wg-quick up wg0
   ```
3. Verify:
   ```bash
   ping 10.10.10.1
   nc 10.10.10.1 1337
   ```

## Connecting to MERIDIAN

Once WireGuard is up, replace `localhost:11337` with `10.10.10.1:1337`:

```bash
# Shellcode delivery
python3 tools/send_shellcode.py shellcode/beachhead.bin 10.10.10.1 1337

# Direct connection
nc 10.10.10.1 1337
```

## Troubleshooting

```bash
# Check WireGuard status
sudo wg show

# Check interface is up
ip addr show wg0

# Restart
sudo wg-quick down wg0 && sudo wg-quick up wg0
```
