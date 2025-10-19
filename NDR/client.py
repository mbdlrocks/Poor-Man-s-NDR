#!/usr/bin/env python3

"""
Client that repeatedly opens a new TCP connection from a (different) ephemeral source port,
sends a fixed-size payload, then closes. 
Useful to simulate repeated bot callbacks from different ephemeral client ports to the same C2 address:port.
"""

import socket
import time
import random

HOST = '127.0.0.1'
PORT = 9999
INTERVAL = 0.5          
PAYLOAD_SIZE = 64       
EPHEMERAL_LO = 49152
EPHEMERAL_HI = 65535
BIND_ATTEMPTS = 10      
TIMEOUT = 3.0           
payload = b'A' * PAYLOAD_SIZE

def make_connection_once():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)

    bound = False
    for _ in range(BIND_ATTEMPTS):
        src_port = random.randint(EPHEMERAL_LO, EPHEMERAL_HI)
        try:
            s.bind(('0.0.0.0', src_port))
            bound = True
            break
        except OSError:
            continue

    if not bound:
        src_port = None

    try:
        s.connect((HOST, PORT))
        actual_src = s.getsockname()[1]
        s.sendall(payload)
        print(f"[>] Connected from source port {actual_src} -> {HOST}:{PORT}, sent {PAYLOAD_SIZE} bytes")
    except ConnectionRefusedError:
        print("[!] Connection refused (is server running?)")
    except socket.timeout:
        print("[!] Connection timed out")
    except Exception as e:
        print(f"[!] Socket error: {e}")
    finally:
        try:
            s.close()
        except Exception:
            pass

def main():
    print(f"[i] Sending {PAYLOAD_SIZE}-byte periodic connections to {HOST}:{PORT} every {INTERVAL}s")
    try:
        while True:
            make_connection_once()
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        print("\n[i] Stopped by user")

if __name__ == "__main__":
    main()
