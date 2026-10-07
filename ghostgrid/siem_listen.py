"""Print GhostGrid's syslog alerts as they arrive: a stand-in SIEM.

    python -m ghostgrid.siem_listen --port 5514

Use it to check that alert forwarding works before pointing the decoy at a real SIEM
(set GHOSTGRID_SYSLOG_HOST=127.0.0.1 and GHOSTGRID_SYSLOG_PORT=5514 on the decoy), or
to show alerts arriving live during a demo. It only listens; it never sends anything.
"""
import argparse
import socket


def listen(port: int, host: str = "127.0.0.1") -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(0.5)          # wake up regularly so Ctrl+C works on Windows too
    print(f"Listening for GhostGrid alerts on udp://{host}:{port}  (Ctrl+C to stop)", flush=True)
    try:
        while True:
            try:
                data, (sender, _) = sock.recvfrom(65535)
            except socket.timeout:
                continue
            print(f"[{sender}] {data.decode('utf-8', 'replace')}", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Print GhostGrid's syslog alerts as they arrive (a stand-in SIEM).")
    parser.add_argument("--port", type=int, default=5514, help="UDP port to listen on (default 5514)")
    parser.add_argument("--host", default="127.0.0.1", help="address to listen on (default 127.0.0.1)")
    args = parser.parse_args()
    listen(args.port, args.host)
