#!/usr/bin/env python3
"""
SSH honeypot (Paramiko).
- Logs connections, auth attempts, commands, and session duration.
- Emulates a minimal interactive shell (no real command execution).
"""

from __future__ import annotations

import os
import socket
import threading
import time
import traceback
from dataclasses import dataclass
from typing import Optional, Tuple

import paramiko

from logger import create_logger, HoneypotLogger


HOST = "0.0.0.0"
PORT = int(os.environ.get("HONEYPOT_PORT", "22"))

LOG_PATH = os.environ.get("HONEYPOT_LOG_PATH", "/app/logs/honeypot.log")
HOSTKEY_PATH = os.environ.get("HONEYPOT_HOSTKEY_PATH", "/app/hostkey_rsa")

#Make it look like a real-ish SSH server
SERVER_BANNER = os.environ.get("HONEYPOT_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")

#Users we *might* allow to "login" (fake shell)
ALLOW_USERS = set(u.strip() for u in os.environ.get("HONEYPOT_ALLOW_USERS", "root,admin,ubuntu,test").split(","))
MAX_AUTH_TRIES = int(os.environ.get("HONEYPOT_MAX_AUTH_TRIES", "5"))

#Session behavior
IDLE_TIMEOUT_S = int(os.environ.get("HONEYPOT_IDLE_TIMEOUT_S", "180"))
SHELL_PROMPT = os.environ.get("HONEYPOT_PROMPT", "ubuntu@ip-172-20-0-30:~$ ")


@dataclass
class ConnMeta:
    conn_id: str
    src_ip: str
    src_port: int
    started_at: float


def ensure_hostkey(path: str) -> paramiko.RSAKey:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)

    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key


class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, hp: HoneypotLogger, meta: ConnMeta):
        self.hp = hp
        self.meta = meta
        self.event = threading.Event()

        self.username: Optional[str] = None
        self.auth_ok = False
        self.auth_tries = 0

    def get_banner(self):
        #Paramiko lets us present a server banner string; keep it plausible.
        return (SERVER_BANNER, "en-US")

    def check_channel_request(self, kind: str, chanid: int):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str):
        self.auth_tries += 1
        self.username = username

        self.hp.event(
            "auth_attempt",
            conn_id=self.meta.conn_id,
            src_ip=self.meta.src_ip,
            src_port=self.meta.src_port,
            username=username,
            password=password,
            attempt=self.auth_tries,
        )

        #Brute-force alert
        if self.hp.track_failed_login(self.meta.src_ip, window_s=60, threshold=5):
            self.hp.event(
                "alert_bruteforce",
                conn_id=self.meta.conn_id,
                src_ip=self.meta.src_ip,
                src_port=self.meta.src_port,
                note=">=5 failed login attempts within 60s (across sessions)",
            )

        #Decide whether to allow login (to capture commands).
        #Plausible behavior: allow only common usernames, others denied.
        if username in ALLOW_USERS:
            self.auth_ok = True
            return paramiko.AUTH_SUCCESSFUL

        #If too many tries, disconnect soon (we still log attempts).
        if self.auth_tries >= MAX_AUTH_TRIES:
            return paramiko.AUTH_FAILED

        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def fake_command_response(cmd: str, username: str) -> str:
    """
    Minimal, believable fake responses for common recon commands.
    Keep outputs small and plausible."""
    c = cmd.strip()
    if not c:
        return ""

    if c in ("exit", "logout"):
        return "__EXIT__"

    if c == "whoami":
        return f"{username}\n"
    if c == "pwd":
        return "/home/ubuntu\n"
    if c.startswith("cd "):
        return ""
    if c == "ls" or c.startswith("ls "):
        return "Documents  Downloads  .ssh  notes.txt\n"
    if c == "id":
        return f"uid=1000({username}) gid=1000({username}) groups=1000({username}),27(sudo)\n"
    if c == "uname -a":
        return "Linux ip-172-20-0-30 5.15.0-1051-aws #56-Ubuntu SMP x86_64 GNU/Linux\n"
    if c.startswith("cat "):
        path = c[4:].strip()
        if path in ("/etc/passwd", "etc/passwd"):
            return (
                "root:x:0:0:root:/root:/bin/bash\n"
                "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
            )
        if path.endswith("notes.txt"):
            return "TODO: rotate keys and update backups\n"
        return f"cat: {path}: No such file or directory\n"
    if c.startswith("curl ") or c.startswith("wget "):
        return "bash: curl: command not found\n" if c.startswith("curl ") else "bash: wget: command not found\n"
    if c in ("sudo -l", "sudo -ll"):
        return (
            "Matching Defaults entries for ubuntu on this host:\n"
            "    env_reset, mail_badpass\n\n"
            "User ubuntu may run the following commands on this host:\n"
            "    (ALL : ALL) ALL\n"
        )
    if c == "ps aux":
        return "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
    if "passwd" in c or "useradd" in c:
        return "Permission denied.\n"

    return f"bash: {c.split()[0]}: command not found\n"


def handle_client(client_sock: socket.socket, addr: Tuple[str, int], hostkey: paramiko.RSAKey, hp: HoneypotLogger):
    src_ip, src_port = addr[0], addr[1]
    conn_id = f"{int(time.time()*1000)}-{src_ip}:{src_port}"
    started = time.time()
    meta = ConnMeta(conn_id=conn_id, src_ip=src_ip, src_port=src_port, started_at=started)

    hp.event("connect", conn_id=conn_id, src_ip=src_ip, src_port=src_port)

    transport = None
    channel = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(hostkey)
        transport.local_version = SERVER_BANNER

        server = FakeSSHServer(hp, meta)
        transport.start_server(server=server)

        channel = transport.accept(20)
        if channel is None:
            hp.event("disconnect", conn_id=conn_id, src_ip=src_ip, src_port=src_port, reason="no_channel")
            return

        #Wait for shell request
        server.event.wait(15)
        if not server.event.is_set():
            hp.event("disconnect", conn_id=conn_id, src_ip=src_ip, src_port=src_port, reason="no_shell_request")
            return

        username = server.username or "unknown"

        #Fake login banner / MOTD
        channel.send("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0 x86_64)\r\n\r\n")
        channel.send(" * Documentation:  https://help.ubuntu.com\r\n")
        channel.send(" * Management:     https://landscape.canonical.com\r\n")
        channel.send("\r\nLast login: " + time.strftime("%a %b %d %H:%M:%S %Y") + " from " + src_ip + "\r\n")
        channel.send(SHELL_PROMPT)

        hp.event("session_start", conn_id=conn_id, src_ip=src_ip, src_port=src_port, username=username)

        buf = b""
        last_activity = time.time()

        while True:
            if channel.recv_ready():
                data = channel.recv(4096)
                if not data:
                    break
                last_activity = time.time()
                buf += data

                #Handle line-by-line (accept both \n and \r\n)
                while b"\n" in buf or b"\r" in buf:
                    #Normalize line ending split
                    if b"\n" in buf:
                        line, _, rest = buf.partition(b"\n")
                        buf = rest
                    else:
                        line, _, rest = buf.partition(b"\r")
                        buf = rest

                    cmd = line.decode(errors="replace").strip()
                    hp.event(
                        "command",
                        conn_id=conn_id,
                        src_ip=src_ip,
                        src_port=src_port,
                        username=username,
                        cmd=cmd,
                    )

                    resp = fake_command_response(cmd, username)
                    if resp == "__EXIT__":
                        channel.send("\r\nlogout\r\n")
                        raise SystemExit

                    if resp:
                        #Use CRLF to feel SSH-like
                        channel.send(resp.replace("\n", "\r\n"))

                    channel.send(SHELL_PROMPT)

            else:
                #Idle timeout
                if time.time() - last_activity > IDLE_TIMEOUT_S:
                    hp.event(
                        "disconnect",
                        conn_id=conn_id,
                        src_ip=src_ip,
                        src_port=src_port,
                        reason="idle_timeout",
                    )
                    break
                time.sleep(0.05)

    except SystemExit:
        pass
    except Exception as e:
        hp.event(
            "error",
            conn_id=conn_id,
            src_ip=src_ip,
            src_port=src_port,
            error=str(e),
            trace=traceback.format_exc().splitlines()[-3:],
        )
    finally:
        duration = round(time.time() - started, 3)
        hp.event("session_end", conn_id=conn_id, src_ip=src_ip, src_port=src_port, duration_s=duration)

        try:
            if channel is not None:
                channel.close()
        except Exception:
            pass
        try:
            if transport is not None:
                transport.close()
        except Exception:
            pass
        try:
            client_sock.close()
        except Exception:
            pass


def run():
    hp = create_logger(LOG_PATH)
    hostkey = ensure_hostkey(HOSTKEY_PATH)

    hp.event("startup", host=HOST, port=PORT, banner=SERVER_BANNER, allow_users=sorted(ALLOW_USERS))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(100)

    while True:
        client, addr = sock.accept()
        t = threading.Thread(target=handle_client, args=(client, addr, hostkey, hp), daemon=True)
        t.start()


if __name__ == "__main__":
    run()

