## SSH Honeypot

This honeypot simulates an SSH service (port 22 in-container) using Paramiko. It does NOT provide a real shell.
Instead, it emulates a minimal interactive prompt to capture attacker behavior safely.

### What it logs (JSON lines)
- Connection metadata: source IP/port, timestamps, session duration
- Authentication attempts: username/password (each try)
- Commands typed in the fake shell (one event per command)
- Alerts:
  - `alert_bruteforce` when an IP reaches >=5 failed logins within 60 seconds

Logs are written to: `logs/honeypot.log`

### Why it’s convincing
- Presents an OpenSSH-like banner (configurable)
- Shows a realistic Ubuntu MOTD + last login line
- Provides a prompt and plausible responses for common recon commands

### Run
From repo root:
```bash
docker compose up --build -d honeypot

```
