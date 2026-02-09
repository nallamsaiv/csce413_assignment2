# Honeypot Analysis

## Summary of Observed Attacks
During testing, the honeypot recorded multiple SSH connection attempts coming from **172.20.0.1** (the Docker network gateway / attacker host in this setup). One session attempted to authenticate as **notallowed** and performed **three failed password guesses** before disconnecting (`reason: no_channel`). Immediately after, a second session authenticated as **ubuntu** (allowed user for the fake shell) and interacted with the honeypot for about **~59 seconds**, issuing several typical reconnaissance commands before exiting. Overall, the activity matched common early-stage attacker behavior: initial credential probing followed by quick host enumeration once “logged in”.

## Notable Patterns
- **Credential guessing / brute force behavior:**  
  The username **notallowed** was tried with multiple password guesses (e.g., `dnndakjdh`, `anduhiodjoj`, `badjkbkajb`), indicating a password-spraying pattern rather than a single typo.
- **Post-authentication reconnaissance:**  
  After the successful-looking login as **ubuntu**, the attacker ran commands consistent with system discovery:
  - `whoami` (confirm identity)
  - `uname` (OS/kernel fingerprinting)
  - `id` (privilege/group membership)
  - `ls` (basic directory reconnaissance)
- **Operator/tooling artifacts:**  
  There were command typos or malformed inputs like `whaomiwhoami` and a Windows-style path attempt `cat \ect\passwd` (likely intended as `/etc/passwd`). A later log entry also contained control/escape characters (e.g., `\u001b...`), which often happens when attackers paste sequences, use terminal hotkeys, or run automated tooling that emits ANSI control codes.
- **Session timing:**  
  The failed-login session ended quickly (~18.7s), while the interactive reconnaissance session lasted longer (~58.9s), which is typical when attackers only proceed once access seems possible.

## Recommendations
- **Enable stronger alerting thresholds:**  
  Trigger an alert when an IP performs repeated failed logins (e.g., 5+ failures in 60 seconds), and optionally escalate when multiple usernames are tested from the same IP.
- **Improve realism of command responses:**  
  Add more believable outputs for common commands (`uname -a`, `pwd`, `cat /etc/passwd`, `ps aux`) and handle common path variants (`/etc/passwd` vs `\etc\passwd`) so the honeypot remains convincing and keeps attackers engaged longer.
- **Enrich logs for better attribution:**  
  Include SSH client version (if available), session byte counts, and a per-session command timeline summary to make analysis easier.
- **Operational hardening:**  
  Rotate logs, export them to a central location/SIEM, and consider temporary IP blocking (or tarpitting) for repeated brute-force sources to reduce noise and resource usage.