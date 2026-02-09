## MITM
Tiny script that sniffs TCP traffic on port **3306** (MySQL) and prints the raw payload as readable ASCII (non-printable bytes show as `.`).

## Requirements
- Python 3
- scapy

## Run
```bash
sudo python3 sniff_mysql.py
```