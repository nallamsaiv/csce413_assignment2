# Port Scanner (TCP Connect)

A simple multi-threaded TCP connect port scanner for authorized lab use.

## Features
- Scan a single host/hostname/IP or a CIDR block (e.g., `172.20.0.0/24`)
- Port specs like `1-1024`, `22,80,443`, or mixed ranges
- TCP connect scan with per-port RTT timing
- Best-effort banner grabbing + lightweight service guessing

## Extra Features
- Threaded scanning for speed
- Output formats: text table (default), JSON, CSV
- Timing presets: `polite`, `normal`, `aggressive`

## File Layout
- `port_scanner/main.py` : scanner implementation + CLI
- `port_scanner/__main__.py` : allows `python3 -m port_scanner`

## Usage

### Scan one host
```bash
python3 -m port_scanner --target 172.20.0.20 --ports 1-10000
```