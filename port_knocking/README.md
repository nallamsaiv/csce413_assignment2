## Port Knocking Implementation

### What this protects
- Protected service port: TCP 2222
- Default state: port 2222 is blocked via iptables (DROP rule)

### Knock design
- Knock protocol: UDP
- Knock sequence: 1234,5678,9012 (configurable)
- Timing window: 10 seconds to complete the sequence (configurable)

### How access is granted
- The server listens on UDP ports in the sequence.
- It tracks progress per source IP address.
- When a client completes the sequence within the time window:
  - the server inserts an iptables rule allowing ONLY that source IP to connect to TCP 2222
  - the rule is tagged with comment `knock_allow`
  - the allow rule is removed automatically after 30 seconds (configurable)

### Demo protected service
- For demonstration, the port_knocking container runs a small TCP service on port 2222.
- Once the firewall opens, `nc` can successfully connect.

### How to run demo
From repo root:
```bash
docker compose up --build -d port_knocking
cd port_knocking
./demo.sh 172.20.0.40
```
### Example usage
```bash
python3 knock_client.py --target 172.20.0.40 --sequence 1234,5678,9012
```
