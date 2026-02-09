# Assignment 2: Network Security

## Important
Each part of the assignmet (i.e. in each folder for each part) there is a README.md document describing what the code is doing and how I finished the assignment (look at that for detailed review)

## Overview

This assignment focuses on network security, service discovery, man-in-the-middle (MITM) attacks, and defensive security measures. You will explore a multi-container Docker environment, discover hidden services, intercept network traffic, and implement security fixes.

## Learning Objectives

By completing this assignment, you will:

1. **Develop a port scanner** - Create a custom network scanning tool
2. **Perform network reconnaissance** - Discover hidden services on non-standard ports
3. **Execute MITM attacks** - Intercept and analyze unencrypted network traffic
4. **Implement port knocking** - Deploy a security-through-obscurity defense mechanism
5. **Build a honeypot** - Create a deception system to detect and log intrusion attempts
6. **Understand network protocols** - Learn TCP/IP, socket programming, and packet analysis

## Assignment Structure

This assignment has **three main parts**:

### Part 1: Network Reconnaissance (40 points)
- Develop a custom port scanning tool
- Discover all hidden services running in the Docker environment
- Identify service types and versions through banner grabbing
- **Capture Flag 1** and **Flag 2**

### Part 2: Man-in-the-Middle Attack (30 points)
- Analyze network traffic between containers
- Intercept unencrypted database communications
- Extract sensitive data from network packets
- **Capture Flag 3** (requires Flag 1 as prerequisite)

### Part 3: Security Fixes (30 points)
- **Fix 1: Port Knocking** - Implement a port knocking system to protect hidden services
- **Fix 2: Honeypot** - Deploy a honeypot to detect and log unauthorized access attempts

## Setup Instructions

### Prerequisites

- **Docker & Docker Compose** - Container orchestration
- **Python 3.8+** - For developing tools and exploits
- **Root/sudo access** - Required for packet sniffing (MITM attack)
- **Basic networking tools** - `tcpdump`, `wireshark`, `netcat` (optional but helpful)

### Running the Assignment

1. **Navigate to the assignment directory:**
   ```bash
   git clone <forked_repository_url>
   cd csce413_assignment2 # or your cloned repo name
   ```

2. **Start all services using Docker Compose:**
   ```bash
   docker compose up --build
   ```

3. **Verify services are running:**
   ```bash
   docker compose ps
   ```

   You should see several containers running. Note that some services are intentionally hidden and won't be directly exposed.

4. **Access the web application:**
   ```
   http://localhost:5001
   ```

   The web application is a simple user management system that interacts with a database.

### Stopping the Environment

To stop all services:
```bash
docker compose down
```

To stop and remove all data:
```bash
docker compose down -v
```

## Part 1: Network Reconnaissance

### Task 1.1: Develop a Port Scanner (20 points)

Create a custom port scanning tool that can:

**Minimum Requirements:**
- Accept target IP/hostname and port range as arguments
- Perform TCP connect scans to detect open ports
- Display results showing port number, state (open/closed), and timing
- Handle errors gracefully (timeouts, connection refused, etc.)
- Service/banner detection - Identify what service is running on each port

**Advanced Features (bonus points):**
- Multi-threading for faster scans
- Scan multiple hosts
- Output formats (JSON, CSV, formatted text)
- Stealth/timing options
- etc...

**Starter Template:**

A basic port scanner template is provided in `port_scanner/main.py`. However, we encourage you to try implementing it from scratch first!

**Example Usage:**
```bash
python3 -m port_scanner --target 172.20.0.0/24 --ports 1-10000
python3 -m port_scanner --target webapp --ports 1-65535 --threads 100
```

**Hints:**
- Use Python's `socket` module for TCP connections
- The Docker network uses the subnet `172.20.0.0/16`
- Consider using `threading` or `concurrent.futures` for parallel scanning
- Read the first few bytes after connecting to get service banners

### Task 1.2: Discover Hidden Services (10 points)

Use your port scanner to discover ALL services running in the Docker environment.

**Known Services:**
- Web Application (Flask) - Port 5001 (publicly exposed)
- MySQL Database - Port 3306 (internal only)

**Hidden Services (you must discover these):**
There are **at least 3 additional services** running on non-standard ports. Your task is to find them all.

**Deliverable:**
Add a section in your report listing all discovered services with:
- Port number
- Service type/name
- Any banner or version information
- Which flag (if any) is associated with this service

**Hints:**
- Scan a wide range of ports (at least 1-10000)
- Some services might be on high ports (above 10000)
- Try connecting to open ports and reading their banner/response
- Use your browser or `curl` for HTTP-based services
- Use `nc` (netcat) or `telnet` for other services

### Task 1.3: Capture Flags 1 and 2 (10 points)

- **Flag 1**: Can be found by discovering and accessing one of the hidden services
- **Flag 2**: Requires interacting with a discovered service (may need credentials or specific requests)

**Flag Format:** All flags follow the format `FLAG{...}`

## Part 2: Man-in-the-Middle (MITM) Attack

### Background

The web application communicates with a MySQL database to fetch and display user information. Investigate whether this communication is properly secured.

### Task 2.1: Network Traffic Analysis (15 points)

**Objective:** Intercept and analyze network traffic between the web application and database.

**Steps:**

1. **Identify the Docker network:**
   ```bash
   docker network ls
   docker network inspect 2_network_vulnerable_network
   ```

2. **Capture traffic using tcpdump:**
   ```bash
   # Get container IPs
   docker inspect 2_network_webapp | grep IPAddress
   docker inspect 2_network_database | grep IPAddress
   
   # Capture traffic on the Docker bridge
   sudo tcpdump -i br-<network_id> -A -s 0 'port 3306'
   ```

   Alternatively, use Wireshark with a display filter: `tcp.port == 3306`

3. **Generate traffic:**
   - Access the web application at `http://localhost:5001`
   - Click through different pages to trigger database queries
   - Look for SQL queries and responses in the captured packets

4. **Analyze the traffic:**
   - Is the database communication encrypted?
   - Can you see SQL queries in plain text?
   - Can you extract sensitive data from the packets?

**Alternative Approach:**

Write a Python script using `scapy` to sniff and analyze packets:

```python
from scapy.all import sniff, TCP

def packet_handler(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 3306:
        # Analyze MySQL traffic
        pass

sniff(filter="tcp port 3306", prn=packet_handler)
```

**Deliverable:**
- Use the starter template in `mitm/`
- Captured packet dumps or intercepted data (store them in `mitm/`)
- Explanation of the vulnerability and its impact

### Task 2.2: Capture Flag 3 (15 points)

**Objective:** Use the data obtained from your MITM attack to capture Flag 3.

**Hints:**
- Flag 1 is not just a flag - it serves a purpose in this assignment
- One of the discovered services requires authentication
- The authentication token might be transmitted over the unencrypted database connection
- Pay attention to ALL data being transmitted, not just user credentials

## Part 3: Security Fixes

Now that you've exploited the vulnerabilities, it's time to fix them!

### Fix 1: Port Knocking (15 points)

**Objective:** Implement a port knocking system to protect one of the hidden services.

**Starter Template:**

A basic port knocking starter template is provided in `port_knocking/` with a server, client, Dockerfile, and demo script scaffold.

**What is Port Knocking?**

Port knocking is a security technique where a port is kept closed by a firewall until a client sends a specific sequence of connection attempts to predefined ports. Only after the correct "knock sequence" is received does the firewall open the protected port.

**Requirements:**

Your implementation must:
1. **Choose a service to protect** (e.g., the SSH server on port 2222)
2. **Define a knock sequence** - A series of ports that must be "knocked" in order (e.g., 1234, 5678, 9012)
3. **Implement the server-side**:
   - Monitor for incoming connections on the knock ports
   - Verify the sequence is correct
   - Dynamically open the protected port using firewall rules (iptables/nftables)
   - Optional: Add timing constraints (sequence must complete within X seconds)
   - Optional: Reset on incorrect sequence
4. **Implement the client-side**:
   - A script or tool to perform the knock sequence
   - Connect to the protected service after knocking

**Implementation Options:**

- **Option A:** Use existing tools like `knockd` (https://github.com/jvinet/knock)
- **Option B:** Implement from scratch in Python/Bash
- **Option C:** Use iptables `recent` module for stateless implementation

**Deliverable:**

Create a `port_knocking/` directory containing:
- `README.md` - Explanation of your implementation
- `knock_server.py` or `knockd.conf` - Server-side implementation
- `knock_client.py` or `knock_client.sh` - Client to perform knock sequence
- `Dockerfile` - Containerized version of your implementation
- `demo.sh` - Script demonstrating the port knocking in action

**Testing:**
```bash
# Before knocking - should fail
ssh user@target -p 2222

# Perform knock sequence
python3 knock_client.py --target <ip> --sequence 1234,5678,9012

# After knocking - should succeed
ssh user@target -p 2222
```

### Fix 2: Honeypot (15 points)

**Objective:** Deploy a honeypot to detect and log unauthorized access attempts.

**What is a Honeypot?**

A honeypot is a security mechanism that creates a decoy system to attract and detect attackers. It looks like a legitimate service but actually logs all interaction attempts for analysis.

**Requirements:**

Your honeypot must:
1. **Simulate a real service** (e.g., fake SSH server on port 22)
2. **Log all connection attempts** including:
   - Source IP address and port
   - Timestamp
   - Connection duration
   - Any commands or data sent by the attacker
   - Authentication attempts (usernames/passwords)
3. **Be convincing** - Should look like a real service (proper banner, responses)
4. **Not be obvious** - Should not immediately reveal it's a honeypot
5. **Alert on suspicious activity** (optional):
   - Multiple failed login attempts
   - Known attack patterns
   - Connections from blacklisted IPs

**Implementation Options:**

- **SSH Honeypot** - Simulate SSH service, log authentication attempts
- **HTTP Honeypot** - Fake vulnerable web application
- **Multi-protocol Honeypot** - Support multiple services

**Suggested Tools/Libraries:**
- Python `paramiko` for SSH honeypot
- Python `socket` for low-level protocol simulation
- Existing honeypots: `cowrie`, `dionaea` (study their approach)

**Deliverable:**

Use the provided `honeypot/` starter template and update it to include:
- `README.md` - Explanation of your honeypot design
- `honeypot.py` - Main honeypot implementation
- `logger.py` - Logging and alerting functionality (or equivalent)
- `Dockerfile` - Containerized honeypot
- `logs/` - Log output directory (leave empty in your submission)
- `analysis.md` - Analysis of logged attacks (create some test attacks)

**Testing:**
```bash
# Start your honeypot
docker-compose up honeypot

# Simulate attacks (from another terminal)
ssh admin@localhost -p 22
# Try different usernames/passwords
# Try command injection attempts

# View logs
cat honeypot/logs/honeypot.log
```

**Bonus Features:**
- Email/webhook alerts on detection
- Integration with threat intelligence feeds
- Visualization dashboard for logged attacks
- Dynamic response (fake file systems, fake command output)

## Flags Summary

| Flag | Location | How to Obtain |
|------|----------|---------------|
| Flag 1 | Hidden service | Discover service via port scanning and access it |
| Flag 2 | Hidden service | Discover service and authenticate/interact properly |
| Flag 3 | Hidden service | Use information from MITM attack (requires Flag 1) |

All flags follow the format: `FLAG{...}`

## Deliverables

Fork this repository, complete your work in your fork, and submit a report.pdf:

1. A link to your forked repository with your completed work
2. A link to your screen recording with **mic and camera on** demonstrating your work
3. A comprehensive report

## Comprehensive Report Requirements

Your `report.pdf` should include:

### 1. Executive Summary (1 page)
- Brief overview of findings
- Critical vulnerabilities discovered
- Recommended fixes
- Video link

### 2. Part 1: Reconnaissance (1-2 pages)
- Port scanner design and implementation details
- Discovered services and their purposes
- Methodology and tools used
- Video link

### 3. Part 2: MITM Attack (1-2 pages)
- Vulnerability analysis
- Attack methodology
- Captured data analysis
- Real-world impact assessment
- Video link

### 4. Part 3: Security Fixes (1-2 pages)
- **Port Knocking:**
  - Design decisions
  - Implementation details
  - Security analysis
  - Limitations and improvements
  - Video link
- **Honeypot:**
  - Architecture and design
  - Logging mechanisms
  - Detection capabilities
  - Analysis of captured attacks
  - Video link

### 5. Remediation Recommendations (1-2 pages)
- How to fix the MITM vulnerability (TLS/SSL)
- Best practices for service discovery protection
- Network segmentation strategies
- Monitoring and detection recommendations

### 6. Conclusion (1 page)
- Lessons learned
- Skills acquired
- Future work

## Grading Rubric

| Component | Points | Details |
|-----------|--------|---------|
| **Part 1: Reconnaissance** | **40** | |
| Port Scanner Implementation | 20 | Functionality, code quality, features |
| Service Discovery | 10 | All services found and documented |
| Flags 1 & 2 | 10 | Correct flags captured |
| **Part 2: MITM Attack** | **30** | |
| Traffic Analysis | 15 | Proper interception and analysis |
| Flag 3 | 15 | Correct flag and methodology |
| **Part 3: Security Fixes** | **30** | |
| Port Knocking | 15 | Working implementation, documentation |
| Honeypot | 15 | Working honeypot, logging, analysis |
| **Report & Documentation** | **10** | |
| Code Documentation | 5 | Comments, README files |
| Final Report | 5 | Clarity, completeness, professionalism |
| **Bonus** | **+10** | Advanced features, creativity |
| **Total** | **100 (+10)** | |

## Tips for Success

### General Tips
- **Start early** - This assignment requires significant development work
- **Test frequently** - Make sure your tools work before moving on
- **Document as you go** - Take notes and screenshots during your exploration
- **Use version control** - Git is your friend
- **Ask questions** - If you're stuck, reach out to course staff

### Port Scanner Tips
- Start with a simple single-threaded scanner, then optimize
- Test on known services (web app on port 5001) before scanning unknown ports
- Handle socket timeouts appropriately (1-3 seconds is reasonable)
- Be patient - scanning 65535 ports takes time even with threading

### MITM Attack Tips
- Learn how to use `tcpdump` and Wireshark effectively
- Filter traffic to reduce noise: `tcp port 3306`
- Generate consistent traffic by refreshing the web app multiple times
- MySQL protocol is text-based and relatively easy to read
- You might need to run tcpdump with `sudo`

### Port Knocking Tips
- Start simple - get basic sequence detection working first
- Test with `nc` (netcat) before writing a full client: `nc <ip> 1234`
- Use iptables `-L` to verify rules are being created/removed
- Consider using Docker exec to run iptables inside containers
- Time-based constraints add complexity but increase security

### Honeypot Tips
- Study real service banners - copy them exactly
- Log everything, but store securely (don't fill up disk!)
- Test by attacking your own honeypot
- Make it realistic - delay responses, show realistic errors
- Consider legal implications of honeypots in production

## Resources

### Network Security
- **Nmap Documentation**: https://nmap.org/book/
- **Wireshark User Guide**: https://www.wireshark.org/docs/wsug_html_chunked/
- **TCP/IP Illustrated** by W. Richard Stevens

### Port Knocking
- **Port Knocking Introduction**: https://www.portknocking.org/
- **knockd**: https://github.com/jvinet/knock
- **iptables Tutorial**: https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html

### Honeypots
- **Honeypot Research**: https://www.honeynet.org/
- **Cowrie SSH Honeypot**: https://github.com/cowrie/cowrie
- **Paramiko Documentation**: https://www.paramiko.org/

### Python Libraries
- **socket**: https://docs.python.org/3/library/socket.html
- **scapy**: https://scapy.readthedocs.io/
- **paramiko**: https://www.paramiko.org/
- **threading**: https://docs.python.org/3/library/threading.html

## Troubleshooting

### Docker Network Issues
```bash
# List networks
docker network ls

# Inspect network
docker network inspect 2_network_vulnerable_network

# Get container IPs
docker inspect <container_name> | grep IPAddress
```

### Port Scanner Not Finding Services
- Make sure all containers are running: `docker-compose ps`
- Check you're scanning the right IP range
- Increase timeout values
- Try scanning from inside the Docker network:
  ```bash
  docker exec -it 2_network_webapp /bin/bash
  # Install nmap or use your scanner from inside
  ```

### MITM Capture Shows No Traffic
- Verify database connection is active (check web app logs)
- Use the correct network interface: `tcpdump -D` to list interfaces
- Try capturing all traffic first: `sudo tcpdump -i <interface> -w capture.pcap`
- Make sure you're generating traffic (refresh web app)

### Permission Denied on tcpdump
```bash
# Run with sudo
sudo tcpdump -i docker0 port 3306

# Or add user to pcap group (Linux)
sudo usermod -a -G wireshark $USER
# Logout and login again
```

### Port Knocking Not Working
- Check iptables rules: `sudo iptables -L -n -v`
- Verify knock daemon is running: `docker logs <container>`
- Test each knock port individually with netcat
- Check firewall logs: `sudo tail -f /var/log/syslog`

### Honeypot Not Logging
- Check file permissions on log directory
- Verify honeypot is listening: `netstat -tlnp | grep <port>`
- Test connection: `nc localhost <port>`
- Check honeypot logs: `docker logs <honeypot_container>`

## Academic Integrity

⚠️ **Important Notice:**

This assignment contains intentionally vulnerable network configurations for educational purposes only. You must:

1. **Work individually** - Do not share code or solutions
2. **Only test on provided systems** - Do not scan or attack other networks
3. **Respect resource limits** - Don't create excessive network traffic
4. **Follow ethical guidelines** - Use skills responsibly and legally
5. **Report issues** - If you find unintended vulnerabilities, report them to course staff

**Unauthorized network scanning and attacks are illegal. Always obtain explicit permission before testing any system.**

## Ethical Hacking Guidelines

As you complete this assignment, remember:

- **Permission**: Only scan/attack systems you own or have explicit permission to test
- **Scope**: Stay within the defined scope (this Docker environment only)
- **Impact**: Avoid actions that could crash services or corrupt data
- **Disclosure**: Report findings responsibly
- **Learning**: The goal is education, not causing harm

## Support

If you encounter technical issues:

1. Check the Troubleshooting section above
2. Review Docker logs: `docker-compose logs <service_name>`
3. Verify all containers are running: `docker-compose ps`
4. Try rebuilding: `docker-compose down -v && docker-compose up --build`
5. Post on the course discussion board (without sharing solutions)
6. Contact course staff during office hours

For assignment clarifications or questions about requirements, please contact the TA (ali.a@tamu.edu).

---

**Good luck, and happy (ethical) hacking!** 🔐🌐

*Remember: With great power comes great responsibility. Use your skills for good.*
