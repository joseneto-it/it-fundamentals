# TCP vs UDP

> Protocol fundamentals and their critical security implications in cloud environments

---

## 🔄 Understanding Transport Protocols

TCP and UDP are the two primary **transport layer protocols** that govern how data moves across networks. While they both transport data from source to destination, they take fundamentally different approaches that create distinct security characteristics you must understand as a Cloud Security Engineer.

The choice between TCP and UDP is not just about performance - it determines what kinds of attacks your infrastructure is vulnerable to, how you configure security controls, and what you can detect in security monitoring.

```
┌──────────────────────────────────────────┐
│        Application Layer                 │
│    (HTTP, DNS, SSH, Database, etc.)      │
├──────────────────────────────────────────┤
│     Transport Layer                      │
│      ┌──────┐        ┌──────┐           │
│      │ TCP  │        │ UDP  │           │
│      └──────┘        └──────┘           │
│  Reliability          Speed              │
│  Ordering            Simplicity          │
│  Error Checking      Low Overhead        │
├──────────────────────────────────────────┤
│       Network Layer (IP)                 │
│    (Routing, Addressing)                 │
└──────────────────────────────────────────┘
```

Every network service your cloud infrastructure provides uses either TCP or UDP (or sometimes both). Understanding the security implications of each is fundamental to protecting your systems.

---

## 📦 TCP (Transmission Control Protocol)

### Core Characteristics

TCP is a **connection-oriented, reliable** protocol that guarantees data delivery in the correct order. Think of TCP as registered mail with tracking and delivery confirmation - you know it will get there, you know it arrived intact, and you can verify receipt.

✅ **Reliable delivery**: Guarantees all packets arrive, retransmitting lost packets automatically  
✅ **Ordered delivery**: Packets arrive in the exact order they were sent  
✅ **Connection-oriented**: Establishes and maintains a connection between endpoints  
✅ **Error detection**: Checksums verify data integrity  
✅ **Flow control**: Prevents overwhelming the receiver  
✅ **Congestion control**: Adapts to network conditions  
❌ **Higher overhead**: Connection setup and maintenance cost bandwidth and time  
❌ **Slower**: All the reliability mechanisms add latency  

### The Three-Way Handshake

Before any data is transmitted over TCP, a connection must be established through a precise sequence called the three-way handshake. Understanding this process is critical because it is exploited in one of the most common Denial of Service attacks.

```
Client                                  Server
   │                                        │
   │────────── SYN ─────────────────────────>│  1. Client requests connection
   │         (seq=100)                      │     "I want to establish connection"
   │                                        │
   │<────── SYN-ACK ─────────────────────────│  2. Server acknowledges and responds  
   │      (seq=300, ack=101)                │     "I agree, let's connect"
   │                                        │
   │────────── ACK ─────────────────────────>│  3. Client confirms
   │         (ack=301)                      │     "Connection established"
   │                                        │
   │       *** CONNECTION ESTABLISHED ***   │
   │                                        │
   │────── DATA TRANSFER ────────────────────>│  Now actual data can flow
   │<───── ACKNOWLEDGMENTS ───────────────────│  Server confirms receipt
```

Each step serves a purpose:
- **SYN (Synchronize)**: Client proposes connection with an initial sequence number
- **SYN-ACK (Synchronize-Acknowledge)**: Server accepts and sends its own sequence number
- **ACK (Acknowledge)**: Client confirms, connection is ready for data

**Why this matters for security:** This handshake requires the server to allocate memory for the connection state. Attackers exploit this in SYN flood attacks, which we will cover in the security section.

### TCP in Cloud Services

Most critical cloud services use TCP because data integrity is non-negotiable:

| Service | Port | Why TCP? | Security Implication |
|---------|------|----------|---------------------|
| HTTPS | 443 | Cannot lose parts of encrypted data | TLS depends on TCP's reliability |
| SSH | 22 | Commands must arrive complete and in order | Lost packets would corrupt session |
| RDP | 3389 | Screen updates must be reliable | Missing data breaks remote desktop |
| SMTP | 587 | Cannot lose parts of email messages | Email delivery requires guaranteed arrival |
| MySQL | 3306 | Database transactions must be reliable | Corrupted queries cause errors |
| HTTPS APIs | 443 | Cannot lose API request or response data | Application logic breaks with missing data |

---

## ⚡ UDP (User Datagram Protocol)

### Core Characteristics

UDP is a **connectionless, unreliable** protocol that prioritizes speed over guaranteed delivery. Think of UDP as shouting a message across a crowded room - it might get there perfectly, or parts might be lost, but it is fast and requires minimal setup.

✅ **Fast**: No connection setup or teardown overhead  
✅ **Low latency**: No waiting for acknowledgments  
✅ **Simple**: Minimal protocol overhead  
✅ **Efficient for broadcasting**: Can send to multiple recipients simultaneously  
❌ **No delivery guarantee**: Packets can be lost without notification  
❌ **No ordering**: Packets can arrive out of sequence  
❌ **No error correction**: Application must handle missing or corrupted data  
❌ **No congestion control**: Can flood networks if not carefully implemented  

### How UDP Works (or Doesn't)

UDP has no handshake, no connection state, and no acknowledgments:

```
Client                                  Server
   │                                        │
   │──────── UDP Packet 1 ───────────────────>│  Send and forget
   │──────── UDP Packet 2 ───────────────────>│  No confirmation needed
   │──────── UDP Packet 3 ────────X lost     │  Client doesn't know it's lost
   │──────── UDP Packet 4 ───────────────────>│  Keep sending regardless
   │                                        │
   │     No acknowledgments or retries      │
```

The application must handle lost packets if data integrity matters. Many UDP-based applications implement their own reliability mechanisms when needed.

### UDP in Cloud Services

Services that can tolerate some data loss but require low latency use UDP:

| Service | Port | Why UDP? | Security Implication |
|---------|------|----------|---------------------|
| DNS | 53 | Fast queries needed; can retry if lost | Vulnerable to amplification attacks |
| VoIP | various | Real-time audio tolerates drops better than delay | Can be used for DoS via flooding |
| Video streaming | various | A few lost frames better than buffering | Can flood network without throttling |
| Online gaming | various | Current position more important than historical | Requires application-level validation |
| NTP | 123 | Time synchronization needs speed | Amplification attack vector |
| SNMP | 161 | Network monitoring generates high packet volumes | Can leak network topology if exposed |

---

## ⚖️ Security Implications Comparison

Understanding the security characteristics of each protocol helps you defend against protocol-specific attacks and configure controls appropriately.

### Attack Surface Differences

| Aspect | TCP | UDP | Security Impact |
|--------|-----|-----|-----------------|
| **Connection state** | Maintains state | Stateless | TCP vulnerable to state exhaustion; UDP to flooding |
| **Spoofing difficulty** | Hard to spoof (requires sequence matching) | Easy to spoof source IP | UDP commonly used with spoofed sources in attacks |
| **Amplification potential** | Limited (requires valid handshake) | High (can trigger large responses) | UDP dominant in DDoS amplification |
| **Firewall complexity** | Easier (track connections) | Harder (no connection to track) | Stateless firewalls struggle with UDP |
| **Resource consumption** | Higher per connection | Lower per packet | TCP connection exhaustion vs UDP flooding |

---

## 🔐 Cloud Security Relevance

### SYN Flood Attacks (TCP-Specific)

The SYN flood is one of the most common Denial of Service attacks against cloud infrastructure. It exploits TCP's handshake requirement to exhaust server resources.

**How SYN flood works:**

```
Attacker sends thousands of SYN packets from spoofed IP addresses:

Attacker (spoofed IP) ───SYN──> Server
Attacker (spoofed IP) ───SYN──> Server
Attacker (spoofed IP) ───SYN──> Server
... (thousands per second)

Server responds to spoofed addresses:
Server ───SYN-ACK──> Nonexistent IP (no response)
Server ───SYN-ACK──> Nonexistent IP (no response)  
Server ───SYN-ACK──> Nonexistent IP (no response)

Result:
- Server maintains half-open connections waiting for final ACK
- Memory fills with incomplete connection states
- Legitimate connection requests are rejected
- Service becomes unavailable
```

**Defense mechanisms in cloud:**

AWS Shield automatically mitigates SYN floods using techniques like SYN cookies, which allow the server to avoid allocating resources until the full handshake completes. You can configure additional protection through AWS Shield Advanced for larger attacks.

Azure DDoS Protection monitors traffic patterns and absorbs attack traffic before it reaches your resources, using the massive capacity of Azure's network to handle volumetric attacks.

Google Cloud Armor provides protection at the edge, filtering attack traffic before it reaches your instances.

**Security Group configuration cannot defend against SYN floods** because the attack uses valid-looking SYN packets. Defense requires infrastructure-level DDoS protection services.

### UDP Amplification Attacks

UDP's stateless nature and the ability to spoof source IP addresses make it the protocol of choice for amplification attacks, where attackers generate massive traffic volumes to overwhelm targets.

**How UDP amplification works:**

```
Attacker sends small requests with spoofed source IP (victim's IP):

Attacker ──small UDP query──> DNS Server (53 bytes)
           (spoofed source: Victim IP)

DNS Server ──large response──> Victim (3000 bytes)
           (goes to spoofed source)

Amplification factor: 3000/53 = ~56x

Attacker repeats with thousands of DNS servers simultaneously:
- Attacker sends: 1 MB of requests
- Victim receives: 56 MB of responses
- Victim's network is overwhelmed
```

**Common UDP services exploited for amplification:**

- **DNS (port 53)**: Amplification factor up to 100x with large DNS responses
- **NTP (port 123)**: Amplification up to 600x using monlist command (mostly patched now)
- **SNMP (port 161)**: Amplification up to 600x with certain queries
- **Memcached (port 11211)**: Amplification over 50,000x before widespread patching

**Defense strategy:**

Never expose UDP services directly to the internet unless absolutely necessary. If UDP services must be public (like public DNS resolvers), implement rate limiting and response rate limiting to prevent being used as amplifiers. AWS Network Load Balancers do not protect against UDP amplification; you need AWS Shield or application-level controls.

For internal cloud services using UDP, use Security Groups to allow traffic only from specific sources, never 0.0.0.0/0.

### Stateful vs Stateless Firewalls

The difference between TCP and UDP fundamentally affects how you configure cloud network controls.

**AWS Security Groups (Stateful):**

Security Groups track connection state, so they understand that response traffic is associated with initiated connections:

```
Outbound rule: Allow TCP port 443 to 0.0.0.0/0

This automatically allows:
- Outbound: Instance → External API on port 443
- Inbound: External API port 443 → Instance ephemeral port

No explicit inbound rule needed for return traffic.
```

This works well for TCP because connections have clear state. For UDP, which has no connection, Security Groups use heuristics based on recent packet history to determine what is "return traffic."

**AWS Network ACLs (Stateless):**

Network ACLs do not track connection state, so you must explicitly allow both directions:

```
To allow instance to make outbound HTTPS requests:

Outbound rules:
- Allow TCP port 443 to 0.0.0.0/0

Inbound rules:
- Allow TCP ports 1024-65535 from 0.0.0.0/0 (ephemeral ports for return traffic)

Without the inbound rule, responses cannot reach the instance.
```

This affects your security posture because allowing all ephemeral ports inbound is less restrictive than you might prefer, but it is necessary with stateless filtering.

### Protocol-Specific Monitoring

Cloud Security Engineers monitor different things for each protocol:

**For TCP-based services, monitor:**

- Failed connection attempts (might indicate scanning or brute force attacks)
- Connections from unexpected geographic locations
- Unusually high connection rates to specific ports (potential SYN flood)
- Long-lived connections that might indicate data exfiltration
- Connection patterns that suggest lateral movement between instances

**For UDP-based services, monitor:**

- Abnormally high packet rates (potential DDoS flooding)
- Packets from spoofed or unusual source IPs
- Amplification patterns (small queries generating large responses)
- UDP traffic on unexpected ports (might indicate tunneling or backdoors)
- Ratio of inbound to outbound traffic (legitimate services have predictable patterns)

**VPC Flow Logs capture both protocols and record whether packets were accepted or rejected, providing visibility into both attempted and successful communications.**

---

## 💡 Practical Cloud Security Scenarios

### Scenario 1: Database Security Group Configuration

You are deploying a MySQL database (TCP port 3306) in a private subnet. How should you configure the Security Group?

**Correct configuration:**

```
Inbound:
- Type: MySQL/Aurora
  Protocol: TCP
  Port: 3306
  Source: sg-app-tier (application server security group)

Outbound:
- Usually no outbound rules needed for database
- If database needs to reach external services, allow specific destinations only
```

**Why this is secure:** TCP's connection-oriented nature means you can precisely control which sources establish database connections. The stateful Security Group automatically handles return traffic. The application tier security group reference means only instances in that specific group can connect, implementing least privilege.

**What this prevents:**
- Direct internet access to database (no 0.0.0.0/0 source)
- Connections from unexpected sources
- Data exfiltration via database credentials found elsewhere

### Scenario 2: Internal DNS Server

You deploy an internal DNS server (UDP port 53) for service discovery. How should you configure it securely?

**Correct configuration:**

```
Inbound:
- Type: DNS (UDP)
  Protocol: UDP
  Port: 53
  Source: 10.0.0.0/16 (entire VPC CIDR)

Outbound:
- Type: DNS (UDP)
  Protocol: UDP  
  Port: 53
  Destination: 0.0.0.0/0 (needs to query external DNS)
```

**Why special care is needed:** UDP's stateless nature means the Security Group uses heuristics to allow responses. The DNS server must be able to receive queries from any instance in the VPC, but you are limiting it to the VPC CIDR, not the entire internet.

**Additional security controls:**

Implement rate limiting on the DNS server itself to prevent it being used as an amplifier if somehow the Security Group is misconfigured later. Use VPC Flow Logs to monitor for unusual query patterns that might indicate DNS tunneling or exfiltration. Consider using AWS Route 53 Resolver instead of self-managed DNS to leverage AWS's built-in DDoS protection.

### Scenario 3: Detecting Protocol Abuse

You notice unusual traffic patterns in VPC Flow Logs. How do you investigate protocol-specific issues?

**TCP analysis - Looking for port scanning:**

```
Flow log pattern indicating TCP port scan:
Source: 203.0.113.50
Destination: Your instance  
Multiple destination ports: 22, 23, 80, 443, 3306, 3389, etc.
All connections: REJECT (Security Group blocked them)

Response: Verify Security Groups are restrictive, add source IP to NACL deny list if persistent, check GuardDuty alerts.
```

**UDP analysis - Looking for amplification attempt:**

```
Flow log pattern indicating amplification abuse attempt:
Small inbound UDP packets to port 53 (DNS)
Source IPs are spoofed or unusual
Pattern: Many different sources, same packet size

Response: Ensure DNS server has response rate limiting, restrict source IPs if possible, alert DDoS mitigation team if volume increases.
```

---

## 🔑 Key Points for Cloud Security Engineers

Understanding TCP vs UDP is essential for:

1. **Configuring Security Groups and NACLs correctly** - TCP allows more granular control due to connection state, while UDP requires different approaches to security.

2. **Recognizing attack patterns** - SYN floods exploit TCP's handshake, while amplification attacks exploit UDP's stateless nature and spoof-ability.

3. **Implementing appropriate DDoS protection** - TCP and UDP attacks require different mitigation strategies, from SYN cookies for TCP to rate limiting for UDP.

4. **Monitoring security events effectively** - Different protocols generate different patterns in logs and require different analysis techniques.

5. **Troubleshooting connectivity issues** - Understanding whether a service uses TCP or UDP helps you diagnose why security controls might be blocking legitimate traffic.

6. **Making architecture decisions** - Choosing TCP vs UDP for your own services has security implications you must consider.

Remember that protocol choice is not about preference - it is determined by application requirements. Your job is to understand the security characteristics of each protocol and apply appropriate controls. TCP's stateful nature makes it easier to secure but vulnerable to state exhaustion attacks. UDP's speed comes at the cost of being easily spoofed and harder to filter accurately. Defense in depth means implementing controls at multiple layers regardless of which protocol you are protecting.

---

**Next topic:** [Application Protocols](./05-application-protocols.md) - Understanding HTTP, HTTPS, SSH, DNS, and DHCP from a security perspective
