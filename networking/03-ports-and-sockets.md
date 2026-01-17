# Network Ports

> Understanding service communication channels and their security implications in cloud environments

---

## 🚪 What are Network Ports?

Network ports are **logical communication endpoints** that allow a single device to handle thousands of simultaneous connections while keeping each conversation separate and organized. For a Cloud Security Engineer, ports are not just technical details - they are the primary attack surface that you will spend your career securing and monitoring.

Every exposed port is a potential entry point for attackers. Understanding ports deeply means understanding where your cloud infrastructure is vulnerable and how to protect it.

### Why Ports are Fundamental to Security

When you deploy a server to the cloud, whether it is an EC2 instance, Azure VM, or GCP Compute Engine instance, that server can potentially listen on 65,535 different ports. Each listening port represents a service that can be accessed over the network. Attackers scan these ports constantly, looking for:

- **Open ports that shouldn't be accessible** (misconfiguration)
- **Services running on unexpected ports** (backdoors)
- **Known vulnerabilities** in services listening on standard ports
- **Outdated versions** of services that can be fingerprinted by port behavior

Your job as a Cloud Security Engineer is to ensure that only the necessary ports are open, only to the necessary sources, and only with properly secured services listening on them.

---

## 🔢 How Ports Enable Multiple Services

Imagine you are running a web application on a cloud server at IP address 203.0.113.10. Without ports, that server could only handle one type of connection at a time. But with ports, the same server can simultaneously:

- Accept HTTPS connections on port 443
- Allow SSH administrative access on port 22
- Connect to a database on port 3306
- Send logs to a monitoring service on port 514
- Receive health checks from a load balancer on port 80

Each service "listens" on its designated port, and the operating system routes incoming packets to the correct service based on the destination port number in the packet header.

**Example of port-based routing:**

```
Your laptop opens https://api.example.com

DNS resolves to: 203.0.113.10
Your browser creates connection: YourIP:54321 → 203.0.113.10:443

The server at 203.0.113.10 sees:
- Destination port 443 = route to web server process
- Source port 54321 = use this to send responses back

Meanwhile, an administrator connects via SSH:
AdminIP:49152 → 203.0.113.10:22
- Destination port 22 = route to SSH daemon
- Source port 49152 = use for SSH session responses
```

Both connections to the same IP address remain separate because they use different destination ports.

---

## 📊 Port Categories and Security Implications

The 65,535 available ports are divided into three ranges, each with different security characteristics and implications for cloud infrastructure.

### 1️⃣ Well-Known Ports (0 - 1023)

These ports are **reserved for fundamental internet services** and require administrative privileges to bind to on Unix-like systems. This restriction exists because these ports handle critical services that should only be run by trusted system processes.

**Security significance:** When you see traffic on well-known ports, you know what service should be running. Unexpected behavior on these ports indicates misconfiguration or compromise.

**Critical well-known ports for cloud security:**

| Port | Service | Security Considerations |
|------|---------|------------------------|
| 22 | SSH | **Most attacked port** - Never expose to 0.0.0.0/0. Use key-based auth, not passwords. Monitor failed login attempts. |
| 80 | HTTP | Unencrypted web traffic. Should redirect to 443. Exposing sensitive data over port 80 is a compliance violation. |
| 443 | HTTPS | Encrypted web traffic. Ensure TLS 1.2+ only. Certificate management critical. Monitor for certificate expiration. |
| 3389 | RDP | Windows remote desktop. **Extremely attacked**. Should be behind VPN or bastion host, never public. |
| 25 | SMTP | Email sending. Often abused for spam if misconfigured. Requires authentication in cloud environments. |
| 53 | DNS | Can be exploited for DDoS amplification attacks. Recursive DNS should not be publicly accessible. |

**Common attack pattern:** Attackers scan the entire internet for servers with port 22 or 3389 open to 0.0.0.0/0, then launch brute-force attacks against them. Millions of such scans occur daily.

### 2️⃣ Registered Ports (1024 - 49151)

These ports are used by **specific applications and services** that have registered them with IANA. Applications can bind to these ports without administrative privileges, but their use should still be carefully controlled in production cloud environments.

**Security significance:** These ports often indicate database, application, or middleware services running. Exposing them to the internet is almost always a security mistake.

**Common registered ports in cloud environments:**

| Port | Service | Security Considerations |
|------|---------|------------------------|
| 3306 | MySQL | **Should never be internet-facing**. Belongs in private subnet with access only from application tier. |
| 5432 | PostgreSQL | Same as MySQL - private subnet only. Check for default credentials. |
| 6379 | Redis | **Frequently exploited** when exposed. No built-in authentication by default. Encrypt in transit. |
| 27017 | MongoDB | **Major breach vector**. Must have authentication enabled. Never bind to 0.0.0.0. |
| 8080 | HTTP alt | Often used for development servers accidentally left running in production. |
| 9200 | Elasticsearch | Contains sensitive data. Needs authentication. Should be in private network. |

**Real-world example:** The massive MongoDB ransomware attacks of 2017 occurred because thousands of databases were accessible on port 27017 from any internet IP address, with no authentication required.

### 3️⃣ Dynamic/Ephemeral Ports (49152 - 65535)

These are **temporary ports** assigned by the operating system when an application initiates an outbound connection. The OS chooses an available port from this range for the duration of the connection, then releases it when the connection closes.

**Security significance:** Understanding ephemeral ports is critical for configuring stateful firewalls and security groups correctly. Many security misconfigurations occur because engineers don't understand how return traffic uses ephemeral ports.

**How ephemeral ports work in cloud security:**

```
Your EC2 instance (10.0.1.50) makes HTTPS request to external API:

Outbound connection created:
Source: 10.0.1.50:52341 (ephemeral port assigned by OS)
Destination: 203.0.113.100:443 (HTTPS)

Your Security Group MUST allow:
- Outbound: 10.0.1.50:any → 203.0.113.100:443
- Inbound: 203.0.113.100:443 → 10.0.1.50:52341 (return traffic)

If you block inbound traffic on ephemeral ports, return traffic cannot reach your instance, breaking outbound connections.
```

**AWS Security Groups handle this automatically** (they are stateful), but **Network ACLs are stateless** and require explicit rules for both directions, including ephemeral ports.

---

## 🔐 Cloud Security Relevance

### Security Groups and Port-Based Access Control

In AWS, Azure, and GCP, Security Groups (or Network Security Groups in Azure) are the primary mechanism for controlling port access. Every rule you write references port numbers to determine what traffic to allow or deny.

**Anatomy of a Security Group rule:**

```
Rule: Allow inbound HTTPS from load balancer

Type: HTTPS
Protocol: TCP
Port Range: 443
Source: sg-lb-123456 (security group of load balancer)

Translation: Only HTTPS traffic (port 443) from instances 
in the load balancer security group can reach this instance.
```

### The #1 Cloud Security Misconfiguration

According to numerous cloud security reports, the most common misconfiguration is **exposing unnecessary ports to 0.0.0.0/0** (the entire internet). This happens because:

Engineers copy example configurations without understanding the implications.
Default rules are left in place during testing and forgotten.
Troubleshooting leads to "temporarily" opening ports that remain open permanently.
Insufficient understanding of which ports actually need internet access.

**Critical security principle:** The default should be to deny all inbound traffic, then explicitly allow only what is necessary from the most restrictive source possible.

**Examples of dangerous vs secure configurations:**

```
❌ DANGEROUS - Database exposed to internet:
Protocol: TCP
Port: 3306 (MySQL)
Source: 0.0.0.0/0
Impact: Anyone on the internet can attempt to connect to your database

✅ SECURE - Database accessible only from application tier:
Protocol: TCP  
Port: 3306
Source: 10.0.10.0/24 (application subnet)
Impact: Only application servers can connect to database
```

```
❌ DANGEROUS - SSH from anywhere:
Protocol: TCP
Port: 22
Source: 0.0.0.0/0  
Impact: Every bot on the internet will attack this server

✅ SECURE - SSH from bastion host only:
Protocol: TCP
Port: 22
Source: 10.0.1.50/32 (bastion host IP)
Impact: SSH only possible through hardened, monitored bastion
```

### Port Scanning and Reconnaissance

Attackers use port scanning to map your infrastructure and identify potential attack vectors. Understanding how port scans work helps you defend against them and recognize them in security logs.

**Common scanning techniques:**

**SYN Scan (stealth scan):** Sends TCP SYN packets to ports to see which respond with SYN-ACK (indicating the port is open). This technique is "stealthy" because it doesn't complete the TCP handshake, potentially avoiding detection by simple logging systems.

**Connect Scan:** Completes full TCP connection to each port. More detectable but works through some firewalls that block SYN scans.

**UDP Scan:** Sends UDP packets to discover services like DNS. Slower and less reliable because UDP doesn't provide confirmations like TCP.

**What you will see in VPC Flow Logs when being scanned:**

```
2 123456789012 eni-abc123 203.0.113.50 10.0.1.10 52341 22 6 1 40 1621234567 1621234568 REJECT OK
2 123456789012 eni-abc123 203.0.113.50 10.0.1.10 52342 23 6 1 40 1621234567 1621234568 REJECT OK
2 123456789012 eni-abc123 203.0.113.50 10.0.1.10 52343 80 6 1 40 1621234567 1621234568 ACCEPT OK
2 123456789012 eni-abc123 203.0.113.50 10.0.1.10 52344 443 6 1 40 1621234567 1621234568 ACCEPT OK

Pattern: Sequential source ports, same source IP, different destination ports
Conclusion: Port scan in progress
```

**Defense strategy:** Use AWS GuardDuty, Azure Security Center, or similar services that automatically detect port scanning and alert you. Combined with tight Security Group rules, most scans will simply find closed ports and move on.

### Service Enumeration Through Port Fingerprinting

Once attackers know which ports are open, they attempt to identify the exact service and version running on that port. Many services announce their version in banner messages when you connect.

**Example of service fingerprinting:**

```
$ telnet example.com 22
SSH-2.0-OpenSSH_7.4

Attacker learns:
- SSH is running (expected on port 22)
- Specific version is OpenSSH 7.4
- Can now search for known vulnerabilities in OpenSSH 7.4
```

**Defense:** Modify service banners to not reveal version information, keep services patched to latest versions, and use intrusion detection systems that alert on fingerprinting attempts.

---

## 💡 Practical Cloud Security Scenarios

### Scenario 1: Web Application Security Group Design

You are deploying a three-tier web application. Here is how you should configure port access:

**Load Balancer (Public Subnet):**

```
Inbound:
- Port 443 (HTTPS) from 0.0.0.0/0 - Public access required
- Port 80 (HTTP) from 0.0.0.0/0 - Only to redirect to HTTPS

Outbound:
- Port 443 to application server subnet - Forward HTTPS traffic
- Port 80 to application server subnet - Forward HTTP traffic
```

**Application Servers (Private Subnet):**

```
Inbound:
- Port 443 from load balancer security group only
- Port 80 from load balancer security group only  
- Port 22 from bastion host IP only (for administration)

Outbound:
- Port 443 to 0.0.0.0/0 - For API calls to external services
- Port 3306 to database subnet - MySQL queries
```

**Database (Private Subnet):**

```
Inbound:
- Port 3306 from application server subnet only - MySQL access

Outbound:
- None required for typical database operations
```

Notice how each tier has progressively more restrictive inbound rules, implementing defense in depth through port-based access control.

### Scenario 2: Detecting Unauthorized Services

You are conducting a security audit and discover an EC2 instance is listening on port 8888. This port is not in your approved architecture documentation.

**Investigation steps:**

Check what process is listening on port 8888.
Determine if this is a legitimate service or potential backdoor.
Review how long this port has been accessible and from where.
Check VPC Flow Logs for connections to this port.
Identify who made configuration changes that opened this port.

**Common causes of unexpected ports:**

Developers deployed debugging tools and forgot to remove them.
Misconfigured application is listening on wrong port.
Compromised instance running attacker-installed service.
Legitimate service deployed without following change management process.

**Response:** If unauthorized, immediately block the port in Security Groups, investigate the instance for compromise, and review how the misconfiguration occurred to prevent recurrence.

---

## 🔑 Key Points for Cloud Security Engineers

Understanding network ports enables you to:

1. **Configure Security Groups correctly** by allowing only necessary ports from appropriate sources, implementing least-privilege access at the network layer.

2. **Identify misconfigurations** such as databases exposed to the internet or SSH accessible from anywhere, which are among the most common cloud security vulnerabilities.

3. **Detect reconnaissance activity** by recognizing port scanning patterns in logs and implementing automated alerting for suspicious scanning behavior.

4. **Reduce attack surface** by ensuring services listen only on required ports and closing all unnecessary ports, limiting the avenues attackers have to compromise your infrastructure.

5. **Troubleshoot connectivity issues** by understanding how applications use ports to communicate and how firewalls filter based on port numbers.

6. **Comply with security frameworks** that require documented justification for all publicly accessible ports and regular review of port exposure.

Remember: Every open port is a potential vulnerability. Your role is to ensure that only the minimum necessary ports are accessible, only from appropriate sources, and only with properly secured services behind them. Defense in depth means multiple layers of port-based access control: Network ACLs at the subnet level, Security Groups at the instance level, and host firewalls on the instances themselves.

---

**Next topic:** [TCP vs UDP](./04-tcp-vs-udp.md) - Understanding protocol differences and their security implications
