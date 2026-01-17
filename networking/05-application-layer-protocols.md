# Application Protocols

> Understanding how applications communicate and the security vulnerabilities inherent in each protocol

---

## Overview: Why Application Protocols Matter for Cloud Security

Application layer protocols define how software applications exchange data over networks. While lower layers like TCP and IP handle the mechanics of data transport, application protocols determine what is being communicated and in what format. For a Cloud Security Engineer, understanding these protocols is critical because vulnerabilities at this layer cause the majority of cloud security incidents.

When you hear about data breaches, they almost always involve exploitation of application layer weaknesses: unencrypted HTTP exposing credentials, misconfigured HTTPS certificates allowing man-in-the-middle attacks, weak SSH authentication permitting unauthorized access, DNS hijacking redirecting traffic to malicious sites, or DHCP spoofing attacks positioning attackers as network intermediaries.

Your responsibility is to ensure that every application protocol in use across your cloud infrastructure is configured securely, uses modern encryption where appropriate, and has monitoring in place to detect abuse.

---

## 🌐 HTTP (HyperText Transfer Protocol)

### What is HTTP?

HTTP is the foundation of data communication on the World Wide Web. It is a **request-response protocol** where clients request resources and servers respond with the requested data. Originally designed in an era when the internet was a trusted academic network, HTTP provides zero security features, making it fundamentally unsuitable for any sensitive communication in modern cloud environments.

### Technical Characteristics

- **Port:** 80 (TCP)
- **Transport protocol:** TCP (requires reliable delivery)
- **Security:** ❌ None - all data transmitted in plaintext
- **State:** Stateless (each request is independent)
- **Modern use case:** Should only redirect to HTTPS or serve purely public content with no sensitive data

### The Security Problem

Every byte of data transmitted over HTTP is visible to anyone who can intercept the network traffic. This includes:

**Credentials transmitted in clear text:**

```
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=jose@example.com&password=SecurePassword123

↑ This travels across the network readable by anyone
```

Any device between the client and server can read this: your ISP, your employer's network monitoring tools, coffee shop WiFi operators, or attackers performing man-in-the-middle attacks.

**Session cookies exposed:**

```
GET /account HTTP/1.1
Host: example.com
Cookie: session_id=abc123xyz

↑ Session identifier visible, allowing session hijacking
```

An attacker who captures this cookie can impersonate the user without knowing their password.

**Form data leaked:**

```
POST /api/payment HTTP/1.1
Host: example.com

{"card_number":"4532123456789012","cvv":"123","amount":"500"}

↑ Payment card data transmitted unencrypted = PCI-DSS violation
```

Transmitting payment card data over HTTP is a compliance violation under PCI-DSS and immediately puts you in breach of regulatory requirements.

### Cloud Security Implications

**Compliance violations:** PCI-DSS, HIPAA, GDPR, and virtually every security framework require encryption of sensitive data in transit. Using HTTP for anything beyond public marketing pages violates these requirements.

**Corporate network monitoring:** Remember that in cloud environments, traffic often traverses corporate networks, cloud provider networks, and internet backbones. Every hop is an opportunity for interception.

**Testing environment mistakes:** Developers often use HTTP in testing environments, then forget to configure HTTPS before deploying to production. This is one of the most common security misconfigurations in cloud deployments.

### Secure Configuration

The only acceptable use of HTTP in modern cloud infrastructure:

```
HTTP on port 80 should ONLY redirect to HTTPS:

Server configuration (Apache/Nginx):
- Receive request on port 80
- Return HTTP 301 redirect to https:// equivalent
- Never serve sensitive content over port 80

Load Balancer configuration (AWS ALB):
- Listener on port 80: Redirect to port 443
- No direct backend connections from port 80
```

**Security Group rules should reflect this:**

```
Load Balancer Security Group:
Inbound:
- Port 80 from 0.0.0.0/0 (ONLY for redirect, not serving content)
- Port 443 from 0.0.0.0/0 (actual traffic serves here)
```

**Monitoring requirement:** Use AWS Config rules or Azure Policy to detect and alert on any resources serving content over HTTP without redirecting to HTTPS.

---

## 🔒 HTTPS (HTTP Secure)

### What is HTTPS?

HTTPS is HTTP wrapped inside a TLS (Transport Layer Security) encrypted tunnel. It provides the security guarantees that HTTP lacks: confidentiality, integrity, and authentication. Every modern web application in cloud environments must use HTTPS exclusively for any data that should not be public.

### Technical Characteristics

- **Port:** 443 (TCP)
- **Transport protocol:** TCP
- **Security:** ✅ Strong encryption via TLS 1.2+ (older versions deprecated due to vulnerabilities)
- **State:** Stateless at HTTP layer, but TLS session can be resumed for performance
- **Modern use case:** The only acceptable protocol for web applications handling any sensitive data

### How HTTPS Protects Data

HTTPS is the combination of HTTP and TLS (or its predecessor SSL, which is now deprecated):

```
HTTPS = HTTP + TLS

TLS provides:
1. Encryption: Data is scrambled so eavesdroppers see gibberish
2. Integrity: Tampering with data is detectable
3. Authentication: You are connected to the real server, not an imposter
```

**What encrypted traffic looks like:**

```
Plaintext (what application sends):
username=jose@example.com&password=SecurePassword123

Encrypted in transit (what eavesdropper sees):
b4:28:9f:c3:11:7a:5d:8e:f2:a1:0b:7c:3e:91:2f:4d
8a:62:d3:c5:11:ae:9f:23:7b:81:c4:f0:3a:5e:6d:92
...completely unreadable without decryption key
```

### TLS/SSL Certificate Management

HTTPS depends on digital certificates that prove server identity. Mismanagement of certificates is a common source of security issues in cloud environments.

**Certificate components:**

| Component | Purpose | Security Implication |
|-----------|---------|---------------------|
| **Public key** | Encrypts data sent to server | If compromised with private key, all past sessions can be decrypted |
| **Private key** | Decrypts data, proves identity | **Must be kept secret** - compromise means impersonation is possible |
| **Certificate Authority signature** | Proves certificate legitimacy | Browsers trust pre-approved CAs to verify server identity |
| **Validity period** | Time window certificate is valid | Expired certificates cause browser warnings and broken connections |
| **Domain name** | Which domains certificate is valid for | Mismatch causes browser warnings (potential MITM attack) |

**Common certificate mistakes in cloud:**

**Mistake 1: Using self-signed certificates in production**

```
❌ Bad: Self-signed certificate
- Browsers show warnings to users
- Users trained to click through warnings (security culture erosion)
- No validation of actual server identity
- Vulnerable to man-in-the-middle attacks

✅ Good: Certificate from trusted CA (Let's Encrypt, AWS ACM, DigiCert)
- Browsers trust automatically
- Users see padlock without warnings
- Identity validated by third party
- Free options available (Let's Encrypt, AWS Certificate Manager)
```

**Mistake 2: Letting certificates expire**

```
Impact of expired certificate:
- Website becomes inaccessible (browsers block connection)
- Revenue loss for e-commerce
- Brand damage and user distrust
- Potential security incident if attackers exploit the downtime

Prevention:
- Use AWS Certificate Manager (auto-renews)
- Set up expiration alerts 60, 30, 7 days before expiry
- Automate renewal with Let's Encrypt/certbot
- Monitor certificate validity in security dashboard
```

**Mistake 3: Weak TLS configuration**

```
❌ Dangerous: Allowing old TLS versions
- TLS 1.0 and 1.1 have known vulnerabilities (BEAST, POODLE)
- SSL 3.0 and earlier completely broken

✅ Secure: Enforce TLS 1.2+ only
- AWS ALB: Set security policy to TLS-1-2-only or higher
- Nginx: ssl_protocols TLSv1.2 TLSv1.3;
- Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
```

### Cloud-Specific HTTPS Implementation

**AWS Certificate Manager (ACM):**

Free SSL/TLS certificates that automatically renew. Best practice for AWS-hosted applications.

```
Benefits:
- No cost
- Automatic renewal (no expiration incidents)
- Integrated with ALB, CloudFront, API Gateway
- Private key never exposed (managed by AWS)

Limitations:
- Certificates cannot be exported (tied to AWS services)
- Only valid for resources in AWS
```

**Application Load Balancer HTTPS:**

```
Secure configuration:
1. Upload/create certificate in ACM
2. Configure ALB listener on port 443
3. Attach certificate to listener
4. Select security policy (TLS-1-2-only minimum)
5. Configure HTTP→HTTPS redirect on port 80 listener
6. Backend connections can be HTTP (traffic stays in AWS network)
```

**Why you can use HTTP from load balancer to backend instances:** Traffic between ALB and EC2 instances travels on AWS's internal network, which is isolated from the internet. The encryption provided by HTTPS is primarily to protect data crossing untrusted networks (the internet). However, some compliance frameworks require end-to-end encryption, in which case you should use HTTPS for backend connections too.

### Monitoring and Detection

As a Cloud Security Engineer, you will monitor for:

**Certificate expiration approaching** using AWS Config, CloudWatch, or third-party certificate monitoring services.

**Weak TLS versions accepted** by scanning endpoints with SSL Labs or automated tools and alerting on anything accepting TLS 1.0/1.1.

**Mixed content warnings** where HTTPS pages load HTTP resources, degrading the security to HTTP level.

**Certificate mismatches** where certificate domain does not match the actual domain being accessed (potential MITM attack or misconfiguration).

---

## 🔐 SSH (Secure Shell)

### What is SSH?

SSH is the standard protocol for secure remote administration of servers. In cloud environments, SSH is how you access EC2 instances, manage containers, deploy applications, troubleshoot issues, and perform any task requiring command-line access to remote systems. Given its power (full server control) and ubiquity, SSH security is critical.

### Technical Characteristics

- **Port:** 22 (TCP)
- **Transport protocol:** TCP
- **Security:** ✅ Strong encryption for commands, responses, and authentication
- **Authentication:** Key-based (recommended) or password-based (not recommended)
- **Use case:** Remote server administration, secure file transfers (SCP/SFTP), tunneling

### Why SSH Security Is Critical

SSH provides complete control over a server. An attacker who gains SSH access can:

- Read all files on the system including application code, configuration files, and data
- Modify system configurations to create backdoors ensuring persistent access
- Install malware, cryptocurrency miners, or use the server for attacking others
- Pivot to other systems on the internal network (lateral movement)
- Exfiltrate sensitive data
- Destroy evidence and logs to cover their tracks

**Real-world impact:** SSH is one of the most frequently brute-forced services on the internet. Automated bots constantly scan for port 22 and attempt common username/password combinations. Weak SSH security is a primary entry point in cloud breaches.

### SSH vs TELNET (Legacy Protocol)

TELNET was the predecessor to SSH and is now considered completely insecure:

| Aspect | SSH | TELNET |
|--------|-----|--------|
| **Encryption** | ✅ All traffic encrypted | ❌ Everything in plaintext |
| **Port** | 22 | 23 |
| **Authentication** | Keys or passwords (encrypted) | Passwords (sent in clear text) |
| **Current status** | Industry standard | Obsolete, security hazard |
| **Use case** | Production server access | Never use in production |

If you find port 23 (TELNET) open on any cloud instance, it should be considered a critical security finding requiring immediate remediation.

### Secure SSH Configuration for Cloud

**Never expose SSH to the entire internet:**

```
❌ DANGEROUS Security Group rule:
Type: SSH
Protocol: TCP
Port: 22
Source: 0.0.0.0/0

Impact: Every bot on the internet attacks this server
- Thousands of brute-force attempts daily
- Password-based auth will eventually be compromised
- Even with keys, flood of attempts fills logs and wastes resources

✅ SECURE Security Group rule:
Type: SSH
Protocol: TCP
Port: 22
Source: Bastion host security group

Why this is better:
- SSH only accessible from hardened bastion host
- Bastion has additional monitoring and access controls
- Centralized audit point for all SSH access
- Significantly reduced attack surface
```

**Use SSH key-based authentication exclusively:**

```
Password authentication weaknesses:
- Users choose weak passwords
- Passwords are brute-forceable given enough attempts
- Passwords can be phished or socially engineered
- No way to audit which key was used for which session

SSH key authentication benefits:
- Cryptographically strong (2048-bit or 4096-bit keys)
- Cannot be brute-forced in practical timeframes
- Can be individually revoked if compromised
- Each user has unique key for audit trail
- Can enforce MFA with SSH keys (AWS Session Manager)
```

**Hardening the SSH daemon configuration:**

```bash
/etc/ssh/sshd_config secure settings:

# Disable password authentication
PasswordAuthentication no
ChallengeResponseAuthentication no

# Disable root login (use sudo instead)
PermitRootLogin no

# Only allow specific users
AllowUsers admin-user deploy-user

# Use modern SSH protocol version only
Protocol 2

# Set idle timeout to disconnect inactive sessions
ClientAliveInterval 300
ClientAliveCountMax 2

# Limit authentication attempts
MaxAuthTries 3

# Disable empty passwords
PermitEmptyPasswords no
```

These settings dramatically reduce the attack surface and align with CIS benchmarks for SSH hardening.

### Bastion Host Architecture

The recommended pattern for SSH access in cloud environments:

```
Internet → Bastion Host (hardened) → Private Instances

Bastion Host characteristics:
- Minimal software installed (reduces vulnerabilities)
- In public subnet with elastic IP (static address for allow-listing)
- Enhanced logging to CloudWatch/SIEM
- MFA required for bastion access
- Intrusion detection monitoring (GuardDuty, CloudWatch agent)
- Regular security patching enforced
- Immutable infrastructure (replaced rather than modified)

Private instances:
- In private subnet with no internet gateway
- Security Groups allow SSH only from bastion security group
- No public IPs assigned
- Cannot be reached from internet even if credentials are compromised

Access flow:
1. Administrator connects to bastion via SSH with MFA
2. From bastion, connects to private instance
3. All connections logged and auditable
4. Bastion can be shut down when not in use for maximum security
```

**Modern alternative:** AWS Systems Manager Session Manager provides SSH-like access without requiring port 22 to be open at all, eliminating the SSH attack surface entirely while providing centralized logging.

### What Cloud Security Engineers Monitor

**Failed SSH authentication attempts:** Spikes indicate brute-force attack in progress. Normal rate is zero or near-zero failed attempts.

**SSH connections from unexpected geographic locations:** If your team is in Brazil and SSH connection originates from China, investigate immediately.

**SSH key usage patterns:** Same key used from multiple locations simultaneously, or key used after employee departure, indicates compromise.

**Configuration drift:** Alerting when SSH daemon configuration changes from hardened baseline (someone manually enabling password auth, for example).

**Privileged escalation after SSH:** Monitoring for rapid sudo usage or privilege escalation attempts following SSH login.

---

## 🗂️ DNS (Domain Name System)

### What is DNS?

DNS is the internet's phone book, translating human-readable domain names (like www.example.com) into machine-readable IP addresses (like 203.0.113.10). While users rarely think about DNS, it is critical infrastructure that, when compromised, can redirect all traffic to attacker-controlled servers without users noticing.

### Technical Characteristics

- **Port:** 53 (primarily UDP, sometimes TCP for large responses)
- **Transport protocol:** UDP for speed (queries must be fast), TCP for zone transfers
- **Security:** ❌ Traditional DNS has no built-in security (DNSSEC adds validation)
- **Caching:** Responses cached at multiple levels for performance
- **Use case:** Every internet connection starts with DNS

### Why DNS Security Matters

DNS operates on trust. When your browser queries DNS for www.bank.com, it trusts that the response is accurate. If an attacker can manipulate DNS, they can:

**DNS spoofing/poisoning:** Respond to DNS queries with false information, redirecting users to phishing sites that look identical to legitimate sites.

**DNS hijacking:** Take control of domain registrations or DNS servers to persistently redirect traffic.

**DNS tunneling:** Use DNS queries and responses to exfiltrate data from compromised networks, bypassing firewalls that allow DNS.

**DNS amplification attacks:** Exploit open DNS resolvers to amplify attack traffic in DDoS attacks.

### How DNS Works

```
Example: User browses to www.example.com

1. Browser checks local DNS cache
   - If found: use cached IP, skip next steps
   - If not found: continue

2. Query local DNS resolver (often ISP-provided)
   - "What is the IP for www.example.com?"

3. Resolver checks its cache
   - If cached: return IP address
   - If not cached: perform recursive query

4. Recursive DNS query:
   Root server: "Ask .com server"
   .com server: "Ask example.com authoritative server"
   example.com server: "IP is 203.0.113.10"

5. Resolver caches result (TTL determines how long)

6. Resolver returns IP to browser: 203.0.113.10

7. Browser connects to 203.0.113.10 port 443 (HTTPS)

Total time: 20-100ms for uncached, <1ms for cached
```

### DNS in Cloud Environments

**AWS Route 53:** Managed DNS service that provides authoritative DNS for your domains and acts as resolver for VPC resources.

**Azure DNS:** Similar managed service for Azure environments.

**Benefits of managed DNS services:**

- Built-in DDoS protection (AWS Shield, Azure DDoS Protection)
- High availability across multiple availability zones
- Integrated with other cloud services (load balancers, S3, CloudFront)
- Health checks and automatic failover
- Lower risk of misconfiguration compared to self-managed DNS

### DNS Security Vulnerabilities and Mitigations

**Vulnerability 1: Open DNS Resolvers**

```
Problem:
DNS server configured to answer queries from anyone
→ Used in amplification attacks
→ Allows attackers to map your infrastructure

Secure configuration:
DNS resolver should only answer queries from:
- Resources within your VPC (10.0.0.0/16)
- Explicitly authorized external IPs (office, VPN)
Never from 0.0.0.0/0

AWS Route 53 Resolver:
- Automatically scoped to VPC
- Not publicly accessible
- No amplification risk
```

**Vulnerability 2: DNS Cache Poisoning**

```
Attack:
Attacker sends fake DNS responses
→ If accepted, wrong IP cached
→ All subsequent requests go to attacker's server

Mitigation:
- Use DNSSEC (validates responses with cryptographic signatures)
- Randomize source ports for queries (harder to spoof)
- Use DNS over HTTPS (DoH) or DNS over TLS (DoT)
- Monitor for unusual DNS response patterns
```

**Vulnerability 3: DNS Tunneling for Data Exfiltration**

```
Attack technique:
Compromised server encodes data in DNS queries:
- Normal query: www.example.com
- Tunneled data: x3j8s9d2k1.example.com
- Attacker's DNS server extracts encoded data from query

Why it works:
- DNS usually allowed outbound through firewalls
- Blends with legitimate traffic
- Can exfiltrate data slowly to avoid detection

Detection:
- Monitor DNS query lengths (tunneled queries are longer)
- Alert on high volume of queries to single domain
- Analyze query randomness (tunneled queries look random)
- Use AWS GuardDuty (detects DNS exfiltration patterns)
```

### What Cloud Security Engineers Monitor

**Unusual DNS query patterns:** Sudden spike in queries to unknown domains, very long queries, or high entropy in domain names.

**DNS queries to known malicious domains:** Using threat intelligence feeds to block known bad actors.

**DNS response times:** Degradation might indicate DDoS or infrastructure issues.

**DNSSEC validation failures:** Indicates potential poisoning attempt or misconfiguration.

**DNS queries from unexpected sources:** Instance making DNS queries it should not need to make suggests compromise.

---

## 📮 DHCP (Dynamic Host Configuration Protocol)

### What is DHCP?

DHCP automatically assigns IP addresses and network configuration to devices joining a network. In traditional networks, DHCP is essential for usability. In cloud environments, DHCP is typically abstracted by the cloud provider (AWS VPC, Azure Virtual Network), but understanding how it works is important for troubleshooting and recognizing attacks.

### The DORA Process

DHCP follows a four-step negotiation called DORA:

```
D - Discover: Client broadcasts "Any DHCP server, I need configuration"
O - Offer: Server broadcasts "Here's an available IP and config"
R - Request: Client broadcasts "I accept that offer"
A - Acknowledge: Server confirms and marks IP as leased

Example:
Client: "DHCP DISCOVER - broadcast to 255.255.255.255"
Server: "DHCP OFFER - I have 192.168.1.50 for you"
Client: "DHCP REQUEST - I accept 192.168.1.50"
Server: "DHCP ACK - Confirmed, here's your full config:
         IP: 192.168.1.50/24
         Subnet: 255.255.255.0
         Gateway: 192.168.1.1
         DNS: 8.8.8.8"
```

### Security Vulnerabilities in DHCP

**DHCP Spoofing Attack:**

```
Attack scenario:
Attacker sets up rogue DHCP server on network
→ Responds faster than legitimate DHCP server
→ Provides malicious configuration to clients

Malicious configuration provided:
IP address: 192.168.1.100 (legitimate)
Gateway: 192.168.1.99 (attacker's machine)
DNS: 192.168.1.99 (attacker's DNS server)

Result:
- All client traffic routes through attacker (man-in-the-middle)
- DNS queries go to attacker's server (can redirect to phishing sites)
- Attacker intercepts all traffic before forwarding to real gateway

Mitigation:
- DHCP snooping on switches (only authorized DHCP servers allowed)
- In cloud: Use VPC DHCP options, not self-managed DHCP
- Monitor for multiple DHCP servers on same network segment
```

**DHCP Starvation Attack:**

```
Attack:
Attacker requests all available IP addresses
→ DHCP server has no more IPs to give
→ Legitimate devices cannot join network

How it works:
for each available IP:
  send DHCP request with unique MAC address
  DHCP server marks IP as leased
  
Eventually:
  No IPs left in pool
  Legitimate users get "no IP address available" error
  Denial of service complete

Mitigation:
- Rate limiting on DHCP server
- MAC address filtering (though MAC can be spoofed)
- Increase DHCP pool size
- Monitor DHCP lease exhaustion
```

### DHCP in Cloud Environments

**AWS VPC DHCP:**

AWS automatically provides DHCP services within VPCs. When you launch an instance, it receives network configuration via DHCP without you managing a DHCP server.

```
Configuration provided by AWS DHCP:
- Private IP from subnet CIDR range
- VPC DNS server (Route 53 Resolver)
- Domain name for instance
- NTP servers for time synchronization

You can customize via DHCP Options Sets:
- Custom DNS servers (for hybrid cloud scenarios)
- Custom domain name
- Custom NTP servers
```

**Why cloud DHCP is more secure than traditional:**

No rogue DHCP server risk - AWS infrastructure prevents unauthorized DHCP servers. No IP exhaustion attacks - VPC subnets have dedicated IP ranges. Consistent configuration - All instances get proper settings automatically. No manual DHCP server management - Reduces configuration errors.

### What Cloud Security Engineers Monitor

While DHCP is largely handled by cloud providers, you should still monitor:

**DHCP option sets changes** to ensure no one modified DNS servers to malicious resolvers.

**Instances with static IPs** that bypass DHCP, which might indicate manual misconfig or attacker trying to evade monitoring.

**IP address exhaustion** in subnets, which might indicate legitimate growth or attack.

---

## 🔑 Key Points for Cloud Security Engineers

Understanding application protocols gives you the knowledge to:

1. **Never use HTTP for sensitive data** - Always HTTPS, with proper certificate management and TLS 1.2+ enforcement.

2. **Secure SSH access properly** - Bastion hosts, key-based auth only, restrictive Security Groups, modern alternatives like AWS Systems Manager.

3. **Protect DNS infrastructure** - Use managed services, prevent amplification attacks, monitor for tunneling, implement DNSSEC where possible.

4. **Understand DHCP attack vectors** - While abstracted in cloud, recognize spoofing and starvation attacks in hybrid environments.

5. **Monitor protocol abuse** - Each protocol has specific attack patterns that you must recognize in logs and alerts.

6. **Enforce encryption** - Every protocol that supports encryption (HTTPS vs HTTP, SSH vs TELNET) must use it exclusively.

Remember that application layer security is where most breaches occur. Securing these protocols correctly prevents the vast majority of common cloud security incidents. Your understanding of how they work, how they are attacked, and how to defend them is fundamental to your career as a Cloud Security Engineer.

---

**Next topic:** [NAT and Firewall](./06-nat-firewall.md) - Network address translation and traffic filtering from a security perspective
