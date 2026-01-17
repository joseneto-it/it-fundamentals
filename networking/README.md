# Networking Fundamentals

> Building a solid networking foundation with a focus on cloud security concepts.

---

## Why Networking Matters for Cloud Security

Networking fundamentals are essential for anyone aiming to work with cloud security.
Cloud environments are built on **virtual networks**, and securing them requires a
clear understanding of how network communication works.

Security groups, firewall rules, routing tables, and network segmentation all rely
on core networking concepts such as IP addressing, ports, protocols, and traffic flow.
Many cloud security incidents originate from misunderstandings of these fundamentals.

This section documents my study of networking concepts and how they relate to
security considerations in cloud environments.

---

## Topics Covered

### 1. IP Addressing and Network Masks
Understanding how devices are identified and grouped within a network.

**Security-focused context:**
- Private vs public IP addressing
- CIDR blocks in cloud virtual networks
- Source and destination rules in security controls

---

### 2. Subnets and Broadcast
Network segmentation and traffic isolation concepts.

**Security-focused context:**
- Public and private subnet design
- Network isolation and segmentation
- Limiting lateral movement within networks

---

### 3. Network Ports
How services communicate through ports and why port exposure matters.

**Security-focused context:**
- Identifying exposed services
- Reducing attack surface
- Port-based access control

---

### 4. Transport Protocols (TCP and UDP)
Differences between TCP and UDP and their impact on communication.

**Security-focused context:**
- Stateful vs stateless connections
- Common attack patterns related to transport protocols
- Protocol-aware security controls

---

### 5. Application Layer Protocols
How applications exchange data over the network.

**Security-focused context:**
- HTTP and HTTPS communication
- DNS resolution and common risks
- Secure remote access using SSH
- Encrypting data in transit

---

### 6. NAT and Firewall Basics
Traffic control and address translation mechanisms.

**Security-focused context:**
- Controlling inbound and outbound traffic
- Egress filtering concepts
- Defense-in-depth at the network level

---

## Scope

This documentation focuses on **foundational networking concepts**.
Advanced topics such as routing protocols, enterprise firewalls, and deep packet
inspection are intentionally left for later stages.

---

## Learning Goal

The goal of this section is to build a strong mental model of how networks operate,
serving as a foundation for future hands-on labs, cloud studies, and security-focused
projects.
