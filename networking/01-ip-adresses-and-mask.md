# IP Addresses and Network Masks

> Understanding device identification and network organization as a foundation for cloud security concepts.

---

## What is an IP Address?

An IP address is a **logical identifier** assigned to a device connected to a network.
It functions similarly to a postal address, allowing traffic to be routed to the
correct destination.

In cloud environments, IP addressing plays a central role in routing decisions,
resource isolation, and the application of security controls.

---

## IP Structure

An IP address is composed of two logical parts:

| Component | Purpose | Analogy | Cloud Context |
|---------|--------|---------|--------------|
| Network portion | Identifies the network | Street name | VPC or subnet identification |
| Host portion | Identifies the device | House number | Individual instances or services |

Example:
IP address: 192.168.1.10

192.168.1 → Network portion
.10 → Host portion

---

## Network Masks (Subnet Masks)

A network mask defines which portion of an IP address represents the network
and which portion represents the host.

This distinction determines whether traffic is:
- routed locally within the same network, or
- forwarded to a gateway to reach another network.

Example:
IP address: 192.168.1.10
Subnet mask: 255.255.255.0

Network: 192.168.1.0/24
Hosts: 1–254

From a security perspective, subnet boundaries often define **security zones**
and influence how access control rules are applied.

---

## Gateways

A gateway is the network component responsible for forwarding traffic between
different networks.

In cloud platforms, gateways are commonly represented by services such as:
- Internet Gateways
- NAT Gateways
- Virtual Private Gateways

Traffic destined for another network must pass through a gateway, making it
an important control point for enforcing security policies.

---

## IP Classes and Private Address Ranges

Traditional IP classes (A, B, and C) are largely historical and are not used
directly in modern cloud network design. However, they help explain the origin
of common private address ranges.

### Private IP Ranges (RFC 1918)

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

These addresses are not routable on the public internet and are commonly used
to isolate internal cloud resources.

---

## Cloud Context Example (AWS)

When creating a virtual network in AWS, a CIDR block must be defined:

VPC CIDR: 10.0.0.0/16

Subnets:

Public subnet: 10.0.1.0/24

Private subnet: 10.0.10.0/24

Subnet size directly impacts:
- the number of deployable resources
- network segmentation
- the scope of security rules

---

## Common Security Considerations

- Avoid overly broad CIDR ranges in access rules (e.g., `0.0.0.0/0`)
- Limit public IP exposure whenever possible
- Plan CIDR blocks with future growth in mind
- Use network segmentation to reduce attack surface

Misconfigurations related to IP-based access controls have contributed to
several real-world security incidents, highlighting the importance of
understanding these fundamentals.

---

## Key Takeaways

Understanding IP addressing and subnet masks helps to:
- design logically segmented networks
- apply least-privilege access controls
- reduce unintended exposure
- build a solid foundation for cloud and security studies

---

**Next topic:** [Subnets and Broadcast](./02-subnets-broadcast.md)

