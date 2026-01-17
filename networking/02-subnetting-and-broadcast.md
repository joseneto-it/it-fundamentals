# Subnets and Broadcast

> Network segmentation fundamentals and their role in cloud security design.

---

## What Are Subnets?

Subnets are **logical divisions within a larger network**, used to group resources
into isolated segments with specific access and security characteristics.

In cloud environments, subnetting plays a key role in implementing **security zones**
and reducing the blast radius of potential incidents.

---

## Subnet Analogy

A useful analogy is to think of a network as a building and subnets as secured floors
within that building. Each floor serves a different purpose and has different access
controls.

VPC / Virtual Network
├── Public Subnets (DMZ)
│ ├── Load Balancers
│ └── Bastion Hosts
├── Private Application Subnets
│ └── Application Servers
└── Private Data Subnets
└── Databases

Resources within the same subnet communicate more freely, while traffic between
subnets must pass through defined security controls.

---

## Why Create Subnets?

### Security Isolation

Subnetting enables network segmentation, which helps limit lateral movement.
If a resource in a public-facing subnet is compromised, proper subnet isolation
can prevent direct access to internal systems such as application servers or databases.

Network boundaries between subnets act as control points where routing rules,
Network ACLs, and monitoring can be applied.

---

### Compliance and Data Classification

Many compliance frameworks require network segmentation to separate systems
with different data sensitivity levels.

Examples include:
- PCI-DSS environments isolating cardholder data
- Healthcare systems isolating protected health information (PHI)

Subnet-based isolation is commonly used to support these requirements.

---

## Broadcast Fundamentals

Broadcast traffic is a message sent to all devices within the same broadcast domain,
which typically corresponds to a subnet.

While broadcast traffic is limited in modern cloud environments, understanding
the concept is important for foundational networking knowledge and troubleshooting.

---

### Security Considerations of Broadcast Traffic

Broadcast domains can introduce risks such as:
- ARP spoofing and man-in-the-middle attacks
- Network reconnaissance within a subnet
- Performance degradation due to excessive broadcast traffic

By dividing networks into smaller subnets, broadcast traffic is contained and
its potential impact is reduced.

---

## Practical Cloud Subnet Design

### Three-Tier Architecture Example

A common cloud architecture uses multiple subnets to separate concerns:
VPC: 10.0.0.0/16

Public Subnets:

Load balancers

Bastion hosts

Private Application Subnets:

Application servers

Private Data Subnets:

Databases and sensitive services

Each tier has different security requirements and access rules.

---

## Traffic Flow and Security Controls

Typical traffic flow in a segmented architecture:

- External traffic enters through public-facing components
- Application logic runs in private subnets
- Data storage remains isolated in restricted subnets

Security controls such as Security Groups, Network ACLs, and route tables
enforce these boundaries.

---

## Common Subnet-Related Security Issues

- Placing all resources in a single subnet
- Assigning public IPs to sensitive systems
- Using overly permissive Network ACL rules
- Poor CIDR planning that limits future growth

These issues can increase attack surface and complicate incident containment.

---

## Key Takeaways

Understanding subnets and broadcast concepts helps to:
1. Implement network segmentation
2. Reduce lateral movement
3. Limit blast radius during incidents
4. Support compliance requirements
5. Create clear traffic boundaries for monitoring

Subnet design in cloud environments is not only about IP management,
but about defining security zones with enforced boundaries.

---

**Next topic:** [Network Ports](./03-network-ports.md)


