# IT Fundamentals Glossary

This glossary provides clear and concise definitions of fundamental
terms used throughout the **IT Fundamentals** repository.

The goal is to establish consistent terminology and solid mental models
for operating systems, networking, and cloud-related concepts, serving
as a reference during study and future hands-on practice.

This glossary focuses on **foundational concepts**, intentionally
avoiding deep implementation details.

---

## A

### Application
A software program designed to perform a specific task for a user.
Applications run on top of an operating system, which provides access
to hardware resources.

---

## B

### Boot Process
The sequence of steps a computer follows to initialize hardware,
load the operating system kernel, and start system services.

---

## C

### CIDR (Classless Inter-Domain Routing)
A notation used to define IP address ranges and subnet sizes
(e.g., `10.0.0.0/16`). Widely used in cloud networking to allocate
and control IP ranges.

### CPU (Central Processing Unit)
The component responsible for executing instructions and performing
computations. The operating system schedules CPU time between processes.

---

## D

### DHCP (Dynamic Host Configuration Protocol)
A protocol that automatically assigns IP addresses and network
configuration to devices joining a network.

In cloud environments, DHCP is typically managed by the cloud provider.

### DNS (Domain Name System)
A system that translates human-readable domain names (e.g. `example.com`)
into IP addresses required for network communication.

---

## F

### Firewall
A security control that filters network traffic based on predefined
rules, allowing or blocking traffic according to source, destination,
port, and protocol.

In cloud environments, firewalls exist at multiple layers (NACLs,
Security Groups, host-based firewalls).

---

## G

### Gateway
A network device or service that routes traffic between different
networks. In cloud environments, examples include Internet Gateways
and NAT Gateways.

---

## H

### Host
Any device connected to a network with an IP address.
In cloud contexts, a host typically refers to a virtual machine
or instance.

---

## I

### IP Address
A logical identifier assigned to a device on a network, used to
identify both the network and the specific host.

### Internet Gateway
A cloud-managed gateway that allows resources in a virtual network
to communicate with the public internet.

---

## N

### NAT (Network Address Translation)
A mechanism that translates private IP addresses into public IP
addresses for internet communication.

Commonly used to allow outbound internet access from private subnets
while blocking inbound connections.

### Network
A group of devices connected to exchange data and resources.

### Network Mask (Subnet Mask)
Defines which portion of an IP address represents the network
and which portion represents the host.

---

## O

### Operating System (OS)
Software that manages hardware resources and provides services
and execution environments for applications.

Examples include Linux, Windows, and macOS.

---

## P

### Port
A logical endpoint used to identify specific services or applications
on a host (e.g., port 80 for HTTP, port 443 for HTTPS).

### Process
A running instance of a program, managed by the operating system.
Each process has its own memory space and execution context.

### Program
A set of instructions stored on disk. When executed, it becomes
a process.

---

## S

### Security Group
A stateful virtual firewall used in cloud platforms to control
inbound and outbound traffic at the resource level.

### Subnet
A logical subdivision of a network, used to group resources and
control traffic flow and security boundaries.

---

## T

### TCP (Transmission Control Protocol)
A connection-oriented transport protocol that provides reliable,
ordered, and error-checked data delivery.

### UDP (User Datagram Protocol)
A connectionless transport protocol that prioritizes speed over
reliability.

---

## V

### Virtual Machine (VM)
A software-based emulation of a physical computer, running its own
operating system on shared hardware.

### VPC (Virtual Private Cloud)
A logically isolated virtual network within a cloud provider,
used to deploy and secure cloud resources.

---

## Scope Note

This glossary is intended to support the study materials in this
repository. As the repository evolves, additional terms may be added
to reflect new topics and learning stages.

