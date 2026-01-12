# DNS Basics

## What is DNS?
Domain Name System (DNS) is responsible for translating domain names into IP addresses.

Without DNS, users would need to memorize numerical IP addresses to access websites.

## DNS Hierarchy
DNS operates through a hierarchical structure:

1. **Root Servers**  
   They do not know the IP address of the website but know which servers manage top-level domains.

2. **Top-Level Domain (TLD) Servers**  
   These servers manage extensions such as .com, .org and .br.

3. **Authoritative Servers**  
   These servers belong to the organization that owns the domain and provide the final IP address.

DNS resolution works like climbing a ladder until the correct address is found.

## DNS Caching
To avoid repeating the full resolution process every time, DNS responses are cached by devices and routers.

### Advantages
- Faster website loading
- Reduced network traffic

### Point of Attention
If a website changes its IP address, cached records may cause temporary access issues until the cache expires.

## Why DNS Matters for Cloud
Cloud platforms rely heavily on DNS for scalability, availability and service discovery.
Managed DNS services improve reliability and performance in distributed systems.

