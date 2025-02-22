DNS Rebinding
DNS rebinding changes the IP address of an attacker controlled machine name to the IP address of a target application, bypassing the same-origin policy and thus allowing the browser to make arbitrary requests to the target application and read their responses.

Summary
Tools
Methodology
Protection Bypasses
0.0.0.0
CNAME
localhost
References
Tools
nccgroup/singularity - A DNS rebinding attack framework.
rebind.it - Singularity of Origin Web Client.
taviso/rbndr - Simple DNS Rebinding Service
taviso/rebinder - rbndr Tool Helper
Methodology
Setup Phase:

Register a malicious domain (e.g., malicious.com).
Configure a custom DNS server capable of resolving malicious.com to different IP addresses.
Initial Victim Interaction:

Create a webpage on malicious.com containing malicious JavaScript or another exploit mechanism.
Entice the victim to visit the malicious webpage (e.g., via phishing, social engineering, or advertisements).
Initial DNS Resolution:

When the victim's browser accesses malicious.com, it queries the attacker's DNS server for the IP address.
The DNS server resolves malicious.com to an initial, legitimate-looking IP address (e.g., 203.0.113.1).
Rebinding to Internal IP:
