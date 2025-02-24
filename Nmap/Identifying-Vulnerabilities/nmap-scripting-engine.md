# Exploring the Nmap Scripting Engine

- The Nmap Scripting Engine is among the most powerful components of Nmap due to its versatility. Written in the Lua scripting language, these scripts amplify Nmap to be able to fingerprint more specific systems, perform more nuanced scans, exploit known vulnerabilities, and even enumerate firewall rules.

- To list them on your Kali machine, simply use the following command:

    ```
    ls -l /usr/share/nmap/scripts
    ---------- snip ----------
    -rw-r--r-- 1 root root  2835 Jan  3 15:56 dpap-brute.nse
    -rw-r--r-- 1 root root  5805 Jan  3 15:56 drda-brute.nse
    -rw-r--r-- 1 root root  3796 Jan  3 15:56 drda-info.nse
    -rw-r--r-- 1 root root  7477 Jan  3 15:56 duplicates.nse
    -rw-r--r-- 1 root root  5855 Jan  3 15:56 eap-info.nse
    -rw-r--r-- 1 root root 57881 Jan  3 15:56 enip-info.nse
    -rw-r--r-- 1 root root  1716 Jan  3 15:56 epmd-info.nse
    -rw-r--r-- 1 root root  2564 Jan  3 15:56 eppc-enum-processes.nse
    -rw-r--r-- 1 root root  3910 Jan  3 15:56 fcrdns.nse
    -rw-r--r-- 1 root root  1083 Jan  3 15:56 finger.nse
    -rw-r--r-- 1 root root  4183 Jan  3 15:56 fingerprint-strings.nse
    -rw-r--r-- 1 root root 29093 Jan  3 15:56 firewalk.nse
    -rw-r--r-- 1 root root  8887 Jan  3 15:56 firewall-bypass.nse
    ---------- snip ---------
    ```
- You can then explore any of them by printing out the file, either via the cat command or with a text editor (nano, vi, vim, and so on):

    ```
    cat /usr/share/nmap/scripts/address-info.nse
    local datafiles = require "datafiles"
    local nmap = require "nmap"
    local stdnse = require "stdnse"
    local string = require "string"
    local table = require "table"

    description = [[
    Shows extra information about IPv6 addresses, such as embedded MAC or IPv4 addrsses when available.

    Some IP address formats encode extra information; for example some IPv6
    addresses encode an IPv4 address or MAC address. This script can decode
    these address formats:
    * IPv4-compatible IPv6 addresses,
    * IPv4-mapped IPv6 addresses,
    * Teredo IPv6 addresses,
    * 6to4 IPv6 addresses,
    * IPv6 addresses using an EUI-64 interface ID,
    * IPv4-embedded IPv6 addresses,
    * IPv4-translated IPv6 addresses and
    * ISATAP Modified EUI-64 IPv6 addresses.
    ----------- snip ---------

- **10 that are most often used when conducting enterprise penetration tests of multibillion dollar corporations:**

1. `Vulners.nse`: This is one of the handiest scripts available for doing a quick surface-level vulnerability analysis. This script looks at the services being run on the system and queries the vulenrs.com database of vulnerabilities to determine if those services match known vulnerabilities. It will then print out those CVEs to the command prompt along with hyperlinks to their database for additional information. What makes this even more convenient is that Vulners will even define if there is a known exploit available for that vulnerability.

2. `Ms-exchange-version.nse`: Outdated versions of on-premises Microsoft Exchange have been riddled with severe vulnerabilities. This script does a better job  han even most commercial vulnerability scanners at fingerprinting the exact version of the exchange that is being utilized.

3. `Smb-security-mode.nse // smb2-security-mode.nse`: SMB signing not being enabled or required is one of the most common high-severity vulnerabilities seen on internal environments. With this script, you can very rapidly determine if a pass-the-hash attack will be a viable option for lateral movement within the environment.

4. `Smb-os-discovery.nse`: Fingerprinting server infrastructure can be challenging, but with Windows 2012R2 recently reaching the end of life (and still very widely used), the opportunity for exploiting these systems is as present as ever. Having the capacity to fingerprint Windows systems via the SMB protocol is essential for any pentester.

5. `Smb-enum-*`: This shortcut for running dozens of individual SMB enumeration scripts is a great way to save time on an engagement. When you do not need to worry about being stealthy, throwing everything at a target in the most efficient way is a plus.

6. `Smb-vuln-*`: Similar to preceding point, being able to automatically verify susceptibility to a list of high-severity SMB vulnerabilities rapidly can be a great technique, especially in larger scope engagements where efficiency is everything.

7. `Broadcast-jenkins-discover.nse`: Jenkins has had countless vulnerabilities over the years and many instances remain tremendously out of date. Being able to identify these systems on the network can provide an early and effective foothold for exploitation.

8. ` Http-wordpress-enum.nse`: WordPress websites are incredibly common and often make use of many individual plugins, some of which are commercially supported, and others are community-driven. As a result, there have been countless WordPress plugin-specific vulnerabilities over the last decade; many of which do not have patches. This script is a very handy way to fingerprint these plugins and print out any known vulnerabilities associated with them.

9. `Firewalk.nse`: Firewalk is a fairly old, but still quite useful script that attempts to determine firewall rules on a specified gateway by analyzing IP time to live (TTL) expirations. Essentially this technique, known as firewalking, sends varying types of probes to the gateway and based on the TTL and reply ascertains if a firewall rule is impacting that port.

- A couple of items to be aware of for this script:
    - first, you need to run it either in an administrator or sudo command prompt as it needs raw socket access. As a result, this is highly unreliable in **Windows Subsystem for Linux (WSL)**.
    - Second, you also need to include the command “**--traceroute**”:

10. `Mysql-empty-password.nse` : it checks MySQL servers for default user credentials by attempting to authenticate to the service. While this can be handy, it should be understood that this is both easily detectable and intrusive.

- **NOTE**: [Cyber-Judo.com on Advanced Nmap Techniques](https://cyber-judo.com/advanced-nmap-techniques)

- More often, true success leading to a cascading compromise within a network environment comes from identifying the vulnerabilities that stem from [misconfigurations](https://github.com/NhatMinh1902/Penetration-Testing/blob/main/Nmap/Identifying-Vulnerabilities/misconfigurations.md), [inherently flawed protocols](https://github.com/NhatMinh1902/Penetration-Testing/blob/main/Nmap/Identifying-Vulnerabilities/inherently-flawed-protocols.md), and [significant technical debt](https://github.com/NhatMinh1902/Penetration-Testing/blob/main/Nmap/Identifying-Vulnerabilities/technical-debt.md).







