# Introduction

- this is a very simplified description of a very complex discipline, but the basic structure of the concept is very applicable.
    1. Plan the engagement and define the scope.
    2. Map the attack surface.
    3. Analyze the attack surface to identify applicable vulnerabilities.
    4. Conduct targeted exploitation of vulnerable systems.
    5. Produce and deliver the final report.

# Common Platform Enumeration (CPE) and Common Vulnerabilities and Exposures (CVE)
## Common PLatform EnumerationCPE
- [What is CPE?](https://nmap.org/book/output-formats-cpe.html).
- Common Platform Enumeration(CPE) is a standardized way to name software applicat ons, operating systems, and hardware platforms. Nmap includes CPE output for service and OS detection.
- **Structure of a CPE Name**

     ```Cpe:[cpe_version]:[ype]:[vendor]:[product]:[version]:[update]:[edition]:[language]```

- The main division of CPE names is in the <**ype**> field; this can take on only three values: 
    - **a** for applications.
    - **h** for hardware platforms.
    - **o** for operating systems.

- **Nmap** will attempt to identify the CPE through numerous means and output, the most likely result in a far more readable form. To accomplish this, Nmap will combine dozens of operating system versioning and service versioning techniques, which include (among many others):
    - Analyzing the TTL of ICMP responses
    - Analyzing TCP ISN sampling
    - Analyzing IP ID sampling
    - Analyzing service headers

## Common Vulnerabilities And Exposures (CVEs)

- Vulnerabilities is another word that is used frequently in the information security industry and can have different meanings based on context. When discussing CVEs always consider the following definition of a vulnerability taken directly from [cve.org](https://www.cve.org/):
- To gauge the legitimate impact of a CVE and to aid in prioritizing remediation efforts, many organizations will use what is called the Common Vulnerability Scoring System (**CVSS**). The **CVSS** is a method of qualitatively measuring the severity of a vulnerability from 0 (no impact) to 10 (critical). **CVSS** is owned and maintained by FIRST, which is a US-based non-profit organization focused on aiding security and incident response teams worldwide. While a 1 to 10 scoring range may seem simple, the calculation is actually quite complex and takes into account many aspects such as attack complexity, impact on the **CIA**, what privilege level is required for exploitation, and many more.

## Introduction to Nmap Scripting Engine

- Among the most powerful features Nmap has to assist you in enumerating CPEs, identifying **CVEs**, and even in some cases exploiting systems is the **Nmap Scripting Engine (NSE)**.
- Using `--script` flag followed by the name of the NSE script.
- To get additional insight into what the script does before running it, using the `–script-help` command is extremely helpful.

    ```
     nmap --script-help vulners.nse
    ```
- the **vulners.nse** script is classified into the categories **vuln, safe, and external**.

## Intermediate Nmap Flags

- **The
following 12 flags are designed to take your basic scans and bring them up to the next level by adding more capabilities and nuanced control over how they operate:**

1. `--script`: Among the most powerful features of Nmap is the **Nmap Scripting Engine (NSE)**. We have seen a brief display of the different capabilities of NSE scripts already when we analyzed vulnerabilities using the **vulners.nse** script.

    ```
    nmap --script http-brute.nse 10.0.2.6
    ```

2. `--script-help`: to explore the expansive base of scripts. The `--script-help` command enables you to do just that by outputting information regarding what the particular scripts do without having to launch them.

    ```
    nmap --script-help http-brute.nse
    Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-22 20:11 EST

    http-brute
    Categories: intrusive brute
    https://nmap.org/nsedoc/scripts/http-brute.html
    Performs brute force password auditing against http basic, digest and ntlm a uthentication.

    This script uses the unpwdb and brute libraries to perform password
    guessing. Any successful guesses are stored in the nmap registry, using
    the creds library, for other scripts to use.
    ```

3. `-6`: While the vast majority of the time on penetration tests, you are working with IPv4, there is a chance that you will need to scan a specific IPv6 address.

4. `-sn`: During default scanning one of the initial techniques used by Nmap is ICMP probes. These probes are extremely common and are used by Nmap to help ascertain if a host is alive or not. Very simply, if the host replies to the ICMP probe (also known as a ping), then Nmap will recognize that host as alive; if not, it will move on.This is commonly known as a ping sweep and is used for large-scope host discovery.

    ```
    nmap -sn 192.168.0.0/24
    ------ snip ------
    Nmap scan report for 192.168.0.1
    Host is up (0.00013s latency).
    Nmap scan report for 192.168.0.2
    Host is up (0.00033s latency).
    Nmap scan report for 192.168.0.3
    ------ snip ------
    ```

5.  `-Pn`: Conversely, to the previous flag, there will also be occasions where you do not want to conduct a ping scan. This becomes problematic in environments that specifically block ICMP traffic. During penetration tests, it is not uncommon to see initial reconnaissance scans come back with no live hosts due to a failure of Nmap to determine hosts were alive because there was no ICMP response. In these instances, it is prudent to disable ICMP and re-scan the targets; more often than not, this will return the expected results. The `-Pn` flag is used for exactly this purpose, to disable ICMP (ping) scans.

6.  `-F`: Think of the `-F` as “Fast”, this is a flag that reduces the number of ports scanned from Nmap’s default of 1000 to the top 100. [100 most commonly seen ports and services](https://nmap.org/book/nmap-services.html). While this flag does substantially increase the speed compared to a base scan, it is important to note that very commonly there will be key ports missed. The best way to utilize this scan is as a way to determine which subnets or endpoints of the greater scope should be marked for additional analysis.

7. `--top-ports #`: We have established that the default of Nmap is to scan the top 1000 ports, and you can use the -F flag to reduce that to the top 100. But what if you want to scan the top 25? Or 50? Or 1000? That is where the `--top-ports` flag comes in; this allows you to specify the exact number to scan, which can help provide a good balance between speed and depth. the most common specification for this flag seems to be `--top-ports 2500`.

8. `--version-intensity #`: service version could be abled via the `-sV` command, but additional nuance can be added by specifying the intensity of that versioning effort between **0** and **9**. This is done by sending a series of probes with assigned values to all identified open ports in an attempt to determine the service running on them. The default value of `-sV` is “**7**”. So, if your objective is to return results quicker, select a lower number, and if you are trying to get a more accurate fingerprint, select the higher value:
    ```
    nmap -sV --version-intensity 5 10.2.0.6
    ```

9. ` --version-light`: This flag is simply an alias for `--version-intensity 2`.
It is a very fast way to conduct scanning when you are less interested in the
exact fingerprint of specific services.

10. `--version-all`: This is an alias for `–-version-intensity 9`, which will make every effort available to Nmap (outside of NSE scripts) to identify the exact version of services. This level of specificity of course comes with the inherent drawback that it will take significantly longer to complete the scan. It is not recommended to use this flag against a scope larger than a **/24** subnet, as it will take an egregious amount of time.

11. `--max-os-tries #`: When Nmap conducts operating system identification, it will by default attempt 5 times to determine the exact OS. By specifying a lower value, you can increase the speed of the scan by reducing the attempts to fingerprint the operating system. Alternatively, you can also increase the tries beyond the default of 5 to attempt to better identify the endpoint.
- **the use case of specifying a --max-ostries value greater than 5 is very rarely done**

12. `--exclude-ports #,#`: Many endpoint detection agents, such as SentielOne, CrowdStirke Falcon, and Windows Defender, tend to be very attuned to specific ports being probed such as port **22 (SSH)**, and **445 (SMB)**. This flag lets you simply exclude those ports from being scanned, which in some cases is enough to remain under the noise floor in an environment.

## Exploring the Nmap Scripting Engine

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
    ```

- **10 that are most often used when conducting enterprise penetration tests of multibillion dollar corporations:**

1. p













