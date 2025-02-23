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
  Performs brute force password auditing against http basic, digest and ntlm authentication.

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










