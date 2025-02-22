# Introduction

- this is a very simplified description of a very complex discipline, but the basic structure of the concept is very applicable.
    1. Plan the engagement and define the scope.
    2. Map the attack surface.
    3. Analyze the attack surface to identify applicable vulnerabilities.
    4. Conduct targeted exploitation of vulnerable systems.
    5. Produce and deliver the final report.

# Common Platform Enumeration (CPE) and Common Vulnerabilities and Exposures (CVE)

- [CPE](https://nmap.org/book/output-formats-cpe.html).
- Common Platform Enumeration(CPE) is a standardized way to name software applicat ons, operating systems, and hardware platforms. Nmap includes CPE output for service and OS detection.
- **Structure of a CPE Name**

    - ```**Cpe:[cpe_version]:[ype]:[vendor]:[product]:[version]:[update]:[edition]:[language]**```

- The main division of CPE names is in the <**ype**> field; this can take on only three values: 
    - a for applications.
    - h for hardware platforms.
    - o for operating systems.

- **Nmap** will attempt to identify the CPE through numerous means and output, the most likely result in a far more readable form. To accomplish this, Nmap will combine dozens of operating system versioning and service versioning techniques, which include (among many others):
    - Analyzing the TTL of ICMP responses
    - Analyzing TCP ISN sampling
    - Analyzing IP ID sampling
    - Analyzing service headers


