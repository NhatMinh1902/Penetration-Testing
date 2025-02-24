> In large enterprises, you will often observe outdated infrastructure and devices. There are a myriad of reasons why this occurs, but most commonly it is because there had been a “if it’s not broken don’t fix it” mentality to funding infrastructure changes by leadership. Many organizations are now starting to prioritize security as not only a business necessity but also as a key market differentiator to make their offering more appealing to consumers. However, this was not always the case. In many industries, the focus was on profit and revenue growth rather than ensuring systems are kept modern and serviceable. This has resulted in many organizations having extremely out-of-date systems and software in production environments as the funding has just not been allocated to replace them.

## Example 1:

- Server infrastructure and industrial control devices are typically outdated more often than things like employee workstations in enterprise environments. These devices tend to be far more expensive to replace and have a longer lifetime, which makes them somewhat easier to forget about in the technology refresh cycle.

- Nmap has many scripts that are excellent at fingerprinting server infrastructure to identify if they are end-of-life or vulnerable to a specific exploit. Som of the most helpful are:
    - **fingerprinting potentially outdated systems:**
        - ```Ms-sql-info.nse```
        - ```Rdp-ntlm-info.nse ```
        - ```Smb-os-discovery.nse``` 
    - **pinpointing specific vulnerabilities, and even exploiting:**
        - ```Rdp-vuln-ms12-020.nse```
        - ```Realvnc-auth-bypass.nse```
        - ```Rmi-dumpregistry.nse```

    

