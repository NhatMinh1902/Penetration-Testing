> Security misconfigurations could refer to any number of huge swaths of inadvertent errors when setting up devices. This is such a broad category that in **Open Web Application Security Project (OWASP)’s** 2021 edition of Top 10 Vulnerabilities in Web Apps, over 90% of applications had a vulnerability that fell into this category.

## Example 1:

- The most glaringly obvious example of a security misconfiguration is also extremely common in enterprise networks. "*“What is the #1 way you compromise systems on an internal environment*", they will most likely say “*default credentials*”.

- It is unbelievably common to find printers, phone systems, security cameras, and even significantly more critical devices, such as a Dell iDRAC with their default administrator credentials still active(root/calvin).

- There are a couple of ways that Nmap can support the auditing of default credentials. The first is the use of a few NSE scripts, which attempt to brute force the devices; a few examples are `citrix-brute-xml.nse`, `ftp-bute.nse`, and
`iax2-brute.nse`.

- Using Nmap to scan the subnet for only web servers on the most common ports (80,443,8080,8443):
    ```
    Nmap -p 80,443,8080,8443 –open -iL targets.txt
    ```

- Use an opensource tool in Kali Linux called [EyeWitness](https://github.com/redsiege/EyeWitness). EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possiblel.

## Example 2:

- Many systems are set up that, by default, do not have all security systems hardened. By using the NSE script `smb2-security-mode.nse`, we can see that SMB signing is enabled but not required. This is a big problem from a security standpoint. SMB signing is a Microsoft feature that signs all SMB messages with both a session key and an encryption algorithm.

- By doing this, an extremely popular (and old) man-in-the-middle attack called pass-the-hash is largely mitigated. In a pass-the-hash attack, an attacker woul acquire the password hash of a valid user, possibly through network traffic poisoning or another vector, and then “pass” that hash to a system not requiring SMB signing to authenticate as that user.






