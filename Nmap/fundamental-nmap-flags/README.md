# 10 flags that are used mostly
1. `-sV`: This flag enabled service version detection on the ports that respond as open. Meaning, that in addition to seeing that port 80 is open on a web server, you may also get additional information, such as whether it is an Apache, Nginx, or IIS web server, as well as what version it is. This additional information can help you determine not only the technology being used in an environment but also start to determine if there are vulnerabilities associated with those services and versions:

    ```nmap -sV 10.0.0.5```

2. `-A`: This flag enabled operating system detection as well as service versioning on the host. A simple way to remember this one is “A” is for “All”. You get all the port, service, versioning, and operating system information that Nmap can identify at once:

    ```nmap -A 10.0.0.5```

- **There are a couple of things to note with -A, which are as follows:**
    - It is redundant and provides more information than `-sV`. It means that there is no reason to combine these flags. The same goes for `-O`, which is operating system versioning; while that flag exists, it is rarely used, as `-A` is considered be a far better alternative.
    - It is a much slower scan than `-sV` because it enumerates so much more information. That is why both `-sV` and `-A` are listed here. There will be times when the service versioning information is enough, and you need to speed over the additional information.

3. `-T`: T stands for time; it is the speed at which the scan is conducted, and it comes in six variations, ranging from T0, which is extremely slow, to `T5`, which is extremely fast. Appropriately, the default of Nmap (if you do not specify otherwise) is `T3`, quite fast. I will typically use `T2` during most engagements that are not extremely large.

4. `-v`: V stands for verbosity; this is a common argument you will find in tools and simply makes the output that is displayed more verbose. It adds additional details to the output and is paired very well with either `-sV` or `-A`. There are also three levels of verbosity: `-v`, `-vv`, and `-vvv`. The more Vs that are added, the more verbose the output will be, but also the longer the scan will take. I have personally rarely found it helpful to use more than a single v when leveraging this flag:

    ```nmap -sV -v 10.0.0.5```

5. `-iL`: This flag is “in list”, and it is essential for anybody conducting a penetration test of a complex environment. This allows Nmap to read the target list from a txt file rather than scanning one entry or range in the command line. Imagine an engagement where you have dozens if not hundreds of individual external domains and IP addresses; you can put them all into a simple txt file and Nmap will sequentially scan them all at once for you:

    ```nmap -iL target.txt```

6.  `-oX`: This is for Output. There are several options available to save the output to a file, which can be referenced later: `-oG` for **Greppable output**, `-oN` for **normal output**, there is even `-oS` for a comical Script Kiddie output riddled with misspellings and crazy capital letters. But I tend to use `-oX`, which outputs to an **XML** format that is easily imported into additional tools such as Zenmap and Legion.use `-oA` for all of them.

7. `-p`: P stands for Port. You can specify specific ports that you want to scan
that are single, in ranges, or comma-separated like so:
    - -p 80 (only port 80)
    - -p 80-443 (every port between 80 and 443)
    - -p 80,440 (only ports 80 and 443)

    You can also use `-F` (fast) to reduce from the top **1,000** to the top **100**, or use `–-allports` to scan all **65,535 ports**.

8. `-sU`: This flag specifies scanning **UDP** ports as opposed to **TCP**. When you use the `-p` command, by default, Nmap will assume you mean **TCP** port **X**.
    - if you are looking for the **IPMIv2** protocol, which can be hosted on either**TCP** or **UDP** port **623**. In this instance, you would want to make sure that you check both options, or you could potentially miss a critical vulnerability.

9. `–open`: This flag filters the response and only shows you ports that respond as being “open” on the target hosts. This is a huge time saver and quality-of-life improvement.

10. `--reason`: This is a flag that most people have never heard of, but it can be really helpful in determining what is going on. It shows the reason why each port is being reported the way that it is. If you are seeing a lot of ports ope and they are all coming back Filtered, this is a great flag to add on and rescan the target. While it cannot magically change the status to open, it can display the type of packet that was received from the port when the connection was made:

    ```nmap -Pn 10.0.0.5 --reason```


## Hand-on
### EX1: 
-  Now we can start to utilize Nmap to dive into the hosts both collectively as well as individually. The strategy tend to be used for this is to first scan the entire target list, looking for ports typically open during this type of engagement.

    ```Nmap -A -T2 --open -p 21,22,25,80,110,179,443,8080,8443 -iL targets.txt -oX results1.xml```

- Let's break down what that scan is doing flag by flag:

**Flag** | **Function** 
------------ | ------------- 
**-A** | Fingerprint the operating system and all services and versions
**-T2** | Slow scanning speed
**--open** | Only show results for ports that are returned in the open state
**-p** | A numerical list of the ports to be scanned
**-iL** | Supplying the targets list “**targets.txt**”
**-oX** | Directing the output to also be piped to the file **results1.xml**

- Additionally, we strategically specified several individual ports with the `-p` flag:

**Port** | **Protocol**
------------ | -------------
21 |  FTP – File Transfer Protocol
22 | SSH – Secure Shell
25 | SMTP – Simple Mail Transfer Protocol
80 | HTTP – Hypertext Transfer Protocol
110 | POP3 – Post Office Protocol version 3
179 | BGP – Border Gateway Protocol
443 | HTTPS – Hypertext Transfer Protocol Secure
8080 | Alternate port for HTTP
8443 | Alternate port for HTTPS

- These ports can be logically put into three main categories to identify the most
    - commonly seen systems that are externally exposed:
    - Web Servers (80,443,8080,8443)
    - Mail Servers (25,110)
    - File Transfer Servers (21,22)
    - Networking Misconfiguration (179)

- Khi bạn xem xét kỹ các kết quả này, có một số điều quan trọng mà bạn cần lưu ý để giúp bạn xác định CPE của từng điểm cuối:
    - Specific operating system and version
    - What the system is likely used for
    - Specific services running on the ports and their associated versions

- You will need to systematically determine what vulnerabilities (CVEs) are known that are associated with both the endpoint itself (operating system) and any of the services running on that endpoint. To this end, there are a few great resources that can help you along the way:

**Resource** |  **Purpose**
------------ | ------------- 
https://www.cvedetails.com |  This is a free-to-use repository of information on known CVEs, which allows you to search by the CVE ID, product title, vendor, or even vulnerability type.
https://www.cisa.gov |  The United States Cybersecurity Infrastructure and Security Agency has a robust database of known exploited vulnerabilities. Once you have identified a vulnerability through cvedetails.com or any other means, this is a great place to check and see if that vulnerability has been exploited in the wild.
https://www.exploit-db.com |  This is a database of known exploits, which can be searched by title, system, or CVE ID. Once you have identified an applicable CVE and confirmed that it is being exploited in the wild, this is one area to look into the exploit code.

### EX2: 
- With the initial group of systems identified you will want to create a second list of targets to dig deeper into the ones that seem to be the most interesting in terms of having outdated services or operating systems. Separating these systems into a **targets2.txt** file, we can then take some of the restrictions off of the scan profile to dig deeper:

    ```nmap -A --version-intensity 9 --allports --open -iL targets2.txt -oX results2.xml```

- There are two additional flags: **version intensity** and **all ports**.
    - the “**all ports**” flag simply directs Nmap to query every TCP port that exists
    - The “**version-intensity**” flag however is slightly more nuanced. Version-intensity is an option that can be given a numerical value from **1** (least intense) to **9** (most intense), which will increase the likelihood of successfully versioning the service at the expense of taking longer to
scan.

- A default Nmap version scan (-sV) will be using a version-intensity rating equivalent to 7.
- use the `--version-all` flag as a shorthand alias for “**version-intensity 9**”.

### Case Study – Continuous Attack Surface MonitoringCase Study of a Small Business

- First, they built a process with documentation, laying out a few very specific scans that they would run every other Friday. By establishing the process and meticulously documenting how it is meant to run, they were able to keep it regimented and effective.
    - They scanned every subnet they had on their internal network, as opposed to just the IP addresses that they knew about.
    - They scanned every externally accessible domain and asset the company owned for ports, services, and vulnerabilities.
    - They would output the results to XML files, and analyze them for any week-to-week changes using Zenmap.

- This is the scan that they used:

    ```nmap -A -v -T2 –-open –-vulners.nse -iL [Internal or External Target List] -oX [month] [Internal or External]_nmap_results.xml```




