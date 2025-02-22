# 10 flags that are used mostly
1. `-sV`: This flag enabled service version detection on the ports that respond as open. Meaning, that in addition to seeing that port 80 is open on a web server, you may also get additional information, such as whether it is an Apache, Nginx, or IIS web server, as well as what version it is. This additional information can help you determine not only the technology being used in an environment but also start to determine if there are vulnerabilities associated with those services and versions:

    ```nmap -sV 10.0.0.5```

2. `-A`: This flag enabled operating system detection as well as service versioning on the host. A simple way to remember this one is “A” is for “All”. You get all the port, service, versioning, and operating system information that Nmap can identify at once:

    ```nmap -A 10.0.0.5```

    **There are a couple of things to note with -A, which are as follows:**
        -It is redundant and provides more information than `-sV`. It means that there is no reason to combine these flags. The same goes for `-O`, which is operating system versioning; while that flag exists, it is rarely used, as `-A` is considered be a far better alternative.
        -It is a much slower scan than `-sV` because it enumerates so much more information. That is why both `-sV` and `-A` are listed here. There will be times when the service versioning information is enough, and you need to speed over the additional information.

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



