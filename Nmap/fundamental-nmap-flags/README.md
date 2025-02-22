# 10 flags that are used mostly
1. `-sV`: This flag enabled service version detection on the ports that respond as open. Meaning, that in addition to seeing that port 80 is open on a web server, you may also get additional information, such as whether it is an Apache, Nginx, or IIS web server, as well as what version it is. This additional information can help you determine not only the technology being used in an environment but also start to determine if there are vulnerabilities associated with those services and versions:

 ```nmap -sV 10.0.0.5```


