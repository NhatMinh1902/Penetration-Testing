> Some network protocols are designed in such a way that their fundamental implementation presents a vulnerability that can be exploited by an attacker. Two commonly seen examples are Intelligence Platform Management Interface Version 2 (IPMIv2) and MQ Telemetry Transport (MQTT). These are very different protocols and are used for completely different purposes, but both offer a very easy path to exploitation once they are identified.

## Example 1:
- IPMIv2 is a protocol designed to support management and monitoring by system administrators for out-of-band management systems, like an iDRAC, for example. The problem with this protocol is the way it handles authentication and provides  hashed version of the user’s password once a username is submitted. This allows attackers to systematically dump all user hashes and attempt to crack them usin an offline dictionary or brute force-based means.

- Identifying hosts with IPMIv2 with Nmap can be done with one command first identifying hosts with UDP port 623 open, then versioning the service with the script ipmi-version:

    ```
    Nmap -sU -p 623 –-open --script ipmi-version.nse -iL targets.txt
    ```

- There are several other tools available which will both scan for and dump the hashes for IPMIv2, such as the Metasploit module `auxiliary/scanner/ipmi/ipmi_dumphashes`. However, it is almost always quicker and safer to first confirm the use of IPMIv2 using Nmap, and then determine if exploitation is permitted within your rules of engagement.


## Example 2:

- MQTT is a lightweight messaging protocol most commonly used by IoT devices due to the inherently resource-constrained nature of such devices. In most implementations of MQTT, authentication is completely optional to establish a connection and subscribe to various topics that are published by the MQTT brokers.

- To identify and subscribe to various topics for additional system information and enumeration, you can simply scan for systems with port 1833 open and call the `mqtt-subscribe.nse` script:

    ```
    Nmap -p 1883 --open --script mqtt-subscribe -iL targets.txt
    ```



