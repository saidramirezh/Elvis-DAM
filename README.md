# Elvis DAM - Directory Traversal / Auth Bypass (ElvisDAM-DT.sh)

A vulnerability in Elvis DAM was discovered and reported to WoodWing Software in May 2018.
Jetty web server used by some versions of Elvis DAM is vulnerable to path traversal attacks.
PathResource class introduced in Jetty 9.3.X (CVE-2016-4800) can be bypassed by requesting malicious URLs containing specific escaped characters.

Due to the way that Elvis DAM works, it is possible to gain access to its administration and other systems configured within it. This shell script retrieves 4 configuration files from the affected server.

    node-config.properties.txt
    ldap-config.properties.txt
    internal-users.properties.txt
    cluster-config.properties.txt

A video with the proof of concept of this vulnerability is avalilable at https://www.youtube.com/watch?v=PWcRfdQ3R2I

WoodWing Software released a fix for this vulnerability in the following versions:

    6.14.2
    5.27.8
    4.6.29

## Affected versions

This exploit has been successfully tested on the following versions and platforms:

**CentOS/RHEL:**	5.16.4.1 QP, 5.27.6.206 GA, 5.27.2.260 GA

**macOS:**		5.11.3.2 GA, 5.27.6.206 GA, 5.19.1.154 GA

**Windows:** 	5.22.2.197 GA, 5.11.5.1 QP2

This shell script will try to determine if Elvis DAM is vulnerable or not. If it is vulnerable, critical configuration files will be retrieved and saved for its manual review.

### Usage

If no arguments are specified the usage will be displayed

```
Arguments:

-u, --URL 					Elvis DAM URL (Mandatory), don't include / at the end 
-p, --platform	<windows | linux | macos>	Platform to exploit

If argument <-p | --platform> is not specified, the script will try to determine if target is vulnerable or not

Examples:

bash ElvisDAM.sh -u https://elvis-dam-windows/
bash ElvisDAM.sh --url https://elvis-dam-macos -p macos
```
 
## Author

* **Said Ramirez Hernandez** - [SaidRamirezH](https://github.com/saidramirezh)
