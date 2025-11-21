# jerry --- Penetration Testing Notes

## 1. Target Information

-   **IP Address:** 10.129.9.14\
-   **Hostname (if applicable):** Not identified\
-   **Operating System (guessed):** Windows Server (based on SMB
    fingerprinting + directory structure)\
-   **Ports Open (quick scan):** 8080\
-   **Ports Open (full scan):** 8080 (no other TCP ports found)

------------------------------------------------------------------------

## 2. High-Level Recon Summary

*(Update this after initial scans)* - Potential entry points: Apache
Tomcat 7.0.88\
- Web services: Tomcat default apps, manager console\
- Auth portals: Tomcat Manager\
- File shares: None\
- Remote access: None\
- Known vulnerable versions: Tomcat 7.0.88 manager upload

------------------------------------------------------------------------

# 3. Enumeration

## 3.1 Nmap Results

### Quick Scan

Command:

``` bash
nmap -sC -sV 10.129.9.14
```

### Full TCP Scan

Command:

``` bash
nmap -p- --min-rate 1000 -T4 10.129.9.14
```

**Key findings:** - Version info: Apache Tomcat/Coyote JSP engine 1.1\
- Interesting scripts: http-title\
- Authentication required? Yes\
- Default creds possible? Yes

------------------------------------------------------------------------

## 3.2 Service Enumeration Checklist

### FTP (21)

-   Not open

### SSH (22)

-   Not open

### HTTP (8080)

-   Web server version: Apache Tomcat/7.0.88\
-   Directories: /manager, /manager/html, /examples\
-   File uploads: Yes (WAR)\
-   Tech stack: JSP / Tomcat\
-   Tools used: gobuster, whatweb, curl

### SMB (139/445)

-   Not open

------------------------------------------------------------------------

# 4. Vulnerability Discovery

## 4.1 Web Vulnerabilities

-   File Upload (WAR)\
-   Default credentials

## 4.2 Service Vulnerabilities

-   Outdated Tomcat\
-   Misconfigured Manager access

## 4.3 Credentials Found

-   tomcat:s3cret

------------------------------------------------------------------------

# 5. Initial Foothold

## 5.1 Access Method

-   Technique: WAR reverse shell upload\
-   Steps: Login → Upload WAR → Trigger shell

## 5.2 Shell Details

-   User: NT AUTHORITY`\SYSTEM  `{=tex}

------------------------------------------------------------------------

# 6. Privilege Escalation

## 6.1 Local Enumeration

-   Already SYSTEM\
-   No Privesc needed

## 6.2 Potential Paths

-   Not required

## 6.3 Exploitation

-   Already SYSTEM

------------------------------------------------------------------------

# 7. Loot / Flags

## 7.1 User Flag

-   Path:
    C:`\Users`{=tex}`\Administrator`{=tex}`\Desktop`{=tex}`\flags  `{=tex}
-   Command: `type "2 for the price of 1.txt"`

## 7.2 Root Flag

-   Same file

------------------------------------------------------------------------

# 8. Post-Exploitation Notes

-   Persistence possible with WAR backdoor\
-   Full compromise due to weak credentials

------------------------------------------------------------------------

# 9. Lessons Learned

-   Default creds testing is essential\
-   Stabilize Windows shells faster\
-   Automate web enumeration
