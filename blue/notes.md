blue — Penetration Testing Notes
# 1. Target Information

    • IP Address: 10.129.5.29
    • Hostname (if applicable): haris-PC
    • Operating System (guessed): Windows 7 Professional 7601 Service Pack 1
    • Ports Open (quick scan):
        ◦ 135/tcp - msrpc
        ◦ 139/tcp - netbios-ssn
        ◦ 445/tcp - microsoft-ds
        ◦ 49152/tcp - msrpc
        ◦ 49153/tcp - msrpc
        ◦ 49154/tcp - msrpc
        ◦ 49155/tcp - msrpc
        ◦ 49156/tcp - msrpc
        ◦ 49157/tcp - msrpc
    • Ports Open (full scan):
        ◦ 135/tcp - msrpc
        ◦ 139/tcp - netbios-ssn
        ◦ 445/tcp - microsoft-ds
        ◦ 49152/tcp - unknown
        ◦ 49153/tcp - unknown
        ◦ 49154/tcp - unknown
        ◦ 49155/tcp - unknown
        ◦ 49156/tcp - unknown
        ◦ 49157/tcp - unknown

# 2. High-Level Recon Summary

(Update this after initial scans)
    • Potential entry points:
        ◦ SMB (ports 135, 139, 445)
    • Web services: None discovered.
    • Auth portals: None discovered.
    • File shares: Accessible via SMB (Shares: ADMIN$, C$, IPC$, Share, Users).
    • Remote access: None discovered.
    • Known vulnerable versions:
        ◦ SMBv1 vulnerable to MS17-010 (EternalBlue).

# 3. Enumeration

## 3.1 Nmap Results
Quick Scan
Command:
-nmap -p- --min-rate 1000 -T4 10.129.5.29

Key findings:
    • Version info:
        ◦ SMBv1 (Windows 7 Professional 7601 Service Pack 1)
    • Interesting scripts:
        ◦ smb-vuln-ms17-010 detected vulnerability.
    • Authentication required?
        ◦ SMB shares available with guest account (anonymous access).
    • Default creds possible?
        ◦ Default guest login credentials worked for SMB shares.

## 3.2 Service Enumeration Checklist
FTP (21)
    • Anonymous login allowed? No FTP service found.
SSH (22)
    • Version: No SSH service found.
HTTP/HTTPS (80/443/other)
    • Web server version: None found.
SMB (139/445)
    • Null session? Yes, guest access allowed.
    • Shares enumerated:
        ◦ ADMIN$, C$, IPC$, Share, Users
    • Interesting files:
        ◦ User files found: root.txt (admin), user.txt (haris).
    • Users found:
        ◦ Administrator, haris.
    • Enum4linux / rpcclient output notes:
        ◦ SMBv1 enabled, vulnerable to MS17-010.
        ◦ Guest account has access to SMB shares.
SMTP (25)
    • No SMTP service found.
Databases
MySQL (3306)
    • No MySQL service found.
PostgreSQL (5432)
    • No PostgreSQL service found.
MongoDB (27017)
    • No MongoDB service found.

#4. Vulnerability Discovery

##4.1 Web Vulnerabilities
    • SQL Injection: None found.
    • Command Injection: None found.
    • File Upload (bypass / abuse): None found.
    • LFI/RFI: None found.
    • Directory Traversal: None found.
    • SSTI: None found.
    • Authentication weaknesses: SMB guest access.
    • Session/cookie issues: None found.
    • Logic flaws: None found.
    • Client-side / JS leaks: None found.
##4.2 Service Vulnerabilities
    • Outdated service versions: Windows 7 Professional (EternalBlue vulnerability).
    • Known CVEs applicable: CVE-2017-0143 (MS17-010).
    • Misconfigurations: SMBv1 enabled with no signing required, guest access allowed.
    • Default or weak creds: Guest account used to access SMB shares.
##4.3 Credentials Found
    • Creds discovered:
        ◦ Administrator — Root flag.
        ◦ haris — User flag.
    • Source (file, response, config, DB, etc.):
        ◦ Found in root.txt and user.txt files on Desktop.
    • Validated on: SMB shares.

#5. Initial Foothold

##5.1 Access Method
    • Exploit / technique:
        ◦ Exploited MS17-010 (EternalBlue) SMB vulnerability.
    • Targeted service:
        ◦ SMB (port 445).
    • CVE / exploit name (if applicable):
        ◦ CVE-2017-0143 (MS17-010) — EternalBlue.
    • Steps taken:
        ◦ Scanned with Nmap for MS17-010 vulnerability.
        ◦ Used Metasploit to exploit SMBv1 and gain access to the machine.
##5.2 Shell Details
    • User: NT AUTHORITY\SYSTEM (highest privileges).
    • Groups: SYSTEM.
    • Home directory: C:\Windows\system32.
    • Environment notes: Meterpreter session running with SYSTEM privileges.

# 6. Privilege Escalation
## 6.1 Local Enumeration
Commands to run (log key results below):
    • id: SYSTEM.
    • whoami: SYSTEM.
    • uname -a: Windows 7 Professional 7601.
    • sudo -l: N/A (Windows).
    • ps aux: Meterpreter session with SYSTEM privileges.
    • lsb_release -a / cat /etc/os-release: Windows 7 Professional.
    • find / -perm -4000 -type f 2>/dev/null: N/A (Windows).
    • crontab -l / ls -la /etc/cron*: N/A (Windows).
    • getcap -r / 2>/dev/null: N/A (Windows).
## Findings:
    • Kernel version: Windows 7 SP1.
    • Sudo privileges: Not applicable (Windows).
    • SUID binaries of interest: Not applicable (Windows).
    • Scheduled tasks: Not found.
    • Capabilities: Not applicable (Windows).
    • Writable config/script files: None found.
    • Interesting services / processes: SYSTEM.
## 6.2 Potential Priv-Esc Paths
    • Misconfigured sudo: Not applicable (Windows).
    • SUID abuse: Not applicable (Windows).
    • Capabilities abuse: Not applicable (Windows).
    • Kernel exploit candidate: None found.
    • Docker/LXC/LXD escape: Not applicable (Windows).
    • Credential reuse (SSH/sudo/mysql/etc.): Not applicable (Windows).
    • Path hijacking / writable scripts: None found.
## 6.3 Exploitation
    • Final method used: EternalBlue (MS17-010) exploit.
    • Commands/exploit steps:
        ◦ Used Metasploit to exploit SMBv1 and gain SYSTEM privileges.
    • Root shell obtained? (when/how): Yes, with Meterpreter session as SYSTEM.

#7. Loot / Flags
##7.1 User Flag
    • Path: c:\Users\haris\Desktop\user.txt
    • Command used: cat "c:\Users\haris\Desktop\user.txt"
    • Flag value: 2764ecc9bfc77eaaa6d07bcd14d52423
##7.2 Root Flag
    • Path: c:\Users\Administrator\Desktop\root.txt
    • Command used: cat "c:\Users\Administrator\Desktop\root.txt"
    • Flag value: 1427d15c4f3cbffc54ba3b3607eb822e
##7.3 Other Interesting Data
    • Passwords: None found.
    • Hashes: None found.
    • Keys: None found.
    • Configs: None found.

#8. Post-Exploitation Notes
    • Could persistence be added? How?
        ◦ Yes, you can add persistence via creating new users or modifying startup scripts.
    • Lateral movement possibilities (if in real network):
        ◦ SMB can be used to move laterally to other machines with SMBv1 enabled.
    • Data exfiltration paths:
        ◦ Can access files in SMB shares (C$, Users, etc.).
    • What would be high impact in real life?
        ◦ Remote code execution via SMB, potential for lateral movement within the network.

#9. Lessons Learned / To Improve
    • What slowed me down: Initial difficulty in confirming the existence of SMB shares.
    • What I missed initially: Need for enum4linux output to confirm SMB vulnerability.
    • Commands I had to look up: enum4linux and nmap options for SMB vulnerability checks.
    • Techniques to practice: Automated SMB enumeration and exploit verification.
    • Things to automate in future (scripts, aliases, etc.):
        ◦ SMB share enumeration and vulnerability checks for faster exploitation.
