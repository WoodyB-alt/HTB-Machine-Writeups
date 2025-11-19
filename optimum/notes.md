# )ptimum — Penetration Testing Notes
# 1. Target Information
    • IP Address: 10.129.5.141
    • Hostname (if applicable): OPTIMUM
    • Operating System (guessed): Windows Server 2012 R2 Standard (confirmed after foothold)
    • Ports Open (quick scan): 80, 135, 139, 445
    • Ports Open (full scan): 80, 135, 139, 445, 5985, and numerous high ephemeral ports (49152–49157)

# 2. High-Level Recon Summary
### Potential entry points:
    • Rejetto HFS 2.3 web server running on port 80
    • SMB open but nothing writable
    • WinRM open (5985) but no creds initially
### Web services:
    • HFS 2.3 vulnerable to RCE via search parameter
### Auth portals:
    • None discovered on HTTP
    • WinRM requires valid credentials
### File shares:
    • Standard ADMIN$, C$, IPC$ — but no null session access
### Remote access:
    • Shell via HFS exploit
    • WinRM available after privilege escalation if creds found
### Known vulnerable versions:
    • Rejetto HFS 2.3 (CVE-2014-6287) — Remote Command Execution

# 3. Enumeration
## 3.1 Nmap Results
### Quick Scan
Command used: nmap -sC -sV 10.129.5.141
### Full TCP Scan
Command used: nmap -p- --min-rate 1000 -T4 10.129.5.141
### Key findings:
    • Port 80 running HFS 2.3 (vulnerable)
    • SMB open but locked down
    • WinRM open
    • Windows Server 2012 R2 fingerprinted
    • No anonymous access
    • HFS version banner leaks vulnerability


##  3.2 Service Enumeration Checklist
### FTP (21)
    • Not open
### SSH (22)
    • Not open
### HTTP/HTTPS (80)
    • Web server version: Rejetto HFS 2.3
    • Directories found: Default root listing
    • Interesting endpoints: ?search= parameter
    • File uploads: Not directly, but remote execution possible
    • Login portals: None
    • CMS: None
    • Tech stack: HFS executable running as kostas
### Tools used:
    • curl
    • browser
    • manual testing of payloads
### SMB (139/445)
    • Null session: NO
    • Shares: ADMIN$, C$, IPC$
    • No readable directories without authentication
### SMTP (25)
    • Not open
### Databases
    • None exposed externally


# 4. Vulnerability Discovery
## 4.1 Web Vulnerabilities
    • Command Injection: YES (via HFS search parameter)
    • LFI/RFI: HFS supports .load for remote file fetching
    • Directory Traversal: Possible through HFS paths but not needed
    • Other issues: HFS allows arbitrary execution with { .exec | command }
## 4.2 Service Vulnerabilities
    • HFS 2.3 RCE (CVE-2014-6287)
    • Windows Server 2012 R2 vulnerable to MS16-032 for priv esc
## 4.3 Credentials Found
    • No useful credentials discovered
    • WinPEAS indicated Autologon missing
    • No plaintext passwords leaked

# 5. Initial Foothold
## 5.1 Access Method
Exploit / technique: Rejetto HFS 2.3 Remote Command Execution
Targeted service: HTTP (Port 80)
CVE / exploit name: CVE-2014-6287 / rejetto_hfs_exec
Steps taken:
    • Tested manual curl payloads
    • Launched Metasploit module exploit/windows/http/rejetto_hfs_exec
    • Set RHOSTS, LHOST, LPORT, PAYLOAD
    • Obtained reverse shell as kostas
## 5.2 Shell Details
User: OPTIMUM\kostas
Groups: Users
Home directory: C:\Users\kostas
Environment notes:
    • Running HFS from desktop
    • No admin privileges initially


# 6. Privilege Escalation
## 6.1 Local Enumeration
Commands/tools used: winPEAS, manual registry queries, whoami /priv, systeminfo
Findings:
    • Kernel version: Windows Server 2012 R2 (6.3.9600)
    • Sudo privileges: N/A on Windows
    • SUID binaries: N/A
    • Scheduled tasks: Nothing exploitable
    • Capabilities: Standard low-priv
    • Writable folders: User’s Desktop
    • Interesting services: Secondary Logon vulnerable
    • Vulnerability: MS16-032 privilege escalation viable
## 6.2 Potential Priv-Esc Paths
    • Kernel exploit: MS16-032
    • Token manipulation: Not available
    • Autologon credentials: WinPEAS reported missing
    • DLL hijacking paths: Not required
    • Writable TEMP folders: Yes, but unnecessary
## 6.3 Exploitation
Final method used: MS16-032 Secondary Logon Handle Privilege Escalation
Commands/exploit steps:
    • Converted shell to Meterpreter using post/multi/manage/shell_to_meterpreter
    • Used exploit/windows/local/ms16_032_secondary_logon_handle_privesc
    • Set SESSION to Meterpreter
    • Set PAYLOAD to windows/meterpreter/reverse_tcp
    • Launched exploit and gained SYSTEM
Root shell obtained: Yes (NT AUTHORITY\SYSTEM) through Meterpreter session


# 7. Loot / Flags
## 7.1 User Flag
Path: C:\Users\kostas\Desktop\user.txt
Command used: type user.txt
Flag value: faefeec90441a611c7156690cec677cf
## 7.2 Root Flag
Path: C:\Users\Administrator\Desktop\root.txt
Command used: type root.txt
Flag value: (not recorded)
## 7.3 Other Interesting Data
    • HFS executable
    • Ability to load remote files
    • Meterpreter sessions persistent until machine reset


# 8. Post-Exploitation Notes
## Could persistence be added?
    • Yes: registry run keys or scheduled tasks (as SYSTEM)
## Lateral movement possibilities:
    • None; standalone host
## Data exfiltration paths:
    • SMB
    • HTTP outbound allowed
## High-impact findings:
    • Publicly exploitable unauthenticated RCE
    • Privilege escalation with well-known Windows kernel exploit


# 9. Lessons Learned / To Improve
## What slowed me down:
    • Trying to manually force RCE before switching to Metasploit
    • WinPEAS autologon search confusion
    • Attempting wrong payload architecture on priv-esc module
## What I missed initially:
    • Shell needed converting to Meterpreter before using MS16-032
## Commands I had to look up:
    • Meterpreter migration and shell upgrade
    • Running winPEAS correctly
## Techniques to practice:
    • Faster pivot to MSF modules
    • Recognizing classic Windows priv-esc patterns
    • Meterpreter workflow and cleanup
## Things to automate in future:
    • Auto-recon scripts
    • Auto-MSF templates for Windows priv-esc
    • Aliases for shell upgrade
