# Shocker — Penetration Testing Notes

## 1. Target Information
- **IP Address:** 10.129.9.31
- **Hostname (if applicable):** N/A
- **Operating System (guessed):** Ubuntu Linux (Apache 2.4.18, OpenSSH 7.2 → Ubuntu 16.04 era)
- **Ports Open (quick scan):** 80/tcp (HTTP), 2222/tcp (SSH)
- **Ports Open (full scan):** Same as quick scan (80, 2222)

---

## 2. High-Level Recon Summary
*(Update this after initial scans)*
- Potential entry points:
  - HTTP on port 80
  - CGI scripts under `/cgi-bin/`
- Web services:
  - Apache 2.4.18
  - CGI scripts enabled
- Auth portals:
  - None on port 80
  - SSH available on port 2222
- File shares:
  - None
- Remote access:
  - SSH (OpenSSH 7.2)
- Known vulnerable versions:
  - Shellshock (CVE-2014-6271) triggered via `/cgi-bin/user.sh`

---

# 3. Enumeration

## 3.1 Nmap Results

### Quick Scan
Command:
```bash
nmap -sC -sV 10.129.9.31
```

### Full TCP Scan
Command:
```bash
nmap -p- --min-rate 1000 -T4 10.129.9.31
```

**Key findings:**
- Version info:
  - Apache httpd 2.4.18 (Ubuntu)
  - OpenSSH 7.2p2 Ubuntu 4ubuntu2.2
- Interesting scripts:
  - `/cgi-bin/user.sh` found via gobuster
- Authentication required?
  - SSH only (port 2222)
- Default creds possible?
  - Not attempted; not required for foothold

---

## 3.2 Service Enumeration Checklist

### FTP (21)
- Not open

### SSH (2222)
- Version: OpenSSH 7.2p2
- Weak encryption? Not checked
- Default creds tested? No
- Banner info: Ubuntu build

### HTTP/HTTPS (80)
- Web server version: Apache 2.4.18 (Ubuntu)
- Directories found:
  - `/cgi-bin/` (403 but exists)
  - `/index.html`
- Interesting endpoints:
  - `/cgi-bin/user.sh`
- File uploads? No
- Login portals? No
- CMS? None
- Tech stack:
  - Languages/frameworks: Bash CGI script
  - CMS: None

**Tools used:**
- `gobuster`
- `curl`
- `nmap --script http-shellshock`

### SMB (139/445)
- Not open

### SMTP (25)
- Not open

### Databases
- None exposed

---

# 4. Vulnerability Discovery

## 4.1 Web Vulnerabilities
- SQL Injection: Not applicable
- Command Injection: **Yes — Shellshock**
- File Upload: None
- LFI/RFI: None
- Directory Traversal: Not applicable
- SSTI: N/A
- Authentication weaknesses: None
- Session/cookie issues: None
- Client-side / JS leaks: None

## 4.2 Service Vulnerabilities
- Outdated Apache with CGI enabled
- Shellshock via Bash environment processing
- `/cgi-bin/user.sh` directly exploitable

## 4.3 Credentials Found
- None required

---

# 5. Initial Foothold

## 5.1 Access Method
- **Exploit / technique:** Shellshock (CVE-2014-6271)
- **Targeted service:** Apache CGI script at `/cgi-bin/user.sh`
- **Steps taken:**
  - Enumerated `/cgi-bin/`
  - Found `user.sh`
  - Confirmed script output matched Linux `uptime`
  - Tested Shellshock payload via User-Agent header
  - Achieved command execution

## 5.2 Shell Details
- User: `www-data`
- Groups: `www-data`
- Home directory: `/var/www`
- Environment notes: Limited shell, needed TTY upgrade

---

# 6. Privilege Escalation

## 6.1 Local Enumeration

Commands run:
- `id`
- `whoami`
- `uname -a`
- `sudo -l`

**Findings:**
- Kernel version: Ubuntu 16.04-era kernel (uname output not recorded)
- Sudo privileges:
  ```
  (ALL) NOPASSWD: /usr/bin/perl
  ```
- SUID binaries of interest: None needed
- Scheduled tasks: None relevant
- Capabilities: None relevant
- Writable config/script files: No
- Interesting services: None
- Credentials in files: None

## 6.2 Potential Priv-Esc Paths
- Misconfigured sudo: YES — Perl can be run as root → FULL ROOT
- Kernel exploit: Not needed
- SUID abuse: Not needed
- Docker/LXC escape: Not applicable
- Credential reuse: Not applicable

## 6.3 Exploitation
- Final method used:
  ```bash
  sudo perl -e 'exec "/bin/bash";'
  ```
- Root shell obtained: Yes, immediately

---

# 7. Loot / Flags

## 7.1 User Flag
- Path: `/home/shelly/user.txt`
- Command used:
  ```bash
  cat /home/shelly/user.txt
  ```

## 7.2 Root Flag
- Path: `/root/root.txt`
- Command used:
  ```bash
  cat /root/root.txt
  ```

## 7.3 Other Interesting Data
- None required

---

# 8. Post-Exploitation Notes
- Could persistence be added? Yes — via:
  - Adding SSH key to `/root/.ssh/authorized_keys`
  - Modifying /etc/passwd
- Lateral movement possibilities: None (isolated HTB VM)
- Data exfiltration paths: N/A
- High impact in real life:
  - Shellshock on CGI scripts = full server compromise
  - Misconfigured sudo (`perl` NOPASSWD) = instant privilege escalation

---

# 9. Lessons Learned / To Improve
- What slowed me down:
  - Assuming 403 on `/cgi-bin/` meant no access — it actually meant the opposite
- What I missed initially:
  - Need to enumerate inside `/cgi-bin/` using extensions
- Commands I had to look up:
  - Shellshock curl syntax
  - Perl root shell command
- Techniques to practice:
  - CGI enumeration
  - Header injection exploitation
  - Priv-esc via misconfigured sudo
- Things to automate in future:
  - CGI brute forcing script
  - Automatic Shellshock testing script
  - Recon wrappers (already using recon.sh)
