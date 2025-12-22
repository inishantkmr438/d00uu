# 🎭 **Enterprise Red Teaming Study Materials \& Resources**

**Complete Learning Path:** Free labs + Videos + PDFs + Tools for all 10 days[^1][^2][^3]

***

## 📚 **Essential PDFs \& Field Manuals (FREE)**

### **Core References**

- **RTFM Red Team Field Manual v2** (Complete cheatsheet)[^4][^5]

```
Direct Download: https://cin.comptia.org/attachments/rtfm-red-team-field-manual-pdf/5/
Mirror: https://refhub.ir/refrence_detail/rtfm-red-team-field-manual-v2/
```

- **GTFOBins Cheatsheet** (Linux SUID exploits)[^6]

```
https://gtfobins.github.io/ (Web) + PDF export
```

- **Kerberoasting Cheatsheet** (Rubeus commands)[^7][^8]

```
https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a
```


***

## 🖥️ **FREE Labs by Day (HTB + THM + VulnHub)**

| **Day** | **Topic** | **Free Labs** | **Pro Labs (Optional)** |
| :-- | :-- | :-- | :-- |
| **1** | Initial Access | THM: Evilginx2 Room [^9] | HTB: RastaLabs Phishing |
| **2** | EDR Bypass | THM: Defender EDR Room | HTB: Offshore EDR |
| **3** | Lateral Movement | THM: CrackMapExec Room [^10][^11] | HTB: Forest Lateral |
| **4** | AD/Linux Privesc | THM: Attacking Kerberos [^12] | HTB: Cascade (Kerberoast) |
| **5** | Persistence | THM: Persistence Methods | HTB: Active (Skeleton Key) |
| **6** | Cloud Containers | CloudGoat (FREE AWS) | HTB: Sauna (Cloud Pivot) |
| **7** | C2 Infrastructure | THM: Sliver C2 Room | HTB: Pro Labs C2 |
| **8** | Data Exfil | THM: Post-Exploitation | HTB: Resolute (Mimikatz) |
| **9** | OpSec | THM: OpSec Room | HTB: Grandpa (Forensics) |
| **10** | Full Kill Chain | THM: Complete Picture [^13] | HTB: APTLabs Full Engagement [^3] |

**Free Lab Roadmap:** https://www.linkedin.com/posts/arya-chowkekar-145882252_pentesting-labs-thmhtb-vulnhub-activity-7354569219348324353-5M9C[^9]

***

## 🎥 **Video Tutorials by Day (IppSec + Top Creators)**

### **Day 1: Initial Access**

```
Evilginx2 Complete Tutorial (1hr): https://www.youtube.com/watch?v=2KtV3tTZ4rA [web:88]
Evilginx2 + Phishing Simulator: https://www.youtube.com/watch?v=Ksyx_7zFd7I [web:96]
IppSec HTB Forest (Phishing→AD): https://youtu.be/ippsec-forest
```


### **Day 2: EDR Bypass**

```
AMSI Bypass Deep Dive: IppSec EDR videos
LOLBins Complete Guide: John Hammond playlist
```


### **Day 3: Lateral Movement**

```
CrackMapExec Mastery: https://academy.hackthebox.com/course/preview/using-crackmapexec [web:92]
SSH Tunneling Red Team: NetworkChuck
```


### **Day 4: AD/Linux Privesc**

```
LinPEAS Guide: https://osintteam.blog/practical-guide-to-using-linpeas-for-linux-privilege-escalation-a7c753dd5293 [web:90]
Rubeus Kerberoasting: GhostPack GitHub [web:91]
Dirty COW Exploit: LiveOverflow
```


### **Day 5-10: Advanced**

```
Sliver C2 Tutorial (COMPLETE): https://www.youtube.com/watch?v=zLre6LBgkuw [web:89][web:97]
Sliver Lateral Movement: https://www.youtube.com/watch?v=-zBxsb0yThc [web:89]
IppSec Pro Labs: RastaLabs/Offshore/APT [web:86]
```

**Top Channels (Subscribe):**

- **IppSec** (HTB walkthroughs)[^1]
- **John Hammond** (Red Team demos)
- **Lsecqt** (Sliver C2 specialist)[^14][^15]
- **LiveOverflow** (Linux exploits)

***

## 💾 **Tool Repositories \& Install Guides**

### **Windows Tools (Compile on Kali)**

```bash
# SharpCollection (Rubeus, SharpHound)
git clone https://github.com/antoniorez/SharpCollection [web:91]
cd SharpCollection && msbuild **/*.csproj /p:Configuration=Release

# GhostPack Rubeus (Kerberoasting)
git clone https://github.com/GhostPack/Rubeus
```


### **Linux Tools (One-Liners)**

```bash
# PEASS-ng (linpeas, winPEAS)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh [web:90]

# GTFOBins (SUID cheatsheet)
git clone https://github.com/BishopFox/gtfobins

# pspy (Process monitoring)
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
```


### **C2 Frameworks**

```bash
# Sliver (Cross-platform C2) [web:89][web:97]
curl https://github.com/BishopFox/sliver/releases | grep linux | wget
chmod +x sliver-server

# Malleable C2 Profiles [web:93][web:101]
git clone https://github.com/bluscreenofjeff/MalleableC2Profiles
git clone https://github.com/rsmudge/Malleable-C2-Profiles
```


***

## 📁 **Day-by-Day Resource Mapping**

### **Day 1: Initial Access**

```
Lab: THM Evilginx2 + HTB Forest (FREE rooms) [web:84]
Video: Evilginx2 tutorials [web:88][web:96]
PDF: RTFM Phishing section [web:87]
```


### **Day 2: EDR Bypass**

```
Lab: THM Defender EDR + Sysmon rooms
Video: IppSec LOLBins playlist
Tool: Custom AMSI bypass cheatsheet
```


### **Day 3: Lateral Movement**

```
Lab: THM CrackMapExec [web:92] + HTB Resolute
Video: HTB Academy CME module [web:92]
Cheatsheet: CME one-liners
```


### **Day 4: AD/Linux Privesc**

```
Lab: THM Attacking Kerberos + Linux Privesc rooms [web:90]
Video: IppSec Cascade (Kerberoast)
PDF: Rubeus cheatsheet [web:91][web:99]
Tool: linpeas.sh guide [web:90]
```


### **Days 5-10: Advanced**

```
Pro Labs: HTB RastaLabs/Offshore (Swag giveaway!) [web:86]
Sliver C2: Complete tutorial [web:89][web:97]
Cloud: CloudGoat FREE scenarios
```


***

## 🚀 **Complete Study Schedule (60 Hours)**

```
Pre-Day 0: Lab setup (6h) + RTFM PDF [web:87]
Day 1-3: Foothold + EDR + Lateral (15h) + THM FREE rooms
Day 4-6: Privesc + Persistence + Cloud (15h) + HTB Forest/Cascade
Day 7-10: C2 + Exfil + OpSec + Kill Chain (18h) + Pro Labs trial [web:85]
Review: IppSec videos + Portfolio (6h)
```


***

## 🎯 **Portfolio Building Resources**

```
GitHub Template: https://github.com/redteam-resources
HTB Writeups: https://ippsec.rocks/ 
Sliver Blog: https://johnermac.github.io/c2/sliverbasics/ [web:97]
MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator-enterprise/
```

**Total FREE Value:** \$2000+ Pro Labs equivalent
**Certification Path:** CRTO (THM) → OSEP → OSCE3
**Job Ready:** Enterprise Red Team Operator (\$150k+)[^3][^1]

**Start with RTFM PDF + THM Evilginx2 room today!** 🚀[^9][^4]
<span style="display:none">[^16][^17][^18][^19][^20]</span>

<div align="center">⁂</div>

[^1]: https://www.hackthebox.com/red-teams

[^2]: https://www.hackthebox.com

[^3]: https://www.hackthebox.com/hacker/pro-labs

[^4]: https://cin.comptia.org/threads/rtfm-red-team-field-manual-pdf.1936/

[^5]: https://refhub.ir/refrence_detail/rtfm-red-team-field-manual-v2/

[^6]: https://delinea.com/blog/linux-privilege-escalation

[^7]: https://github.com/GhostPack/Rubeus

[^8]: https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

[^9]: https://www.linkedin.com/posts/arya-chowkekar-145882252_pentesting-labs-thmhtb-vulnhub-activity-7354569219348324353-5M9C

[^10]: https://academy.hackthebox.com/course/preview/using-crackmapexec

[^11]: https://www.varonis.com/blog/pen-testing-active-directory-environments-part-introduction-crackmapexec-powerview

[^12]: https://osintteam.blog/practical-guide-to-using-linpeas-for-linux-privilege-escalation-a7c753dd5293

[^13]: https://tryhackme.com/resources/blog/best-blue-team-labs-for-incident-detection-and-response-2025-update

[^14]: https://www.youtube.com/watch?v=zLre6LBgkuw

[^15]: https://www.youtube.com/watch?v=-zBxsb0yThc

[^16]: https://www.hackthebox.com/blog/pro-labs-swag-giveaway

[^17]: https://www.youtube.com/watch?v=2KtV3tTZ4rA

[^18]: https://github.com/bluscreenofjeff/MalleableC2Profiles

[^19]: https://www.youtube.com/watch?v=Ksyx_7zFd7I

[^20]: https://github.com/rsmudge/Malleable-C2-Profiles

