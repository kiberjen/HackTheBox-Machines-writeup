<h1> Решение Jet с HackTheBox </h1>
<ol>
<li> Запускаем vpn и проверяем выданный ip адрес </li>
<br>
 sudo openvpn  *.ovpn

 ping 10.13.37.10 

[![ping 10.13.37.10](/Fortresses/Jet/image/1_ping.png "ping 10.13.37.10")](https://github.com/kiberjen/HackTheBox-Machines-writeup/blob/main/Fortresses/Jet/image/1_ping.png)

<li> Запускаем nmap для сканирования открытых портов </li>

nmap -F 10.13.37.10

вывод nmap

```
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http
```
[![nmap -F 10.13.37.10](/Fortresses/Jet/image/2_nmap.png "nmap -F 10.13.37.10")](https://github.com/kiberjen/HackTheBox-Machines-writeup/blob/main/Fortresses/Jet/image/2_nmap.png)

nmap -sS -A -p- -oN nmap.txt 10.13.37.10

команды nmap
```
-F -
-sS -
-A -
-p- -
-oN -
```
вывод nmap

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 62:f6:49:80:81:cf:f0:07:0e:5a:ad:e9:8e:1f:2b:7c (RSA)
|   256 54:e2:7e:5a:1c:aa:9a:ab:65:ca:fa:39:28:bc:0a:43 (ECDSA)
|_  256 93:bc:37:b7:e0:08:ce:2d:03:99:01:0a:a9:df:da:cd (ED25519)
53/tcp   open  domain   ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp   open  http     nginx 1.10.3 (Ubuntu)
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: SecureWeb Inc. - We design secure websites
5555/tcp open  freeciv?
| fingerprint-strings: 
|   DNSVersionBindReqTCP, GenericLines, GetRequest, adbConnect: 
|     enter your name:
|     [31mMember manager!
|     edit
|     change name
|     gift
|     exit
|   NULL: 
|     enter your name:
|   SMBProgNeg: 
|     enter your name:
|     [31mMember manager!
|     edit
|     change name
|     gift
|     exit
|     invalid option!
|     [31mMember manager!
|     edit
|     change name
|     gift
|     exit
|     invalid option!
|     [31mMember manager!
|     edit
|     change name
|     gift
|     exit
|     invalid option!
|     [31mMember manager!
|     edit
|     change name
|     gift
|     exit
|     invalid option!
|     [31mMember manager!
|     edit
|     change name
|     gift
|     exit
|     invalid option!
|     [31mMember manager!
|     edit
|     change name
|     gift
|     exit
|     invalid option!
|     [31mMember manager!
|     edit
|     change name
|     gift
|     exit
|     invalid option!
|     [31mMember manager!
|     edit
|     change name
|     gift
|     exit
|     invalid option!
|     [31mMember manager!
|     edit
|     change name
|     gift
|     exit
|_    invalid option!
7777/tcp open  cbt?
| fingerprint-strings: 
|   Arucer, DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, Socks5, X11Probe: 
|     --==[[ Spiritual Memo ]]==--
|     Create a memo
|     Show memo
|     Delete memo
|     Can't you read mate?
|   NULL: 
|     --==[[ Spiritual Memo ]]==--
|     Create a memo
|     Show memo
|_    Delete memo
```


<li> видим 80 порт переходим </li>

Изучаем web страничку и получаем первый флаг от Connect


<li> Узнаем информацию о доменном имени через dig </li>

dig @10.13.37.10 -x 10.13.37.10

```
;; AUTHORITY SECTION:
37.13.10.in-addr.arpa.  604800  IN      SOA     www.securewebinc.jet. securewebinc.jet. 3 604800 86400 2419200 604800
```

получаем www.securewebinc.jet добавим в /etc/hosts

sudo nano /etc/hosts
```
## Jet

10.13.37.10   www.securewebinc.jet 
```

<li>Переходим на сайт и получаем флаг от Digging in... </li>

<li> Изучаем исходный код и находим обфусцированный код </li>

http://www.securewebinc.jet/js/secure.js

заходим на сайт и расшифровываем

https://lelinhtinh.github.io/de4js/

переходим на страницу http://www.securewebinc.jet/dirb_safe_dir_rf9EmcEIx/admin/login.php

изучаем код и получаем флаг от Going Deeper

<li> </li>

</ol>

