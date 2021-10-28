<h1> Решение Jet с HackTheBox </h1>
<ol>
<li> Запускаем vpn и проверяем выданный ip адрес </li>

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
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5555-TCP:V=7.91%I=7%D=10/28%Time=617AF27E%P=x86_64-pc-linux-gnu%r(N
SF:ULL,11,"enter\x20your\x20name:\n")%r(GenericLines,63,"enter\x20your\x20
SF:name:\n\x1b\[31mMember\x20manager!\x1b\[0m\n1\.\x20add\n2\.\x20edit\n3\
SF:.\x20ban\n4\.\x20change\x20name\n5\.\x20get\x20gift\n6\.\x20exit\n")%r(
SF:DNSVersionBindReqTCP,63,"enter\x20your\x20name:\n\x1b\[31mMember\x20man
SF:ager!\x1b\[0m\n1\.\x20add\n2\.\x20edit\n3\.\x20ban\n4\.\x20change\x20na
SF:me\n5\.\x20get\x20gift\n6\.\x20exit\n")%r(SMBProgNeg,9D1,"enter\x20your
SF:\x20name:\n\x1b\[31mMember\x20manager!\x1b\[0m\n1\.\x20add\n2\.\x20edit
SF:\n3\.\x20ban\n4\.\x20change\x20name\n5\.\x20get\x20gift\n6\.\x20exit\ni
SF:nvalid\x20option!\n\x1b\[31mMember\x20manager!\x1b\[0m\n1\.\x20add\n2\.
SF:\x20edit\n3\.\x20ban\n4\.\x20change\x20name\n5\.\x20get\x20gift\n6\.\x2
SF:0exit\ninvalid\x20option!\n\x1b\[31mMember\x20manager!\x1b\[0m\n1\.\x20
SF:add\n2\.\x20edit\n3\.\x20ban\n4\.\x20change\x20name\n5\.\x20get\x20gift
SF:\n6\.\x20exit\ninvalid\x20option!\n\x1b\[31mMember\x20manager!\x1b\[0m\
SF:n1\.\x20add\n2\.\x20edit\n3\.\x20ban\n4\.\x20change\x20name\n5\.\x20get
SF:\x20gift\n6\.\x20exit\ninvalid\x20option!\n\x1b\[31mMember\x20manager!\
SF:x1b\[0m\n1\.\x20add\n2\.\x20edit\n3\.\x20ban\n4\.\x20change\x20name\n5\
SF:.\x20get\x20gift\n6\.\x20exit\ninvalid\x20option!\n\x1b\[31mMember\x20m
SF:anager!\x1b\[0m\n1\.\x20add\n2\.\x20edit\n3\.\x20ban\n4\.\x20change\x20
SF:name\n5\.\x20get\x20gift\n6\.\x20exit\ninvalid\x20option!\n\x1b\[31mMem
SF:ber\x20manager!\x1b\[0m\n1\.\x20add\n2\.\x20edit\n3\.\x20ban\n4\.\x20ch
SF:ange\x20name\n5\.\x20get\x20gift\n6\.\x20exit\ninvalid\x20option!\n\x1b
SF:\[31mMember\x20manager!\x1b\[0m\n1\.\x20add\n2\.\x20edit\n3\.\x20ban\n4
SF:\.\x20change\x20name\n5\.\x20get\x20gift\n6\.\x20exit\ninvalid\x20optio
SF:n!\n\x1b\[31mMember\x20manager!\x1b\[0m\n1\.\x20add\n2\.\x20edit\n3\.\x
SF:20ban\n4\.\x20change\x20name\n5\.\x20get\x20gift\n6\.\x20exit\ninvalid\
SF:x20option!\n\x1b")%r(adbConnect,63,"enter\x20your\x20name:\n\x1b\[31mMe
SF:mber\x20manager!\x1b\[0m\n1\.\x20add\n2\.\x20edit\n3\.\x20ban\n4\.\x20c
SF:hange\x20name\n5\.\x20get\x20gift\n6\.\x20exit\n")%r(GetRequest,63,"ent
SF:er\x20your\x20name:\n\x1b\[31mMember\x20manager!\x1b\[0m\n1\.\x20add\n2
SF:\.\x20edit\n3\.\x20ban\n4\.\x20change\x20name\n5\.\x20get\x20gift\n6\.\
SF:x20exit\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port7777-TCP:V=7.91%I=7%D=10/28%Time=617AF27E%P=x86_64-pc-linux-gnu%r(N
SF:ULL,5D,"\n--==\[\[\x20Spiritual\x20Memo\x20\]\]==--\n\n\[1\]\x20Create\
SF:x20a\x20memo\n\[2\]\x20Show\x20memo\n\[3\]\x20Delete\x20memo\n\[4\]\x20
SF:Tap\x20out\n>\x20")%r(X11Probe,71,"\n--==\[\[\x20Spiritual\x20Memo\x20\
SF:]\]==--\n\n\[1\]\x20Create\x20a\x20memo\n\[2\]\x20Show\x20memo\n\[3\]\x
SF:20Delete\x20memo\n\[4\]\x20Tap\x20out\n>\x20Can't\x20you\x20read\x20mat
SF:e\?")%r(Socks5,71,"\n--==\[\[\x20Spiritual\x20Memo\x20\]\]==--\n\n\[1\]
SF:\x20Create\x20a\x20memo\n\[2\]\x20Show\x20memo\n\[3\]\x20Delete\x20memo
SF:\n\[4\]\x20Tap\x20out\n>\x20Can't\x20you\x20read\x20mate\?")%r(Arucer,7
SF:1,"\n--==\[\[\x20Spiritual\x20Memo\x20\]\]==--\n\n\[1\]\x20Create\x20a\
SF:x20memo\n\[2\]\x20Show\x20memo\n\[3\]\x20Delete\x20memo\n\[4\]\x20Tap\x
SF:20out\n>\x20Can't\x20you\x20read\x20mate\?")%r(GenericLines,71,"\n--==\
SF:[\[\x20Spiritual\x20Memo\x20\]\]==--\n\n\[1\]\x20Create\x20a\x20memo\n\
SF:[2\]\x20Show\x20memo\n\[3\]\x20Delete\x20memo\n\[4\]\x20Tap\x20out\n>\x
SF:20Can't\x20you\x20read\x20mate\?")%r(GetRequest,71,"\n--==\[\[\x20Spiri
SF:tual\x20Memo\x20\]\]==--\n\n\[1\]\x20Create\x20a\x20memo\n\[2\]\x20Show
SF:\x20memo\n\[3\]\x20Delete\x20memo\n\[4\]\x20Tap\x20out\n>\x20Can't\x20y
SF:ou\x20read\x20mate\?")%r(HTTPOptions,71,"\n--==\[\[\x20Spiritual\x20Mem
SF:o\x20\]\]==--\n\n\[1\]\x20Create\x20a\x20memo\n\[2\]\x20Show\x20memo\n\
SF:[3\]\x20Delete\x20memo\n\[4\]\x20Tap\x20out\n>\x20Can't\x20you\x20read\
SF:x20mate\?")%r(RTSPRequest,71,"\n--==\[\[\x20Spiritual\x20Memo\x20\]\]==
SF:--\n\n\[1\]\x20Create\x20a\x20memo\n\[2\]\x20Show\x20memo\n\[3\]\x20Del
SF:ete\x20memo\n\[4\]\x20Tap\x20out\n>\x20Can't\x20you\x20read\x20mate\?")
SF:%r(RPCCheck,71,"\n--==\[\[\x20Spiritual\x20Memo\x20\]\]==--\n\n\[1\]\x2
SF:0Create\x20a\x20memo\n\[2\]\x20Show\x20memo\n\[3\]\x20Delete\x20memo\n\
SF:[4\]\x20Tap\x20out\n>\x20Can't\x20you\x20read\x20mate\?")%r(DNSVersionB
SF:indReqTCP,71,"\n--==\[\[\x20Spiritual\x20Memo\x20\]\]==--\n\n\[1\]\x20C
SF:reate\x20a\x20memo\n\[2\]\x20Show\x20memo\n\[3\]\x20Delete\x20memo\n\[4
SF:\]\x20Tap\x20out\n>\x20Can't\x20you\x20read\x20mate\?")%r(DNSStatusRequ
SF:estTCP,71,"\n--==\[\[\x20Spiritual\x20Memo\x20\]\]==--\n\n\[1\]\x20Crea
SF:te\x20a\x20memo\n\[2\]\x20Show\x20memo\n\[3\]\x20Delete\x20memo\n\[4\]\
SF:x20Tap\x20out\n>\x20Can't\x20you\x20read\x20mate\?");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=10/28%OT=22%CT=1%CU=42422%PV=Y%DS=2%DC=T%G=Y%TM=617AF3
OS:4E%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=8)SE
OS:Q(SP=F4%GCD=1%ISR=10F%TI=Z%TS=8)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54
OS:DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=7120%W2=7120%
OS:W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC
OS:=Y%Q=)ECN(R=N)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=
OS:Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A
OS:=S+%F=AR%O=%RD=0%Q=)T5(R=N)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:6(R=N)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)U1(R=N)IE(R=Y%DFI=N%T
OS:=40%CD=S)IE(R=N)

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

