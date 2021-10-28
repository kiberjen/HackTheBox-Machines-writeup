<h1> Решение Jet с HackTheBox </h1>
<ol>
<li> Запускаем vpn и проверяем выданный ip адрес </li>

 sudo openvpn  *.ovpn

 ping 10.13.37.10 

[![ping 10.13.37.10](/Fortresses/Jet/.image/1_ping.png "ping 10.13.37.10")](https://github.com/kiberjen/HackTheBox-Machines-writeup/blob/main/Fortresses/Jet/.image/1_ping.png)

<li> Запускаем nmap для сканирования открытых портов </li>

nmap -F 10.13.37.10


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

