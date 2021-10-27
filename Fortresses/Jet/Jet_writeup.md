<h1> Решение Jet с HackThe Box </h1>

1. Запускаем vpn и проверяем выданный ip адрес

sudo openvpn  *.ovpn

ping 10.13.37.10

2. Запускаем nmap для сканирования открытых портов

nmap -sC -sV -Pn -p- -oN nmap.txt 10.13.37.10

команды nmap

-sC -
-sV -
-Pn -
-p- -
-oN -

вывод nmap


2. видим 80 порт переходим 

Изучаем web страничку и получаем первый флаг от Connect


4.  Узнаем информацию о доменном имени через dig 

dig @10.13.37.10 -x 10.13.37.10


;; AUTHORITY SECTION:
37.13.10.in-addr.arpa.  604800  IN      SOA     www.securewebinc.jet. securewebinc.jet. 3 604800 86400 2419200 604800


получаем www.securewebinc.jet добавим в /etc/hosts

sudo nano /etc/hosts
## Jet

10.13.37.10   www.securewebinc.jet 

5. Переходим на сайт и получаем флаг от Digging in...

6. Изучаем исходный код и находим обфусцированный код

http://www.securewebinc.jet/js/secure.js

заходим на сайт и расшифровываем

https://lelinhtinh.github.io/de4js/

переходим на страницу http://www.securewebinc.jet/dirb_safe_dir_rf9EmcEIx/admin/login.php

изучаем код и получаем флаг от Going Deeper





