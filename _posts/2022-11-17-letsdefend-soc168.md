---
title: "SOC168 - Whoami Command Detected in Request Body"
date: 2022-11-17T18:41:44+00:00	
categories:
  - letsdefend
tags:
  - blueteam
  - soc
  - letsdefend
---

# Event Detail
```txt
EventID: 118
Event Time: Feb. 28, 2022, 4:12 a.m.
Rule: SOC168 - Whoami Command Detected in Request Body
Level: Security Analyst
Hostname WebServer1004
Destination IP Address 172.16.17.16
Source IP Address 61.177.172.87
HTTP Request Method POST
Requested URL https://172.16.17.16/video/
User-Agent Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)
Alert Trigger Reason Request Body Contains whoami string
Device Action Allowed
```


# Investigation

Attacker is trying to exploit the parameter "s" by sending different payload which contains system command like ls, cat, uname and whoami.

All of these request is getting HTTP Response Status 200 and the Response Size is non-zero, here is one of the dangerous request where attacker is trying to read the shadow file that contains user creds.

![Log1](/assets/images/Pasted_image_20221112005247.png)

More request log:

![Log 2](/assets/images/Pasted_image_20221112005519.png)

Looking at the Response Size of the request, I believe the web server is returning the corresponding file that the attacker request.

Let's look at the target web server and to confirm if the attacker have remote command execution:

![Log 3](/assets/images/Pasted_image_20221112005802.png)

it is confirm that the attacker were able to execute system command on the target server, we don't see any connection from the attacker ip address. However, since the attacker has the ability to execute command on target, it is best for us to quarantine that machine

![Log 4](/assets/images/Pasted_image_20221112010151.png)

Checking the mailbox, there is no planned scanning from the pentester we hire.

Lucky for me, got all correct answer

![Result](/assets/images/Pasted_image_20221112010409.png)
