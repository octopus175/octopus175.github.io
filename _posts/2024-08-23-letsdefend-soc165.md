---
title: "SOC165 - Possible SQL Injection Payload Detected"
date: 2024-08-24T00:29:16+00:00
categories:
  - letsdefend
tags:
  - blueteam
  - soc
  - letsdefend
---

# Event Detail

**EventID:**

115

**Event Time:**

Feb. 25, 2022, 11:34 a.m.

**Rule:**

SOC165 - Possible SQL Injection Payload Detected

**Level:**

Security Analyst

**Hostname**

WebServer1001

**Destination IP Address**

172.16.17.18

**Source IP Address**

167.99.169.17

**HTTP Request Method**

GET

**Requested URL**

https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-

**User-Agent**

Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1

**Alert Trigger Reason**

Requested URL Contains OR 1 = 1

**Device Action**

Allowed

# Solution

Checking the network log to learn more about the traffic coming from the source IP `167.99.169.17`
![Log1](/assets/images/2024-08-23-letsdefend-soc165/Pasted_image_20240823201221.png)
There are multiple requests coming from this source, let inspect the Request URL in these requests and see if there are any SQL payload in them.

Here are the Request URLs from the logs in chronological order:
- https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-
- https://172.16.17.18/
- https://172.16.17.18/search/?q=%27
- https://172.16.17.18/search/?q=%27%20OR%20%271
- https://172.16.17.18/search/?q=%27%20OR%20%27x%27%3D%27x
- https://172.16.17.18/search/?q=1%27%20ORDER%20BY%203--%2B

There are total of five HTTP requests that is containing SQL injection payload, all five requests have HTTP Response Status code 500. Therefore we can assume the attack did not go well.
![Log 2](/assets/images/2024-08-23-letsdefend-soc165/Pasted_image_20240823202033.png)
# Playbook Answers

True Positive
- We can confirm there is SQL injection payload in web request from this attacker

Do You Need Tier 2 Escalation? (+5 Point)
- No, because the attack is unsuccessful

Was the Attack Successful? (+5 Point)
- The attack is unsuccessful according to the HTTP response code of the web request

What Is the Direction of Traffic? (+5 Point)
- Internet - Company Network, judging from the Source IP it is coming from external

Check If It Is a Planned Test (+5 Point)
- There is no planned test on that date according to email log.

What Is The Attack Type? (+5 Point)
- SQL injection

Is Traffic Malicious? (+5 Point)
- Yes, it is trying to perform SQL injection