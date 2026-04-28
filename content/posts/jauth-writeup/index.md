+++
date = '2026-04-14'
draft = false
title = 'Pico JAuth writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

Most web application developers use third party components without testing their security. Some of the past affected companies are:

-  Equifax (a US credit bureau organization) - breach due to unpatched Apache Struts web framework CVE-2017-5638
-  Mossack Fonesca (Panama Papers law firm) breach - unpatched version of Drupal CMS used
-  VerticalScope (internet media company) - outdated version of vBulletin forum software used

Can you identify the components and exploit the vulnerable one? The website is running here. Can you become an admin? You can login as test with the password Test123! to get started.


## Identifying the vulnerabilities

Looking at the Cookie structure, we have an `isAdmin=0` part and a JWT token, with an "auth" similar to the "iat" (issued at time) number, an "agent" string, which is the User Agent, and a "role", which is "user".

Meddling with the agent and isAdmin didn't seem to work. There is also an /admin page, but it seems completely identical to the /private path. The challenge hints at a third party component though. Which is totally misleading.

Looking at this [article](https://medium.com/@marwan.alsaifii/jwt-none-algorithm-attack-testing-signature-validation-in-web-applications-b3f5d99b28b0), we can try setting the algorithm to 'none',  crafting our own payload, just by b64 encoding it, and appending another period after it:

![challenge-screenshot](fla.png#center)

There is an alternative to manually doing it, the website [token.dev](https://token.dev/), which looks super helpful!
