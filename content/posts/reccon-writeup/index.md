+++
date = '2026-01-07'
draft = false
title = 'CyberEdu reccon Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++


## Challenge overview

I heard you like memes, so we had a **[surprise](https://app.cyber-edu.co/challenges/723d67c0-03f9-11ec-9975-d157ab5ef7a5?tenant=cyberedu)** for you. Enjoy !!

Today is a big day. Finally solving a non-pwn challenge! Let's see if I can still remember how burpsuite works.

---

## Identifying the vulnerabilities

First I ran `ffuf -u http://34.159.240.221:31548/FUZZ -w /usr/share/wordlists/dirb/common.txt`, but only found .hta, .htaccess, .htpasswd and index.php.

![challenge-screenshot](stupid.png#center)

This is all. I ffufed for /images_FUZZ too, but nothing.

I did `exiftool`, `strings`, looked at it in hex, `steghide`, `stegseek`, just about everything. 

I used about three other fuzzing tools, and all of them gave the same thing.

![challenge-screenshot](gobuster.png#center)

Gobuster even told us that everything at /index.php/ was giving code 200. I felt like I wasn't solving this so I searched it online. Apparently, you're supposed to find a /login, that with the parameter `m` with any value would give the flag, and other *letters* just say Try harder.

It worked without the `/login`, though. So just the parameters.

![challenge-screenshot](a.png#center)

![challenge-screenshot](m.png#center)

I guess there's the flag. 

---

