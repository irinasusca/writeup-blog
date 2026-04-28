+++
date = '2026-03-31'
draft = false
title = 'Pico JaWT Writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Challenge overview

Check the admin scratchpad!

---

We can log in, based on a username, but we aren't allowed to write admin. The challenge also hints us with "You can use your name as a log in, because that's quick and easy to remember! If you don't like your name, use a short and cool one like *https://github.com/magnumripper/JohnTheRipper*. 

## Identifying the vulnerabilities

I'm guessing we need to brute force the JWT secret and sign our own admin cookie. I searched it on google and found this [portswigger lab](https://portswigger.net/web-security/jwt#brute-forcing-secret-keys-using-hashcat) saying to use `hashcat -a 0 -m 16500 <jwt> <wordlist>`. Obviously that worked:

![challenge-screenshot](cracked.png#center)

So using [jwt.io](https://www.jwt.io/) I encoded a jwt with the data being `"user":"admin"`, logged in with it, and got the flag: `picoCTF{jawt_was_just_what_you_thought_bbb82bd4a57564aefb32d69dafb60583}`.
