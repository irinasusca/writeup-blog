+++
date = '2026-04-16'
draft = false
title = 'Pico Sql Map 1 writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

You’ve been hired by a shadowy group of pentesters who love a good puzzle. The system looks ordinary, but appearances lie. Somewhere inside, sloppy code and legacy hashing practices left a tiny....

---

I finally stumbled upon the newer AI slop challenges from pico, presenting itself immediately through the page long description. 

## Identifying the vulnerabilities

We can register our own user and search for *flags*. Just writing Flag immediately shows a bunch of fake results; I tried running sqlmap as suggested by the challenge name, but it kept breaking, so I got annoyed and wrote my stuff manually.

`'UNION SELECT name,name FROM sqlite_master--` showed us all the tables, and `'UNION SELECT username,password FROM users--` got us the hashed credentials. The hashes are md5 format, so we can just use hashcat for this.

The command I ran was `hashcat -a 0 -m 0 hashadmin.txt /usr/share/wordlists/rockyou.txt`, `-a 0` for dictionary attack and `-m 0` for md5. The challege hints suggest using [CrackStation](https://crackstation.net/). I ran both of them to test which is better; They both found the same thing, but the website did it in .5 second while hashcat took a minute.

Anyways, the account cracked was ctf-player:dyesebel.
