+++
date = '2026-04-01'
draft = false
title = 'Pico Web Gauntlet 2 & 3 Writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Challenge overview

This website looks familiar... Log in as admin.

---

We need to log in as admin, through SQLi, and we have 5 rounds to beat.

## Identifying the vulnerabilities

This time I realised the filters were actually spelled out in filter.php; oops.

Round 1 filters: `or and true false union like = > < ; -- /* */ admin`

I struggled with this for about two hours until I gave up and found [this solution](https://medium.com/@ahmednarmer1/ctf-day-50-ef758c06b0e7):

- `ad'||'min`, just like the first Web Gauntlet challenge

- `password="a' IS NOT 'b"`

Pretty clever, I had no idea that `IS NOT` existed so maybe I need to brush up on my sql. Anyways, the flag was `picoCTF{0n3_m0r3_t1m3_85a265ac}`.

And also, this is the solution to the third one, Web Gauntlet 3, `picoCTF{k3ep_1t_sh0rt_d0339730}`.
