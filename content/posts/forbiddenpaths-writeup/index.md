+++
date = '2026-04-01'
draft = false
title = 'Pico Forbidden Paths Writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Challenge overview

Can you get the flag? We know that the website files live in /usr/share/nginx/html/ and the flag is at /flag.txt but the website is filtering absolute file paths. Can you get past the filter to read the flag?

---

The / path indeed doesn't work. This is the solution:

![challenge-screenshot](solve.png#center)
