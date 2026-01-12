+++
date = '2026-01-10'
draft = false
title = 'CyberEdu file-crawler Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++

I was stuck between starting to study heap properly or keep doing web challenges, and I guess here we are.

## Challenge overview

Find the vulnerability and get the flag. The flag is located in a temporary folder.

---

## Identifying the vulnerabilities

I inspected the original GET request with burp: 

![challenge-screenshot](pic1.png#center) 

Since the flag is located in a "temporary folder", my first guess was `/tmp/flag`. I tried /local, and we get a TRY HARDER message.

I added the param at GET `/local?image_name=/tmp/flag`, and we immediately get the flag back.

![challenge-screenshot](flag.png#center)

That's it.

---






