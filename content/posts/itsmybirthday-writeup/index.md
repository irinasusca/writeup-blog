+++
date = '2026-03-30'
draft = false
title = 'Pico It is my Birthday Writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

Yes. That's right. I'm going back to finish the pico web category, because I feel like the ones I have left on CyberEdu are a little too difficult for the OSCJ which is next month. And pico is, well, pico-leveled.

And I will only have writeups for the pico challenges that take more than two minutes to solve.

## Challenge overview

I sent out 2 invitations to all of my friends for my birthday! I'll know if they get stolen because the two invites look similar, and they even have the same md5 hash, but they are slightly different! You wouldn't believe how long it took me to find a collision. Anyway, see if you're invited by submitting 2 PDFs to my website.

---

As the challenge suggests, we need to upload two pdf files, whose hashes are compared to each other. 

## Identifying the vulnerabilities

Initially I tried a couple php file upload vulnerabilties but it didn't seem like it was working at all. And based on the challenge description it's more likely to do with md5 collision. I found this [article](https://repo.zenk-security.com/Cryptographie%20.%20Algorithmes%20.%20Steganographie/MD5%20Collisions.pdf), also talking about the birthday paradox (so, the title...).

There was a way to build our own, with the hashclash tool, but that meant we needed to build something with cmake and I didn't like that so I thought about finding some preexisting such files:

![challenge-screenshot](stack.png#center)

This thread lead me to [this page with two PostScript documents that produced the same hash](https://web.archive.org/web/20071226014140/http://www.cits.rub.de/MD5Collisions/). The "this is not a pdf error" I escaped by changing the file name to have the .pdf extension and the file type application/pdf. Then, source was revealed to us, with the flag as well:

![challenge-screenshot](flag.png#center)

Honestly I don't know what the point of this challenge was, other than show that there are indeed md5 hash collisions. Which I wouldn't consider "web exploitation". 
