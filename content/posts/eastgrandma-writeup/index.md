+++
date = '2026-02-05'
draft = false
title = 'CyberEdu east-grandma Writeup'
ShowToc = true
tags = ["CyberEdu", "forensics"]
+++


## Challenge overview

Investigate the wants of the most expensive club on the east coast.

---

We receive a picture called camashadefortza.jpg which we can extract a zip file from using `binwalk -Mve --dd=".*"`. The zip file is encrypted, and of 7z format, so we can try using john the ripper, I guess.

For that we need to prep the format, but `zip2john` won't work, since this is a 7z. So let's grab a tool for that.

From the John the Ripper repo, we have [this .pl file](https://github.com/openwall/john/blob/bleeding-jumbo/run/7z2john.pl).

Then we run `./7z2john.pl 324B6 > hash.txt` and `john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`. It found the password in a couple of minutes because of my shitty VM, and I ran `john --show hash.txt` to see the password, which was 'passwordpassword'. Then, we just extract the file.

The file turns out to be a boot sector or something, and looking for a flag with strings inside:

![challenge-screenshot](flog.png#center)

I thought this was some sort of try harder for half an hour and I felt pretty stupid about it but I realised those were *instructions*. Yeah, so I used cyberchef and got the following flag (which worked): `ctf{44ad656b71865ac4ad2e485cfbce17423e0aa0bcd9bcdf2d98a1cb1048cf4f0e}`.
