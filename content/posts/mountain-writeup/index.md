+++
date = '2026-01-30'
draft = false
title = 'CyberEdu mountain Writeup'
ShowToc = true
tags = ["CyberEdu", "misc"]
+++


## Challenge overview

Take a look at those mountains!

---

We get a zip file I ran `binwalk -Me --dd=".*"` filename on (just does it recursively). We get a PNG file which has a barely visible flag in the top left which I noticed waay to late;  I opened a web version of gimp, turned off the green and blue, and the flag became just visible enough to be transcribed.

![challenge-screenshot](flag.png#center)

Here it is: `DCTF{157d2d840f229720e7f8082dd4468a8583fb348ebf2cb38456147dc046ff942d}`










