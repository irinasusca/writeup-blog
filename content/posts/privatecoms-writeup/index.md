+++
date = '2026-02-03'
draft = false
title = 'CyberEdu private-coms Writeup'
ShowToc = true
tags = ["CyberEdu", "network"]
+++

## Challenge overview

Există o comunicare scursă în acest fișier pcap. Găsește-o și obține flag-ul.


---

Another challenge I've come across at OSCN, which I didn't solve, because *binwalk* won't show it found files if it can't extract them using `-e` but it *will* find and extract them using more flags.

---

Doing a simple `binwalk -Mve --dd=".*" private-coms.pcap` extracts an audio file reading out the flag. I didn't bother listening to it so I popped it into one of those AI wrapper speech to text apps, and got the text in CAPS so I just lowered it with python.

![challenge-screenshot](flag.png#center)

That's it!





