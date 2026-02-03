+++
date = '2026-01-31'
draft = false
title = 'CyberEdu imagine-that Writeup'
ShowToc = true
tags = ["CyberEdu", "misc"]
+++

This challenge is part of one of the Unbreakable python labs, and I decided to solve the challenge myself instead of just reading about it. And since it's pwn, should be fun! 

## Challenge overview

Imagine that we are using socat for this one.

---

We get a server to connect to, with `socat`, and we're prompted to give a starting point twice. This however refers to the starting point first and then the ending point, and it prints out the bytes between the two offsets, then asks us for a password. We can only enter numbers from 1 to 10.


## Identifying the vulnerabilities

Leaking from 1 to 10 shows a PNG header, so I'm assuming we need to retrieve this PNG through the leaked bytes.

For some reason *all* the bytes were preceded by the `\x89` byte that is the first PNG header byte. And apparently socat does this thing where our linux `\n` gets converted to its Windows cousin CRLF (`\r\n`).

I made a script to parse the file byte by byte:

```python
from pwn import *


photo = open("photo.png", 'ab')
i=1
j=2

#de fapt noi citim de la starting point la starting point.
#for some reason prima chestie pe care tr trm e 1

#ignoram primul caracter care fsr e x89

photo.write(b'\x89')

while True:
    p = remote('34.40.48.76', 30721)
    p.recvuntil(b": ")
    si = str(i)
    sj = str(j)
    p.sendline(si)
    p.recvline()
    p.recvuntil(b": ")
    p.sendline(sj)
    p.recvline()
    output = p.recvuntil("Enter")
    print(f"am preluat output: {output} am luat {output[1:-7]}")
    if(output[1:-7]==b'\r\n'):
        photo.write(b'\n')
    else:
        photo.write(output[1:-7])
    #dupa primul x89 si pana la \r\nEnter
    #daca primim un \r\n punem doar un \n fiindca win-linux
    i=j
    j=i+1
    p.close()
    
photo.close()
```

We get a QR code, and the scanned data provided is `asdsdgbrtvt4f5678k7v21ecxdzu7ib6453b3i76m65n4bvcx`. We can input that as a password, and we get the flag!

![challenge-screenshot](flag.png#center)









