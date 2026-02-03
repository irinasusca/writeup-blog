+++
date = '2026-01-28'
draft = false
title = 'CyberEdu password Writeup'
ShowToc = true
tags = ["CyberEdu", "misc"]
+++


## Challenge overview

Can you find the password? I am asking for a friend.

---

We're given a `.pyc` (python bytecode) file. So what we need to do is find a python bytecode decompiler compatible with python version 2.7.

After a bunch of googling I found [this one](https://twy.name/Tools/pyc/). Here is the relevant part of the decompiled code:

![challenge-screenshot](flag.png#center)

The flag is constructed as such: `flag = a + b + c + d + e + f + g + h`. But the chunks are given to us in another order, so we just need to select and concatenate the chunks alphabetically. 

Then we get the flag: `DCTF{09fa4d3142a6a7ab70e9aa1929d62e0805934d86d4b55ea5b1a436b53659eadd}`.









