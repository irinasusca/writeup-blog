+++
date = '2026-03-10'
draft = false
title = 'CyberEdu merry-cemetery Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow"]
+++


## Challenge overview

After doing exactly *two* web challenges, I remembered just how much better pwn is, and if I don't sprinkle in at least another actually fun chall this blog won't last too long. Enough prologue, let's get started.

Rest In Peace Read More: https://en.wikipedia.org/wiki/Merry_Cemetery

The **[challenge](https://app.cyber-edu.co/challenges/23bd9680-abd7-11ea-9682-bf805593105b?tenant=cyberedu)** was initially published at HackTM Quals 2020, organized by WreckTheLine.

This is a reference to Cimitirul Vesel I guess. We're given two files, a `.js` and a `.wasm`, more interestingly. That just means *web assembly*, and it's a sort of binary format.

The `.js` is one of those extremely long files, I mean long enough that reading a book would take less time. And that's coming from me. 

We do have a `var aaaa = "HackTM{REDACTED}";`. It looked like it was prepping for a binary.

![challenge-screenshot](pic1.png#center)

I was right! We're probably just going to need the name of the var.

I used `ghidra` with a WASM extension to decompile the file, and then I looked for strings.

![challenge-screenshot](pic2.png#center)

That's right. A heap menu. I've still got no clue how to solve heap challs so I'm going to leave this for later, and look for a stack one. 

---

## Identifying the vulnerabilities



---


---

## The exploit



---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/babyfmt.py)**.
