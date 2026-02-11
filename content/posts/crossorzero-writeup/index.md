+++
date = '2026-02-05'
draft = false
title = 'CyberEdu cross-or-zero Writeup'
ShowToc = true
tags = ["CyberEdu", "misc"]
+++

## Challenge overview

Can you find the key and the flag? I bet. It is not an encryption. It is ZERO.

---

The code we're given is a perfectly normal string xor alg (I found one on Medium):

![challenge-screenshot](tutty.png#center)

The challenge actually gives us a big hint as to what the key is (ZERO). Yeah, it's literally "0". I converted the base64 to bytes to hex, and used it in an online XOR calculator with the ASCII for "0". 

![challenge-screenshot](find.png#center)

That's it!





