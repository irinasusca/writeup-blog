+++
date = '2026-01-30'
draft = false
title = 'CyberEdu pawn-shop Writeup'
ShowToc = true
tags = ["CyberEdu", "misc"]
+++


## Challenge overview

Se spune ca fericirea nu poate fi cumparata. Acesta este cazul si pentru acest magazin. Trebuie sa gasesti o vulnerabilitate in aceasta aplicatie si sa recuperezi secretul.

---

This was one of the challenges from OSC 2025 county phase, I remember it, so let's quickly solve this.

## Identifying the vulnerabilities

Trying to access the flag, we get this response:

![challenge-screenshot](req.png#center)

Adding the allowed Origin as a HTTP Header, we get the flag.

![challenge-screenshot](flag.png#center)

And here is the correct answer to the question:

![challenge-screenshot](grila.png#center)









