+++
date = '2026-02-10'
draft = false
title = 'CyberEdu universe Writeup'
ShowToc = true
tags = ["CyberEdu", "misc"]
+++

## Challenge overview

What is the technique name? What is the flag?

---

I took a bunch of images with all the steps while solving this challenge, so I'll just let those speak for me. (Also, for the stereogram - stegsolve):

![challenge-screenshot](p1.png#center)

![challenge-screenshot](p12.png#center)

![challenge-screenshot](p22.png#center)

`sed 's/%20/\n/g' part2.txt -i`

![challenge-screenshot](p2.png#center)

Felt really smart for figuring out it was b32.

![challenge-screenshot](p23.png#center)

Here is that stegsolve stereogram solver I mentioned.

![challenge-screenshot](p3.png#center)

And the full flag is ctf{6da4a51e2ee5437bece4699edf7728ae26e6684abe8711b85b034902a920a775}! 
