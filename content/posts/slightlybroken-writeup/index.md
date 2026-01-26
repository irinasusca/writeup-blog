+++
date = '2026-01-13'
draft = false
title = 'CyberEdu slightly-broken Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++

## Challenge overview

For this one, only contact admins for socialising with them. Do not contact them for errors at this challenge.

---


## Identifying the vulnerabilities

We bump into some errors, but look at this section of a response:

![challenge-screenshot](hint.png#center) 

This is part of the Flask/Werkzeug's interactive debugger, and we see it because of the error.

To execute a command, we need the params `__debugger__: 'yes', cmd: 'pinauth', pin: pin, s: SECRET` as json. In a `GET` request, because Workzeug uses `GET`s not `POST`.

If we get the pin right, we get shell, I thought. 

![challenge-screenshot](pin.png#center) 

Looking at this, there is a function to `printpin`. Sounds useful, right? Now let's find the console path, to actually try it.

![challenge-screenshot](console.png#center) 

I got timed out, but at least we confirmed `/console`! We connect to it, and we do get a shell. But it's not as complicated as I thought, we immediately have RCE, and `__import__('os').popen('cat ./flag.txt').read()` prints out our flag.

![challenge-screenshot](flag.png#center) 

I guess that's it!



