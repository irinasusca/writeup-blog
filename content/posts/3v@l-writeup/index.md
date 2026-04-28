+++
date = '2026-04-20'
draft = false
title = 'Pico 3v@l writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

ABC Bank's website has a loan calculator to help its clients calculate the amount they pay if they take a loan from the bank. Unfortunately, they are using an eval function to calculate the loan. Bypassing this will give you Remote Code Execution (RCE). Can you exploit the bank's calculator and read the flag?

## Identifying the vulnerabilities

I hate command injection

We're supposed to bypass this regex: `r'0x[0-9A-Fa-f]+|\\u[0-9A-Fa-f]{4}|%[0-9A-Fa-f]{2}|\.[A-Za-z0-9]{1,3}\b|[\\\/]|\.\.'`. I found this nice [website](https://regex101.com/r/M32bCK/1) that decodes this regex so it's easier to understand. 

Initially I thought we had to comply to this regex, but we actually need to avoid it, oops. Anyways, I tried doing it using only my brain but that didn't work out that well, so I started looking for a tool, and found [this gem](https://github.com/Froezens/Python-Blacklist-Breaker/tree/main). We can specify both a regex and blacklist. And it worked! 

![challenge-screenshot](flag.png#center)




