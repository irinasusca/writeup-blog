+++
date = '2025-12-27'
draft = false
title = 'CyberEdu get-access Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "Format-String"]
+++


## Challenge overview

Can you pwn **[this](https://app.cyber-edu.co/challenges/559a5a60-7f21-11ea-81ac-cdbbeaa73a14?tenant=cyberedu)**?

Very interestingly, this challenge doesn't come with any source files, and we just get a *Username* and *Password* prompt.

![challenge-screenshot](pic1.png#center)

---

## Identifying the vulnerabilities

The first thing I thought about was a buffer overflow.

![challenge-screenshot](pic2.png#center)

The *Username* seemed to read a specific amount of bytes, and the overflow would go into password, and password just didn't crash anything, so it might've been the same situation.

Alright, next idea, since our username is echoed back to us, maybe a format string? 

![challenge-screenshot](pic3.png#center)

Let's go! That's big. Now either the flag is somewhere on the stack, which is highly unlikely based on the challenge ratings, or maybe the proper credentials are somewhere on the stack? Let's try and see what we can leak. I pasted a bunch of `%p`s and we bump into some strings:

![challenge-screenshot](pic4.png#center)

I went up to `%120$p` but the rest seem to be binary addresses. 

Then, I reversed the string we found out 4 bytes by 4 bytes (in case it's a 32 bit binary) and 8 bytes by 8 bytes (if it's a 64 bit binary), and the most likely option I found looked like this:

![challenge-screenshot](pic6.png#center)

The challenge came out in 2019, we have the string *password* and *awesome*, so we just need to figure out what's what.

`TH0S0STH44W3S0M3P4sSw0RDF1RY0UDCTF2019_` (*This is the awesome password for you dctf 2019*)

That underscore might be actually placed like this: `_DCTF2019`. So let's try credentials

`DCTF2019` - `TH0S0STH44W3S0M3P4sSw0RDF1RY0U`

![challenge-screenshot](pic7.png#center)

Well... that's not right...

I ended up trying all of these `username:password` combinations for these usernames: *DCTF2019*, *DCTF2019_*, *_DCTF2019*, *Y0UDCTF2019_*, *Y0U*, *You*, *first*, *admin* and these passwords: *P4sSw0RDF1RY0UDCTF2019_*, *TH0S0STH44W3S0M3P4sSw0RDF1RY0U_*, *TH0S0STH44W3S0M3P4sSw0RDF1RY0U*, *TH0S0STH44W3S0M3P4sSw0RDF1RY0UDCTF2019_*... you get the gist.

At this point I thought we were missing something and I looked up to `%250$p`, and I found another string, `iÎb3686`, but it's most likely junk...

So I decided to look at the leaked string again: 

![challenge-screenshot](pic4.png#center)

Do you see that? We missed the beginning of the string: the `_$`. I assumed it was garbage at first, but it's worth a try.

So our string should look like this: `$_TH0S0STH44W3S0M3P4sSw0RDF1RY0UDCTF2019_`

And finally, we get the flag... to be frank, I really didn't like this challenge. Trying all of those usernames and passwords really drove me crazy.

![challenge-screenshot](pic8.png#center)


