+++
date = '2026-04-15'
draft = false
title = 'Pico findme writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

Help us test the form by submiting the username as test and password as test!

---

This only got a writeup because it took me almost half an hour.

## Identifying the vulnerabilities

Logging in doesn't do much, however by fuzzing we find a /home page, saying *I was redirected here by a friend of mine but i couldnt find anything. Help me search for flags :-)*. It also has a *Search for flags* search bar that does nothing. Parameter fuzzing didn't work either. 

The search bar seems to be doing jack, and the login just isn't functional at all either. That is, until I realized that the password we're supposed to type is *test!*, not *test*. I thought the writer was just being enthusiastic. 

Doing so redirects us to `/next-page/id=cGljb0NURntwcm94aWVzX2Fs`, decoded from base64 to `picoCTF{proxies_al`. Inside that page is the ending of the string, `l_the_way_a0fe074f}`.

This challenge made no sense but whatever, here it is, `picoCTF{proxies_all_the_way_a0fe074f}`.
