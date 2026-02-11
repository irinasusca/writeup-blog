+++
date = '2026-02-11'
draft = false
title = 'CyberEdu online-encryption Writeup'
ShowToc = true
tags = ["CyberEdu", "network"]
+++

## Challenge overview

This is why you should not trust online encryption for your most awesome secrets.

---

After extracting all the HTTP objects, I noticed the `PKCS5` files (from 1 to 30, and only the even ones) contained a `plaintext=(14chars)`. I moved them all to a separate folder and did the following, to extract that plainText parameter:

`grep -E -o 'plainText=[A-Za-z0-9]{14}' * > plaintext.txt`

`grep -o -E '[a-zA-Z0-9]{14}$' plaintext.txt`

The exception was the last part, `019726}`, which was in PKCS5(18) with an extra `%3D%3D` to the parameter value, and also 20, which had a 'ha ha ha' in it (very funny).

Here I decoded them from b64 and then ROT13:

![challenge-screenshot](ok.png#center)
![challenge-screenshot](twtf.png#center)
![challenge-screenshot](exception.png#center)

And the final flag was `ECSC{dd545fbf12fd608daa8c201f50f95c8520bec9f744a3573b1dc0bc53ce019726}`.


