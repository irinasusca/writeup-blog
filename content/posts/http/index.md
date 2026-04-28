+++
date = '2026-04-16'
draft = false
title = 'http'
ShowToc = true
tags = ["Materials"]
+++


## Why

idfk

## headers

Here are some of the headers that I didn't really have much of a clue about what they actually meant.

- **X-Forwarded-For**: the originating IP address of a client connecting to a web server through a HTTP proxy. Basically saying, hey, I'm a proxy forwarding this for this guy!

- **X-Forwarded-Host**: the domain originally requested by the user.

- **Forwarded**: the official version to replace the previous ones, looks like this: *by=<ip>; for=<ip>; host=<ip>; proto=http*

There are also some custom specific headers, like these ones used by nginx or cloudflare or whatever.

- **X-Real-IP**: nginx, single client IP.

- **X-Client-IP**: older X-Forwarded-For.

- **True-Client-IP**: akamai and cloudflare

- **X-Originating-IP**

