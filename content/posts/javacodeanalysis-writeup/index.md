+++
date = '2026-04-20'
draft = false
title = 'Pico Java Code Analysis writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

BookShelf Pico, my premium online book-reading service. I believe that my website is super secure. I challenge you to prove me wrong by reading the 'Flag' book! Here are the credentials to get you started:

-  Username: "user"
-  Password: "user"

## Identifying the vulnerabilities

Initially I thought this was a tad mode complicated, and since there was a profile picture upload with admin restrictions we'd have to work with that, but it was much simpler.

Looking at the source code, we can see the hardcoded jwt secret "1234" so we can use jwt.io to forge our own bearer token.

Trying to access `/base/books/pdf/5` (the flag pdf path, restricted to admin) by just changing the role would give this strange `Failed to evaluate expression '@bookPdfAccessCheck.verify(#bookId, authentication.principal.grantedAuthorities[0].userId)` error. 

But, I tried modifying the user ID, from 6 (new account) down to 2 (apparently, admin) and the last one loaded successfully - getting us the flag! 

![challenge-screenshot](flag.png#center)
