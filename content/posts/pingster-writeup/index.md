+++
date = '2026-01-18'
draft = true
title = 'CyberEdu pingster Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++

I didn't solve this because the stupid chall is broken but I'm leaving this up as draft.

## Challenge overview

Like a DOM with a trick.

## Identifying the vulnerabilities

This website lets us input a domain via POST, then pings it, to check whether the servers are down or not. I entered my ngrok, got an error, and I noticed the error message is passed as a parameter `?error=text`. So maybe we can get a script to execute. 

![challenge-screenshot](xss.png#center)

But our input got sanitized. I tried gobuster but I got rate-limited. Trying to send a `domain=facebook.com` got us a `connect ECONNREFUSED 127.0.0.1:6379`, so just not sending the http part of it. And that's valid for all domains. But even without the protocol, it wouldn't *actually* ping my dummy websites.

![challenge-screenshot](redis.png#center)

So, local network. TCP SSRF with redis? It looks like we have some sort of blacklist, of `% / ! # ( : ; ` among others which will just immediately say Invalid Website. So no `file://` shenanigans either.

I found some resources about redis vulnerabilities [here](https://angelica.gitbook.io/hacktricks/network-services-pentesting/6379-pentesting-redis).

I'm thinking now, since there is an error that's causing it not to connect to anything, can we send a payload that fixes it?

Sending just 'facebook', their ip, localhost all Found. `Redirecting to <a href="/ping/843b5e23223e7d516dd916b8cef7fc6c">/ping/843b5e23223e7d516dd916b8cef7fc6c`

Capital letters are also blacklisted so cant do PING just ping.
 
DOM document object model. With a trick. What trick could it be?

Let me tell you what trick! The fucking challenge was broken for days! And now suddenly .com sites work, they even return that they're up! I genuinely wasted so much time on this!

```html
        The website at
        <a href="https://facebook.com/" target="_blank">
          <strong>facebook.com</strong>
        </a> is up!
        Load time: 2.107 seconds
```
        
Suddenly it works with my ngrok, pipedream, cloudflared. Fuck you cyberedu.

It did a `GET /test.php` with `User-Agent : jsdom/16.5.3`. So maybe it looks something like:

```js
const { JSDOM } = require("jsdom");
await JSDOM.fromURL("https://" + domain + "/test.php");
```
 
I struggled with payloads in a `https://mycloudflare/test.php` but nothing really worked, I even found some CVE I thought might apply, [CVE-2021-20066](https://github.com/jsdom/jsdom/issues/3124), but that wasn't it. I ended up searching for a writep, and I was right about it being a `jsdom` vulnerability. Here is the [writeup](https://blog.kuhi.to/unbreakable-2021-individual-writeup#pingster).

The CVE *this* guy found was [here](https://github.com/jsdom/jsdom/issues/2729).

This line - `const outerRealmFunctionConstructor = Node.constructor;` - escapes the HTML sandbox. Because Node exists in the DOM environment, and Node.constructor is a function that comes from Node.js, which runs on the server (that's the whole difference between js and node). So now, we're executing inside the server.

Even after this I struggled a while - if I serve a test.php file, it thinks our server is down. But it's still trying to `GET /flag.php`.  

Then the chall just broke AGAIN.

![challenge-screenshot](broke.png#center)



 
 

![challenge-screenshot](flag.png#center)

---




