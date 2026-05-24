+++
date = '2026-05-09'
draft = false
title = 'tunneling'
ShowToc = true
tags = ["Materials"]
+++


## Why

Sometimes you might find yourself needing a tunnel...

![challenge-screenshot](tunnel.gif#center)

---

These are ***ALL FREE*** options, because I refuse to pay actual money for this crap.

## http

If you need a HTTP tunnel, there are a couple of pretty easy ways to do it.

Before you do anything, you can open a local port with `python`:

```bash
python3 -m http.server 8000
```

First, there's `ngrok`; Super easy to use, but it's quite annoying because of the warning page that messes up about all your XSS attempts.

```bash
ngrok http 6969
```

My personal favorite is `cloudflared`; I'm pretty sure you need an account for this, but it's fairly quick to set up, and worth it.

```bash
cloudflared tunnel --url localhost:8000
```

Keep in mind these are *https* servers though.

## tcp

I found a great free tool for this called [bore](https://github.com/ekzhang/bore) which you can just install with `cargo` quick enough.

First, you set up a local listener:

```bash
nc -lvnp 1337
```

Then, just run this command:

```bash
bore local 1337 --to bore.pub
```

This will host a tunnel at a random port of `bore.pub`. To actually use the reverse shell in this case, just keep in mind you have to write to your local listener, not the tunnel :)
