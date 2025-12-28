+++
date = '2025-12-27'
draft = false
title = 'CyberEdu nulle Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn"]
+++


## Challenge overview

**[Our](https://app.cyber-edu.co/challenges/9fc63e6a-404f-447c-b041-ec2ab0a1d450?tenant=cyberedu)** developer got a bit too clever with C structs. They decided that if two structs have the same fields, just in a different order, it’s fine to cast between them.

Let's look at our binary, **main**.

![challenge-screenshot](pic6.png#center)

In our `main` function, we get to write into a `aIsYour` string, after which a function I named `call_param` that looks like this is called:

![challenge-screenshot](pic7.png#center)

This function essentially calls the function at address `a1` (its parameter), passing the value located at `a1+1` (immediately after a1) as a parameter to the `a1()` function.

That just means call `a1(a1+1)`.

We also have a function called `call_system` which, guess, calls system, and passes the `call_system` parameter as a parameter to `system`. Ideally that would be `'/bin/sh'`.

And we have complete control of `aIsYour`.

---

## Identifying the vulnerabilities

I tried to see if we can overwrite anything interesting in the `.data`, but we're just barely out of reach:

![challenge-screenshot](pic1.png#center)
![challenge-screenshot](pic2.png#center)

Then, looks like the challenge is pretty simple, we can just change the `aIsYour` to `call_system + /bin/sh`.

---

## The exploit

I created the following payload, sent it locally and popped a shell:

```python
call_system = 0x4011b6

payload = p64(call_system)
payload+= b'/bin/sh'
p.recvuntil(b'g\n')
p.sendline(payload)
```

![challenge-screenshot](pic3.png#center)

Nice! I connected remotely, and we don't immediately find a flag file, so we can look for it with `grep`.

![challenge-screenshot](pic4.png#center)

All done!

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/nulle.py)**.
