+++
date = '2025-11-19T21:09:36+02:00'
draft = false
title = 'Pico Stack Cache Writeup'
ShowToc = true
tags = ["picoCTF", "pwn", "buffer-overflow"]
+++

## Challenge overview


Undefined behaviours are fun. It looks like Dr. Oswal allowed buffer overflows again. Analyse **[this program](https://play.picoctf.org/practice/challenge/306)** to identify how you can get to the flag.


![challenge-screenshot](pic1.png#center)

At first glance, the **vuln** looks like a 32-bit executable with a buffer overflow vulnerability.

Analyzing the binary, we come across some interesting funtions, `UnderConstruction` and `win`.

![challenge-screenshot](pic2.png#center)

After a quick `checksec`, we find vuln has both NX and a stack canary enabled.
So we can probably find a way to leak the stack canary using the `UnderConstruction` function.

---

## Identifying the vulnerabilities

We can easily buffer overflow (the offset I used was 14 of `\x90` padding and then I set the new `eip` as `0x8049E10`, the beginning of `UnderConstruction`) into `UnderConstruction`, and we get a bunch of leaks: 

![challenge-screenshot](pic3.png#center)

It doesn't seem like the stack canary is very effective.
If we overwrite `eip` with the `win` function, it does indeed enter `win`, but no flag seems to be getting printed. Let's analyze it further:

![challenge-screenshot](pic4.png#center)

Aha! So if we look closely, what this does is it saves the flag in the stack, and if the flag array is null, it executes a `_printf(%s %s);`.

In my case, I have a `flag.txt` file created locally, so it doesn't really output anything at all. What it *does* do though, is save the flag in the stack (also hinted by the challenge name, *stack cache*).


We can see the content of `flag.txt` being pushed on the stack.

![challenge-screenshot](pic5.png#center)


---

The next logical step is making it so that the function called after `win` is `UnderConstruction`. We can do this without much hassle since we are working on a 32-bit executable, so no need to work with registers.

The stack alignment for 32-bit is function, parameters, return address and since these functions don't need any params we can easily chain a bunch of functions.

```python
payload = b'\x90'*14
payload += p32(0x8049D90) #win
payload += p32(0x8049E10) #under constr devine ret addr la win
payload += p32(0x8049E10) #a bunch of undr constr to leak the flag
payload += p32(0x8049E10) #to get a bunch of %p 's 
payload += p32(0x8049E10)
payload += p32(0x8049E10)
payload += p32(0x8049E10)
payload += p32(0x8049E10)
payload += p32(0x8049E10)
payload += p32(0x8049E10)
payload += p32(0x8049E10)
payload += p32(0x8049E10)
payload += p32(0x8049EB0) #main
```

Since I wanted to make sure that we would get all of the flag, not just a part of it, since pico flags are usually pretty long, I chained a lot of `UnderConstruction` functions together.


![challenge-screenshot](pic6.png#center)

And lo and behold! Dumping this into CyberChef, we can see the content of the flag is being shown on the stack, separated into 4 byte chunks with reversed bit order.

![challenge-screenshot](pic7.png#center)

All that's left to do is connect remotely and see if we can extract the flag.

![challenge-screenshot](pic8.png#center)

And that’s it! The rest of the code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/pico/stackcache.py)**.
