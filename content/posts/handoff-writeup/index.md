+++
date = '2025-11-10T21:08:35+02:00'
draft = false
title = 'Pico Handoff Writeup'
ShowToc = true
tags = ["picoCTF", "pwn", "buffer-overflow"]
+++

## Challenge overview

The first vuln we encounter in **[handoff](https://play.picoctf.org/practice/challenge/486)** is that it doesn't disable NX.
(Basically, this means that we can execute shellcode on the stack!)

![challenge-screenshot](handoff-1.png#center)

We are presented with a menu with 3 options:

- Add a recipient  
- Send a message to a recipient  
- Exit

Upon trying to exit, we are prompted to give our feedback.

---

## Identifying the vulnerability

Immediately after decompiling the binary, we notice a buffer overflow in its feedback buffer.
We can also see that the value at `feedback[7]` gets turned to `\0`. However, the feedback buffer overflow is way too small for us to do anything with it, so our best bet is to find another buffer and `jmp` to it.

The perfect buffer for this is our very large **message buffer**! Lucky for us, `rax` gets the return of the previously called function (in this case `gets` -- and `gets`'s return is exactly our string).

This is because `gets` always returns the string it receives as input.

So in our feedback buffer, we need a payload that looks something like 
jmp addr, nop, nop, nop, until we reach rip, and then  overwrite `rip` with a `jmp rax` gadget.

![challenge-screenshot2](handoff-2.png#center)

Obviously, our `jmp addr` needs to jump to our longer script, located in the message 
buffer, using `asm(shellcraft.sh())`, which will just spawn a shell for us.

Using `ropper` we find our `jmp rax` gadget:

```python
jmp_rax = p64(0x40116c)
```

We do a search-pattern of our message inside GEF, and we can find it located at
`$rsp - 670`. 

To find the correct offset, do the search-pattern only AFTER the script executes the jmp rax gadget (I struggled with finding the correct offset because of that for quite a bit).

---

## Payload

Okay, so that basically means we need to do a `sub rsp, 670` and a `jmp rsp` at the beginning of our feedback buffer. To avoid getting our payload messed up by the `feedback[8]` byte being changed into a null byte, we pad the payload with a few NOPs to its left.

Then, we just adjust it to the size of the buffer overflow with NOPs, and then glue the `jmp_rax` gadget to its right.

```python
payload1 = asm('nop;nop;sub rsp,670;jmp rsp;')
payload = payload1.ljust(20, b'\x90')
payload += jmp_rax
```

Don't forget to set `context.arch = 'amd64'`!!! Otherwise writing assembly code won’t work.

![challenge-screenshot3](handoff-3.png#center)

And that’s pretty much it! The rest of the code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/pico/handoff.py)**.
