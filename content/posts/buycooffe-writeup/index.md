+++
date = '2025-12-03'
draft = false
title = 'CyberEdu Buy-Cooffe Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow", "Ret2libc", "Canary", "PIE", "ASLR"]
+++

## Challenge overview


It’s early morning, and the caffeine hasn’t quite kicked in yet. As you sip your cup of coffee, you notice something odd – a **[mysterious program](https://app.cyber-edu.co/challenges/9d17bf99-ddd2-465c-b5f9-041ad6993053?tenant=cyberedu)** named cooffee is running on your system.

![challenge-screenshot](pic1.png#center)

At first glance, the **chall** looks like a 64-bit executable, and upon a buffer overflow the program immediately leaks us a `libc` address. We also get the `libc-2.31.so` to download, and that means this is the `libc` version our binary uses.

Now, let's take the look at the disassembled code. In main, we call `coffee()`. 

![challenge-screenshot](pic2.png#center)

Aside from `coffee()`, we can see a lot functions with `ROP` derived names, to the left. And we can see the function getting leaked is `printf`.

And we can see that both reads are vulnerable to buffer overflow, but `printf` getting leaked didn't have anything to do with it, it was just hardcoded.

All the other functions seem to be empty, so they might've been added just so the binary has some gadgets for us to use. So we don't even need to execute a `ret2plt` to leak anything, just take in the input and then calculate the right offsets.

After a `checksec`, we find out that we have full `RelRO`, `PIE`, and `NX`. And most likely `ALSR`. 

---

## Identifying the vulnerabilities

Since in `coffee()`, we have an unsanitized `printf`, we can also leak values from the stack with a format string vulnerability. Since we're working with a canary, we might be able to leak it this way, and then continue on with our script.

![challenge-screenshot](pic4.png#center)

Here is our canary on the stack; All that's left is to leak it in our program with a lot of `%p`s. 

![challenge-screenshot](pic5.png#center)

And here it is! The LSB is shown in the next value, though. Now we just need to calculate the offset to it.

![challenge-screenshot](pic6.png#center)

So the stack is split between the 155th value on the stack and the 156th. Let's call the 155th value `A`, and the 156th value `B`.

Let's take an example so it's easier to understand.

`A = 0x8b705c2f0bf0b500`

`B = 0x8d64ecd3a212573e`

`canary = 3e8b705c2f0bf000`

And we consider that the first byte of `A` is `00`, the first byte of `B` is `3e` (little endian). What we need to do, is take `A`'s first byte, then skip the second (in this example, that `b5`), take all of the rest of its bytes (`8b705c2f0bf0`), and then add the first byte in `B` (`3e`). 

My script for this was
```python
A = int(p.recv(18), 16)
B = int(p.recv(18), 16)

print(hex(A))
print(hex(B))

reconstructed = ( (B & 0xff) << 56 ) | ( (A >> 16) << 8 ) | (A & 0xff)
#<< 56 -> move it to bits 63-56
print(hex(reconstructed))
```

![challenge-screenshot](pic7.png#center)

Here, we can see we the correct canary value, calculated from `A` and `B`!
Now let's see what the value of the canary is going to be like after we return and execute a ROP chain.

---

## The exploit

![challenge-screenshot](pic8.png#center)

Before that, let's calculate the offsets from `libc` to `binsh` and `system`. We might have to change them to the appropriate `2.31` versions, to solve the challenge remotely, but we'll worry about that later. 

![challenge-screenshot](pic9.png#center)

Great! Now, let's look for some `pop rdi; ret` gadgets, using `ropper`.

```python
0x0000000000001223: pop rdi; nop; pop rbp; ret; 
0x00000000000013b3: pop rdi; ret; 
```

Oops, I forgot this chall had `PIE` enabled... I guess we will need to leak the binary position as well. 

Luckily, we easily stumble upon `0x55555555511e <_start+46>`, as the 43rd value on the stack. Our `pop rdi; ret` gadget is at binary + `0x13b3`, so at `0x55555555511e + 0x295`. After double checking, it seems to check out, so we add this to our script:

```python

A = int(p.recv(18), 16)
B = int(p.recv(18), 16)
binary_leak = int(p.recv(14), 16)
pop_rdi_ret = binary_leak + 0x295

print(hex(A))
print(hex(B))
print(hex(pop_rdi_ret))

```

Great; We *might* also need a `ret` for alignment, so let's take care of that, just in case. The `ret` offset from the binary is `0x101a`, so that's `0x399` bytes off from our `pop rdi; ret` gadget. So we just add a `ret = pop_rdi_ret - 0x399`. 

Now, we can start working on our payload, and identifying where we need the canary to be placed. 

![challenge-screenshot](pic2.png#center)

If we look at the function again, it looks like `v2` is the canary; Since it checks its content at the end of the function, and reads it from somewhere else. So the first 24 bytes are `format`'s, the next 8 is the `canary`, and then another 8 bytes for `rbp`. Since the `fread` reads 80 bytes, we need to add a bunch of nops at the end of our payload.

As predicted, a stack misalignment causes a `SIGSEGV`, so we just add another `ret` and...

```python

payload = (b'\x90' * padding_to_canary + 
	   p64(canary) +
	   b'\x90' * 8 +
	   p64(pop_rdi_ret) +
	   p64(binsh) + 
	   p64(ret) +
	   p64(system))
	   
	   
payload = payload.ljust(80, b'\x90')

```

![challenge-screenshot](pic10.png#center)

We pop a shell! Now, let's try remotely, and see what happens.

---

![challenge-screenshot](pic11.png#center)

Well, that's not very good... Looks like their canary is at a different offset from ours. And probably so is the binary. I printed the first hundred values on the stack, and we find one inside the binary at `0x564ae94060f0`. But it's most probably a different one than what we found. And no sight of the canary yet.

The values I found for binary values are

`%87$p: 0x5b4de10ff0f0`

`%77$p: 0x5d25d3fce040`

And clearly since they don't end in the same byte as our locally discovered value, I have no clue what their offset might be. In the meantime, using **[blukat](https://libc.blukat.me/?q=_IO_printf%3Abc90&l=libc6_2.31-0ubuntu9.10_amd64)** I found the `2.31` offsets for our ROP chain functions.

So all we need to do now is find the canary.

After a bit more searching, we find the `11e` ending binary value! At offset 39, so we can update that in our script.

![challenge-screenshot](pic12.png#center)

I also found some canary-looking variables this way: `0x3c9dbcb6f3282a00 0x3e5e2db58d462a00`. They were both right next to each other, but I had no way of checking which one was the right one, and I felt like they were too early on. After a bit more time of searching, I found this:

![challenge-screenshot](pic13.png#center)

Looks familiar doesn't it? I'm guessing it's the same situation of the canary getting a little scrambled between the two variables, so I won't change the logic just yet. The offsets were `%113$p` and `%114$p`.

![challenge-screenshot](pic14.png#center)

And would you look at that! It worked!

---

As always, the rest of the code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/buycooffe.py)**.
