+++
date = '2026-02-05'
draft = true
title = 'CyberEdu baby heap Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow", "Format-String"]
+++


## Challenge overview

In **[this challenge](https://app.cyber-edu.co/challenges/559febf0-7f21-11ea-be53-e5754acd68a0?tenant=cyberedu)** you can test your understanding about basic heap exploitation.

Just as a side note, I've put off doing heap challenges for the longest time ever, because I thought they were too bothersome, but that changes today, because we're solving this! So this is a great and notable milestone. ~After I wrote this, I didn't open my laptop for two days~.

And a quick warning, this is going to be a little more in-depth than usual, because as I said, this is a new concept for me.

![challenge-screenshot](pic1.png#center)

We also have a 64 bit fie with canary, NX, PIE and full RelRo enabled.

And of course, the *menu*. Every time there's a weird menu, 99%, that's heap.

I attempted to overflow the size, but I got `Option: Size: The maximum size was exceeded.` a million times in a row, completely impairing our input:

![challenge-screenshot](pic2.png#center)

I quickly attempted a double free, but it didn't work either.

---

Let's look at the functions here. I won't include the `main`, since it just redirects to these functions. First, `free`:

![challenge-screenshot](free.png#center)

Then, `show`:

![challenge-screenshot](show.png#center)

And finally, `malloc`, which is longer and more interesting.

![challenge-screenshot](malloc1.png#center)

This first part just means we can only allocate up to 5 buffers.

![challenge-screenshot](malloc2.png#center)

We can write up to 511 bytes into our buffer, which get `strcpy`d into `*((_QWORD *)&unk_202040 + v3)` aka `malloc(nbytes)`. This however, copies *everything*, including the null byte terminator of our buf. 

---

## Identifying the vulnerabilities


This means we can overwrite the next chunk's *metadata* with a null byte. The metadata we're specifically interested in is the `prev_inuse` and the `size` flags. I played around with chunks and got to this conclusion: 

If we: 
- `malloc(a)` of size `0x88`,
- then `malloc(b)` of size `0x88`, 
- then `free(a)` and reallocate a with another `malloc(a)` of `0x88`

We essentially overwrite `b`'s metadata! 

I took a screenshot before we free and reallocate the `a` chunk, and one after:

![challenge-screenshot](chunkab.png#center)

Metadata (size `0x90` and flag `0x1` of `prev_inuse`) intact

![challenge-screenshot](chunkab2.png#center)

And now, it's gone! But we don't want all that to be gone, because it's just more trouble if we completely overwrite the size. So instead, we're just going to want to overwrite the `prev_inuse`. So we need the sizes to be at least three digits long, > 256. So how much should we allocate for that? We want to keep the size the same after modifying, and since we can overwrite only two bytes, not just one, we need the metadata to look like `101`. That way, after the overwrite, it's going to be `100`.

![challenge-screenshot](morechunk.png#center)

Here it is, after using size `248`. After freeing `b`:

![challenge-screenshot](freed.png#center)

The big idea would be overwriting `printf.got` with `system`, so that when we choose the `show` option, if the overwrite is successful, calling `printf("/bin/sh")`, aka malloc-ing something with the content `"/bin/sh"` would pop a shell. But if you recall, we're working with *full RelRO*. That means GOT overwrites aren't happening anytime soon. No libc either, so no one_gadget.

So instead, we're going to be using `__free_hook`!

At this point, I really had no clue of what to do next so I started looking online for solutions. And when I tell you I found **nothing**. Not even Claude or GPT knew how to solve this. But I really want to. I struggled two more hours with it I'm seriously done. Maybe I'll do this another time.


---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/off.py)**.
