+++
date = '2025-11-25T21:09:36+02:00'
draft = false
title = 'Pico Buffer Overflow 3 Writeup'
ShowToc = true
tags = ["picoCTF", "pwn", "buffer-overflow", "canary"]
+++

## Challenge overview


Do you think you can bypass the protection and get the flag? It looks like Dr. Oswal added a stack canary to **[this program](https://play.picoctf.org/practice/challenge/306)** to protect against buffer overflows. 


![challenge-screenshot](pic1.png#center)

At first glance, the **vuln** looks like a 32-bit executable, probably with a buffer overflow vulnerability.

We are first prompted to create a canary.txt file, and the binary runs after that.

![challenge-screenshot](pic2.png#center)

Analyzing the binary, first, the `read_canary()` function is called, and then we go into `vuln`.

![challenge-screenshot](pic3.png#center)

There's also a `win` function included in the binary, so we don't have to worry about getting a shell ourselves.

So, firstly, the `read_canary()` reads four bytes from canary.txt. 

After renaming some of the variables from `vuln`, it starts looking like this:

![challenge-screenshot](pic4.png#center)

We see the call to `sscanf`, and looking at the **[C documentation](https://www.tutorialspoint.com/c_standard_library/c_function_sscanf.htm)** for it, what it does is it takes the input from `v` as an integer, and stores it in `&nbytes`.

Then, `read(0, buf, nbytes) will read from the standard input (file descriptor 0),
and write `nbytes` bytes from input into `buf`.

After that, the binary checks if the canary has been modified.

---

## Identifying the vulnerabilities

Time for debugging with `gef`! I set a bp on the `while(v_size <= 63)` just to check if we got anything wrong.

![challenge-screenshot](pic5.png#center)

Looks like our buffer overflow worked!

![challenge-screenshot](pic6.png#center)

For the first input being `123` and the content being an 'A' buffer overflow, it sure does look like it worked!

The only issue is that the canary is also overwritten, so we need to take care of that now.

![challenge-screenshot](pic7.png#center)

The global canary is saved in the `.bss`, and the stack canary is compared to that, to determine a whether stack smashing took place or not.

The canary example I chose is `0xebad3600`, you can use zsh to write it into canary.txt like so: 

```python
	echo -en '\x00\x36\xad\xeb' > canary.txt 
```
 
![challenge-screenshot](pic9.png#center)

Here it's comparing the global canary to our stack canary which is currently overwritten by a bunch of 'A's.

Since the canary is static, taken from a canary.txt file, we might be able to simply bruteforce it, byte by byte.

The offset from the beginning of our input buffer to the canary is `0x40`, so `64` in decimal. 


![challenge-screenshot](pic10.png#center)

---

## The Canary

Considering the challenge hint is *Maybe there's a smart way to brute-force the canary?*, I'm guessing there's more to it than just bruteforcing it.
The global canary is in a `rw` zone, so maybe we can overwrite it?

But since it's 4 bytes, and most likely the last byte is null, we could just bruteforce it. There are 16,777,216 possible combinations with 3 bytes.

But if we test byte-by-byte, we can lower this number monumentally.
So, I opted for creating a `canary_bruteforce()` function to help us find the correct canary.

I'm not familiar with bruteforcing canaries so I looked online to see if I can find a script to help with this, but most of them didn't work.

In the end, the most helpful source was this **[writeup](https://ctftime.org/writeup/32815)**. I made my own `canary_bruteforce()` with similar logic, but I always opt for using and sending bytes rather than strings.

```python
def canary_bruteforce():
	canary= b""
	for i in range(1, 5):
		for c in range(256):
			p=elf.process()
			p.recvuntil(b'> ')
			
			p.sendline(str(64+i))
			p.recvuntil(b'> ')
			payload = b"A"*64 + canary + bytes([c])
			p.sendline(payload)
			result = p.recvall(timeout=0.2)
			
			if b"Stack" not in result:
				canary += bytes([c])
				log.info(f"[+] Found: {canary.hex()}")
				p.close()
				break
            
			p.close()
	return canary
```

Testing it locally, we leak our canary and get the flag!

![challenge-screenshot](pic11.png#center)

All that's left to do is connect remotely and see if we can extract the actual flag.
The first time I tried, it didn't work, so I ended up having to increase the timeout from `0.2` to `1`, and instead of `p.recvuntil`, `p.sendline` I used `p.sendlineafter`, and that worked!


![challenge-screenshot](pic12.png#center)

And that’s it! The rest of the code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/pico/bufferoverflow3.py)**.
