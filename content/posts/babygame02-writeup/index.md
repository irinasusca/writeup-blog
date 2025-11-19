+++
date = '2025-11-19T21:08:35+02:00'
draft = false
title = 'Pico Babygame02 Writeup'
ShowToc = true
tags = ["picoCTF", "pwn", "buffer-overflow"]
+++

## Challenge overview


Break the game and get the flag. Welcome to **[BabyGame 02](https://play.picoctf.org/practice/challenge/346)**! Navigate around the map and see what you can find!


![challenge-screenshot](pic1.png#center)

After analyzing the binary and renaming the variables, we notice we have a **player struct/array** consisting of the **player y**, **player x**. 

Immediately after that, we have the **map matrix**.

![challenge-screenshot](pic2.png#center)

From the `main` function, by solving the puzzle, which can be easily achieved by using the special command `p` we "win". And with the special command `l` we can replace the `@` player character with a char (spoiler, it can be any byte of our liking, not necessarily a char). 

![challenge-screenshot](pic3.png#center)

---

## Identifying the vulnerabilities

What is most likely the vulnerability is that there is no bounds check for the map, and that we can overwrite the variables on the stack by modifying one byte.

More precisely, using our player, and moving it out of bounds will allow us to modify the byte at position
```python
player_x + map + 90 * player_y
```
where map is the location of the map buffer on the stack.

![challenge-screenshot](pic4.png#center)

---

We notice a `win` function, so all we need to do is find a way to jump into `win`.
Using the `file` command, we can see that **game** is a 32-bit executable, so all the function parameters are stored on the stack.

Probably so is the return to `main` inside `move_player`, so we can set a breakpoint on its return.

There is no stack canary or PIE, so nothing that we need to worry about.

![challenge-screenshot](pic5.png#center)

And there it is!

Using `hexdump` with GEF, we can analyze the offset from the beginning of `map` to our return address (the first `0x2e` being the first dot inside `map`).
The offset seems to be 39.

![challenge-screenshot](pic6.png#center)


To modify the return address we need to find a position in `win` that is one byte away from `0x08049709`. 

For example, `0x804975D` works perfectly! 
So all we need to do is overwrite its LSB `09` with `5D`.

We can easily achieve this by using the `l` command.
So first, modify it our player to `\x5D`, then we move to position `map - 39`.

`player_x + map + 90 * player_y = map - 39`
 
One way to solve this is `player_x = -39` and `player_y = 0`. 
To not mess with other values on the stack that might crash our program, we could first go up to `player_y=-2`, go to the right `player_x`, then go back down to `player_y=0`.

```python
p.recvuntil(b'X\n')
p.sendline(b'l'+b'\x5D')
p.recvuntil(b'X\n')
p.sendline(b'w'*4 + b'a'*4 + b'w'*2 +b'a'*39+b's'*2)
```

![challenge-screenshot](pic7.png#center)

---

## Some problems...

It seems to be working fine locally, but remotely we stumble upon another issue.

![challenge-screenshot](pic8.png#center)

And then *another* issue? 

![challenge-screenshot](pic9.png#center)

In these kinds of situations, what happens is some things get aligned differently, so the best thing to do is try other addresses near what we found.

The first one I found that works is `\x60`, and with that we get the flag!

![challenge-screenshot](pic10.png#center)

And that’s it! The rest of the code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/pico/babygame02.py)**.
