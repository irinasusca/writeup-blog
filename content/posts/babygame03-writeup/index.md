+++
date = '2025-11-10T21:08:35+02:00'
draft = false
title = 'Pico Babygame03 Writeup'
ShowToc = true
tags = ["picoCTF", "pwn", "buffer-overflow"]
+++

## Challenge overview


Break the game and get the flag. Welcome to **[BabyGame 03](https://play.picoctf.org/practice/challenge/446)**! Navigate around the map and see what you can find! Be careful, you don't have many moves. There are obstacles that instantly end the game on collision. The game is available to download here. There is no source available, so you'll have to figure your way around the map.


![challenge-screenshot](baby-1.png#center)

After analyzing the binary and renaming the variables, we notice we have a **player struct/array** consisting of the **player y**, **player x** and **player lives**. 

Immediately after that, we have the **map matrix**.

![challenge-screenshot](baby-2.png#center)

We immediately run intos a couple of problems. We need to reach **level 5 to win** and to print the flag *(image below)*, but we **cannot move past level 4** because of the if condition inside of the while.

![challenge-screenshot](baby-3.png#center)

---

First, let’s worry about getting up to level 4. 
We notice that we have a couple of special commands inside the move_player function,
Such as `p` to solve the level and `l` to change the current playertile from @.

![challenge-screenshot](baby-4.png#center)

The only issue with directly using the solve function is that we have a limited amount of lives/moves, and it doesn't account for that. 

---

## Identifying the vulnerabilities

Since the map is initialized immediately after the player lives, and there is no bounds check for the player, we can modify the tile at position `map-4` 
(`map` is a 1d array from `0` to `30x90-2`) so that we overwrite **player_lives** with `0x23` (the dot). 

`player_arr[1] + map + 90 * player_arr` basically represents the current player 
position on the map, and it could also be written as `player_x + map + 90 * player_y`.

So if we modify `player_x` to `86` and `player_y` to `-1` we reach "player position" `map-4` (out of bounds), and then we can overwrite it for unlimited lives. 

The payload I found to reach this position (including the solve function):
```python
payload = b'www'+b'a'*8+b'wsp'
```

---

We repeat this until we reach level 4, where things start to get a little bit more complicated.

Using GDB (in my case, GEF) to analyze the stack, we can find the return address of the `move_player` function (which is `0x804992c`) -- by setting a breakpoint on the `retn` of `move_player`, `0x804969F`, of course.

![challenge-screenshot](baby-5.png#center)

If we can modify that return value (which returns to main) to another address in main that comes *after* the level != 4 check, we can essentially reach level 5.

In this case, the value I chose is `0x8049970`. So we only need to modify the LSB of the return value we found on the stack (we can only modify one byte, through playertile, either way).

The reason we can modify it is, same as `player_lives`, that the `map` array is also located on the stack, a few bytes after our return value!
We can use the `l` command to change our playertile to `\x70`.

To see exactly how many bytes away it is, we can use hexdump with GEF: 

![challenge-screenshot](baby-6.png#center)

And there it is -- our `\x70` value! If we count the bytes from `2c` to `70`, we get `51`, which is the offset from the LSB to the beginning of the map (in this case our playertile was on `map[0]`). So we would need to go to `player_y = 0` and `player_x = -51`.

To avoid getting a SEGFault by messing with all the values on the stack in between, we can first move up to `player_y = -3`, move to the correct x value, and then go back down to `player_y = 0`. And it worked!

---

Now, to evade the second `if` problem, which keeps us in the loop, we need to change the return address from `0x804992c` again. It would be nice for it to be directly in win, but since we can only modify one byte, the best value we can choose is the call to `win()` inside of `main`.


Again, lucky for us, that is `0x80499FE`! So we modify our playertile to `\xfe`, but when we repeat the same technique, something goes wrong. After inspecting the stack again, our `map` array shifts more towards `ebp` and we need to use a bigger offset to modify the return address.

![challenge-screenshot](baby-7.png#center)

GEF's `hexdump` wouldn’t show enough addresses, so I had to use this command.

We can see now the distance is `67` bytes, so we update the offset in our script, and voila!
We got the flag!

![challenge-screenshot](baby-8.png#center)

And that’s pretty much it! The rest of the code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/pico/babygame03.py)**.
