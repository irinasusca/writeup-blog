+++
date = '2025-11-27T21:09:36+02:00'
draft = false
title = 'Pico Homework Writeup'
ShowToc = true
tags = ["picoCTF", "pwn", "buffer-overflow", "PIE"]
+++

## Challenge overview


"time to do some **[homework](https://play.picoctf.org/practice/challenge/217)**!"

At first glance, **homework** looks like a 64-bit executable, but we can't tell much about it.

![challenge-screenshot](pic1.png#center)

After using checksec, sadly, `PIE` is enabled and so is `NX`. 

![challenge-screenshot](pic2.png#center)

We have a `main` function *(picture above)* and a `step` function.
The `step` function uses and then modifies some variables declared/located in the `.bss`, so it would be good to see what they look like before execution starts.

![challenge-screenshot](pic3.png#center)

Char `board[1100]` is at offset `0x5260` from the first read-only section of the binary, int `sn` at `0x50A0`, int `stack[104]` at `0x50C0`, `rows` at `0x56AC`, cols at `0x56B0`, `diry` at `0x56B4`, `dirx` a bit further at `0x5078`.

![challenge-screenshot](pic4.png#center)

As we can see, most of them begin as `0`, except the `cols` and `rows` (same values as in `main`) and the `dirx` starting as `0x1`.

Also, the `flag` is stored in the stack, so we might find a way to leak it.

![challenge-screenshot](pic5.png#center)

The `step` function is a bit more complicated, with a switch for a lot of operands for the char at `board[22 * pcy + pcx]`. For each one, `sn` is checked against some conditions, and `__assert_fail()' is used.

After reading the function's documentation, what it does is it aborts the program if the `assertion` is false, and all of these *assertions* are either checking `sn >= ` to 1, 2 or 3, or `stack[sn-1] <= rows && stack[sn-2] <= cols`.

Then, most of them redirect to `LABEL_76`:

![challenge-screenshot](pic6.png#center)

This relocates pcx (our x position in `board`, inside `step`) and our `pcy` (y position in `board` inside `step`).

`dirx` and `diry` seem like regular matrix directions, with values from `[-1, 0, 1]`. 

Then, for each iteration, it falls through to `LABEL76`, and for normal characters it just seems to iterate through `board[]`, until it finds a special operand.

Here is everything it does, simplified for a better understanding:

```python

'!': if(sn <= 0) abort
     stack[sn - 1] = 1, if it was 0
     stack[sn - 1] = 0, otherwise
    
'$': if(sn <= 0) abort
     --sn
    
'%': if(sn <= 1) abort
     stack[sn-2] %= stack[sn - 1]
     --sn
    
'*': if(sn <= 1) abort
     stack[sn-2] *= stack[sn-1]
     --sn
    
'+': if(sn <= 1) abort
     stack[sn-2] += stack[sn-1]
     --sn
    
',': if(sn <= 0) abort
     putchar(stack[--sn])
     #print a char at stack[--sn]
    
'-': if(sn <= 1) abort
     stack[sn-2] -= stack[sn-1]
     --sn
    
'.': if(sn <= 0) abort
     printf(%d, stack[--sn])
     #this might help us leak stack!
    
'/': if(sn <= 1) abort
     stack[sn-2] /= stack[sn-1]
     --sn
    
':': if(sn <=0 ) abort
     stack[sn] = stack[sn-1]
     ++sn

'\\': if(sn<=1) abort
      swap(stack[sn-1], stack[sn-2])
      #xor swap
    
'`':  if(sn<=1) abort
      stack[sn-2] = stack[sn-2] > stack[sn-1]
    
'g':  if(sn<=1) abort
      if( 0 <= stack[n-1] <= rows && 0 <= stack[n-2] <= cols)
      #bounds check
      stack[sn-2] = board[22 * stack[sn-1] + stack[sn-2]]
      #stack[sn-2] = board[stack[sn-1]][stack[sn-2]]
      --sn
    
'p':  if(sn<=2) abort
      if( 0 <= stack[n-1] <= rows && 0 <= stack[n-2] <= cols)
      #bounds check
      board[22 * stack[sn-1] + stack[sn-2]] = stack[sn-3]
      #board[stack[sn-1]][stack[sn-2]] = stack[sn-3]
      sn-=3
    
'<': dirx = -1
     diry = 0
     #go to the previous element in board array
   
'>': dirx = 1
     diry = 0
     #go to the next element in board array
   
'^': dirx = 0
     diry = -1
     #move up a row in board
   
'v': dirx = 0
     diry = 1
     #move down a row in board
   
'_':  if(sn<=0) abort
      if(stack[--sn]
          dirx= - 1
      else
          dirx = 1
      diry = 0
    
'|':  if(sn<=0) abort
      if(stack[--sn]
          diry = -1
      else
          diry = 1
      dirx = 0
   
'@': return 0;
    
default:
    if(board[22* pcy + pcx] == '0'])
        if(sn>99) abort
        v1 = sn++
        stack[v1] = 0
        
LABEL_76:
    #update pcx and pcy based on dirx and diry
    return 1
    
```
    
Every case except the `@` which returns 0, will step into `LABEL_76`.

Quite a long function isn't it?

We can conclude that `pcx` and `pcy` probably stand for player/position current x and y.

The case that seems the most interesting is the `.` since it does `printf(%d, stack[--sn]`. In `.bss` we have:

`stack[0]: 0x50C0`

`flag: 0x56E0`

And so the offset between them is `0x620`, or 1568 in decimal.
Since int_size is 4 bytes, that means by accessing `stack[392]` we should reach `flag`'s `.bss` location.

The only cases that raise our `sn` are the `:` and `default` case, and they both only raise `sn` by 1.

And, the `22*i` byte of `board` is always 0.

To be fair, this solution seems too good to be true, but let's explore it anyways.

---

## My first Idea


With the input `0::::::::::::::::::::::::::[and so on]` we managed to raise `sn` so that `stack[sn]` overwrites some data.

I also tried a loop `>>:::<<` that theoretically should'be incremented `sn` forever.

![challenge-screenshot](pic7.png#center)

But this only gets us to `sn = 110`.

For some reason after `sn` reaches 110 it wont enter the `:` anymore whatsoever, but it won't abort either, weird. So maybe that's not the way to go with this...

At this point, I was starting to doubt modifying `sn` was the way to go, so I tried to find other any confirmation of this idea. The only two other writeups I found both overwrote the `rows` variable, which was directly after `board` on the `.bss`.

But I'm going to have a little faith in my idea so I will try to see if I can manage something before giving up.

What I missed was that the `stack` was actually a stack (*what a surprise, right?*) and `sn` was the stack pointer.

---

## Understanding step and stack

So almost every action was a `pop()` or a `push()`. 
It was very well explained in **[this writeup](https://hackmd.io/@nut/Hy7MtQDdd)** like this:
```python
0: push 0 to the top of the stack (also asserts if full)
$: discard stack[top]
!: logical NOT of top of stack (stack[top] = !stack[top])
`: sets stack[top-1] to result of stack[top] < stack[top-1] (does not pop anything, which is kinda weird)
%: pops top 2 elements and pushes stack[top-1] % stack[top]
/: pops top 2 elements and pushes stack[top-1] / stack[top]
*: pops top 2 elements and pushes stack[top-1] * stack[top]
+: pops top 2 elements and pushes stack[top-1] + stack[top]
-: pops top 2 elements and pushes stack[top-1] - stack[top]
,: pops and prints stack[top] as ascii character (putchar)
.: pops and prints stack[top] as 32-bit number (printf("%d"))
:: duplicate stack[top] (NO BOUNDS CHECK!!!)
\: swap top 2 elements using XOR

pc controls:
<: set pc direction to left
>: set pc direction to right
^: set pc direction to up
v: set pc direction to down
_: horizontal branch (pc goes right if stack[top]==0, left otherwise), pops stack[top]
|: vertical branch (pc goes down if stack[top]==0, up otherwse), pops stack[top]

@: stop program
g: pushes board[stack[top]][stack[top-1]] onto stack top, pops top 2 elements
p: sets board[stack[top]][stack[top-1]] = (char) stack[top-2], popping off all 3 elements
```
Well, makes a lot more sense now!

And look at this:

![challenge-screenshot](pic10.png#center)

When we reach `sn = 109`, after `stack[sn]` goes into the data immediately after `stack` which is `board`, so we overwrite `board` and fill the values with `0`!!

![challenge-screenshot](pic11.png#center)

And we deleted our loop `>>::::<<` ourselves! Well, ideally, we would want to overwrite them with `:` instead of `0`, right? and since we just duplicate the current top stack element and push it in the stack, if we manage to set the first character on the stack to  be `:`, we might be able to avoid this! 

---

## Adding numbers to stack

First, to start summing/multiplicating numbers, we need to get two `1` values on the stack. The input we should give:

`0`: push 0 on the stack

`!`: pop; push 1;

`:`: push 1;

Now we have a `stack` that looks like `[1, 1]`.

`+`: pop a, pop b; push(a+b)

Now `stack` looks like `[2]`.

Since in ASCII, `:` is `58`, if we add a bunch of `2`s, we can get `stack[top]` to become `58`

I'm thinking we duplicate the `2` using `:` and then multiply the first six ones, we reach `64`. Then we can just decrement `2` another three times, and we get `58`.

`:`: push 2; `stack = [2, 2]`

`+`: pop a,b; push a+b; `stack = [4]`

`:`: push 4; `stack = [4, 4]`

`:`: push 4; `stack = [4, 4, 4]`

`*`: pop a,b; push a*b; `stack = [4, 16]`

`*`: pop a,b; push a*b; `stack = [64]`

Now, since the `-` pushes `stack[top-1]` - `stack[top]`, we need to push a `6` above the `64` in the `stack`.

`0`: push 0; `stack = [64, 0]`

`!`: pop; push 1; `stack = [64, 1]`

`:`: push 1; `stack = [64, 1, 1]`

`+`: pop a, b; push a+b; `stack = [64, 2]`

`:`: push 2; `stack = [64, 2, 2]`

`:`: push 2; `stack = [64, 2, 2, 2]`

`+`: pop a, b; push a+b; `stack = [64, 2, 4]`

`+`: pop a, b; push a+b; `stack = [64, 6]`

`-`: pop a, b; push b-a; `stack = [58]`

`,`: pop a, putchar(a); `stack = []`

`@`: return 0;

So our payload would be `0!:+:+::**0!:+::++-,@`. And it worked!

![challenge-screenshot](pic12.png#center)

---

## A sad realisation


![challenge-screenshot](pic13.png#center)

This is the situation I wanted to reach. In the second board drawing, the direction gets set back by the `<`, and we repeat the `:` padding until we reach `board[0]` again. Theoretically, this should raise `sn` to ~277. Still not 392 but closer...

*(Note from the future - I didn't understand how `board` was being parsed yet - but more on that later - without using `^` or `v` we cannot switch rows)*

Since can never really tell when we reached the correct `sn`, what if we just print the stack top in every loop? We know what the flag is supposed to look like, so we can find it between the printed garbage values.

Well, in a `>.:<` sequence what happens is:

```python
stack = [...data1, data2, data3, data4]
memory = [...data1, data2, data3, data4, data 5, data 6...]

'.':

stack = [...data1, data2, data3]
print data4
memory = [...data1, data2, data3, data4, data 5, data 6...]

':':

stack = [...data1, data2, data3, data3]
memory = [...data1, data2, data3, data3, data 5, data 6...]

'.':

stack = [...data1, data2, data3]
print data3
memory = [...data1, data2, data3, data3, data 5, data 6...]
```


Well. Looks like we just overwrite the data, and we can only print data that we already overwrote. Would've been nice to realise this earlier.


---

## The solution

Since the most interesting/out-of-the-ordinary cases were

```python
g: pushes board[stack[top]][stack[top-1]] onto stack top, pops top 2 elements
p: sets board[stack[top]][stack[top-1]] = (char) stack[top-2], popping off all 3 elements
```

it's most likely that we are going to have to use them to solve the chall.

However, we have face a bounds check, that requires:

`0<=stack[top]<=rows`

`0<=stack[top-1]<=cols`.

That means, the command executes even for `stack[top] == rows` and `stack[top-1] == cols`; That means we can edit the data at `board[50][22]`. But `board` is indexed from starting from 0, so that means that we have an extra row at our disposal!
(50*22 + 22 is 1122).

In `.bss`, the data immediately after `board`, aka the data we can and are going to overflow, is `rows`, `cols`, `dirx` and `pcx`.

The useful ones are `rows` and `cols`, because they can completely break us out of that bound check. So first, let's get `stack[top]` to 50. Then we can figure out the value we need to insert starting after `board[1100]`.

Since modifying `rows` would mean having to flip through a couple of different rows to output the flag, I'd rather opt for modifying `cols`.

That means 4 bytes after `rows` (`board[1100]`), is `cols`, So we should set `stack[top-1]` to 4.

The sequence that gets us 50 is `0!::+:++::+*`, so that would be `stack[top]`.

So what should we change `cols` to? The best idea would be to use 

`g: pushes board[stack[top]][stack[top-1]] onto stack top, pops top 2 elements`

Where `board[stack[top]*22] + stack[top-1]]` would be the first character of the flag, then use `,` to print it, and do the same for the next `n` characters of the flag, probably around 45.

Let's calculate the offset from `board` to `flag`:

`board: 0x5260`

`flag: 0x56E0`

So `0x480 = 1152`. And that's the beginning of `flag`, so we would reach around `1197`. That would mean we would need `cols` should be at around 100.

Alright, so to set `cols` to somewhere a bit more than 100 then.

That is `0!::+:++::**` for 125 (better safe than sorry). 

After fiddling a lot with inputs, it looks like the way `step` reads our `board` is a lot like the snake game, so we need to redirect it and change directions every time we switch rows. And all of them should be close in column-lengths.

As a fun fact, apparently this is based on *Befunge*, and I quote, *a two-dimensional esoteric programming language invented in 1993 by Chris Pressey with the goal of being as difficult to compile as possible*.

We need two rows of input:

`0!::+:++::**` `0!:+` `v` #push 125, push 2, go to next row

`*+::++:+::!0` `+:` `<`  #change movement to left, 2->4, push 50

When we go down one row, we need to change the direction of reading, so the second row is read from right to left.

So now `stack` looks like `[125, 4, 50]`. Let's check if it works, and we modify rows.

![challenge-screenshot](pic14.png#center)

It does push `125` to the stack, but the other values? (`{` is 125)

![challenge-screenshot](pic16.png#center)

Alright, getting somewhere!

![challenge-screenshot](pic17.png#center)

Looking great!! Finally, we get confirmation we modified `cols`.

![challenge-screenshot](pic18.png#center)

Now let's move onto the next row. `p` popped all of our values, so we need to push new ones.

`g: pushes board[stack[top]][stack[top-1]] onto stack top, pops top 2 elements`

`stack[top]` needs to be 50, and `stack[top-1]` needs to iterate from 125 to 52. 


---

## The Loop

We need to print from `board[1100 + 52]` for the first character to `board[1100 + 125]` to the last. So logically we would need a loop for that. So, let's create one using this *language*. If we just pad a line to the right and to left with the same direction character, `>` or `<`, it will keep going back to the other side of the row.

`>>>>>>>execute>>>>>>>`

or

`<<<<<<<execute<<<<<<<`

or something like 

```python
> code here ......... v
^ other code here.... <
```

![challenge-screenshot](pic19.jpg#center)

This is my idea of solving this; But we would need to push a `50` to `board[0][0]` to have easy access to it later. The last thing we push in the stack in line 2 is a 50, so we might as well do it there.

since `p: sets board[stack[top]][stack[top-1]] = (char) stack[top-2], popping off all 3`, and we want to keep the `50` in the stack to overwrite `cols`, we can do the following:

`:`: `[125, 4, 50, 50]`

`00`: `[125, 4, 50, 50, 0, 0]`

`p`: `[125, 4, 50]` and `board[0][0] = 50`

And after this we can resume overwriting `cols`. 

`p`: `board[50][4] = 125`

Now, we can start using `g` to fetch `50` in our loop. For simplicity, lets start with the first col 51.

`00`: `[0, 0]`

`g` : `board[0][0]=50`

Now we can officially start the loop.

`0!+`: `[51]` increment current stack top

`:`: `[51, 51]`

`00`: `[51, 51, 0, 0]`

`g`: `[51, 51, 50]`, `board[50][51]` -> stack top

`g`: `[51, char]` 

`,`: `[51]` print(char)

And now go back to increment. 

And I think I did it! 

![challenge-screenshot](pic20.png#center)

Now testing remotely, fingers crossed...

![challenge-screenshot](pic21.png#center)


It actually worked! Yay! This is definitely my longest writeup yet, but I hope I covered everything on this, since it can definitely be very overwhelming for beginners.

---

As always, the rest of the code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/pico/homework.py)**.
