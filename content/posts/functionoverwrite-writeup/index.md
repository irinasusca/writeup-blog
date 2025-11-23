+++
date = '2025-11-23T21:08:35+02:00'
draft = false
title = 'Pico Function Overwrite Writeup'
ShowToc = true
tags = ["picoCTF", "pwn", "overflow"]
+++

## Challenge overview

Story telling class 2/2
Additional details will be available after launching your **[challenge instance](https://play.picoctf.org/practice/challenge/272)**.

![challenge-screenshot](pic1.png#center)

Upon a quick check, we see that the challenge is a `32-bit` binary, and that we can trigger a `SEGFAULT`. It might be a buffer overflow, but the challenge doesn't necessarily hint that, so let's inspect it further.

Also NX is enabled, so let's keep that in mind.

![challenge-screenshot](pic2.png#center)

The first input string is not susceptible to a buffer overflow, but something interesting happens on the second `scanf`. We read two `%d` (ints), but only one destination for them (`&number1`). 

We also have another couple of functions, `hard_checker`, `easy_checker` and `calculate_story_score`. 

The check in `easy_checker`:

```python
if ( calculate_story_score(input, input_size) != 1337 )
    return printf("You've failed this class.");
```

The check in `hard_checker`:
```python
if ( calculate_story_score(input, input_size) != 13371337 )
    return printf("You've failed this class.");
```

And the `calculate_story_score` they both use:

![challenge-screenshot](pic3.png#center)

---

Now, inspecting with `gef`, let's see where all of our values end up.
For `input='inputexample'`, `nr1=7` (so it satisfies the first check) and `nr2='testing'`), it looks like input is being placed on the stack while the second number is getting placed on the *heap*.

![challenge-screenshot](pic4.png#center)

The functions we stepped into were `hard_checker` and then `calculate_story_score`, so no `easy_checker`.

What `calculate_story_score` does is it sums all of the ASCII characters inside our input string. 

For our inputexample string, the output should be 
```python
sum = 105 + 110 + 112 + 117 + 116 + 101 + 120 + 97 + 109 + 112 + 108 + 101
```
So, `1308`.
Setting a breakpoint on the return of `calculate_story_score`, we can see the value right there on the stack! (`0x51c` = `1308`)

![challenge-screenshot](pic5.png#center)

And here it is, checking if it's equal to `13371337`:

![challenge-screenshot](pic6.png#center)
![challenge-screenshot](pic7.png#center)


---

## Identifying the vulnerability


So, we need to find a string that has the `sum` of its ASCII characters equal to `13371337`. But that's quite a big number, isn't it? And we only have 127 bytes available. 

Chars go from `0-255`, so our best case scenario would be `127*255`, so `32385`. Not even close to `13371337` is it?

We could either find a way to go into `easy_checker` instead, or find another way to raise our `sum`.

Since the challenge hint was *Don't be so negative*, I'm going to assume there's a way to integer overflow or something else to allow us to reach that number.

---

One thing we haven't handled yet is the two numbers. What bothers me are these lines of code:

```python
if ( numbers <= 9 )
    fun[number1] += v3;
```

After trying with two numbers, (78 and 78), we can see they're still placed in the stack and the heap respectively (I thought the second one might've ended up on the heap because I gave it too large a value, but it wasn't the case).

---

## Debugging Detour

Before actually figuring out how to solve this challenge, I wasted a surprising amount of time due to a small mistake, which is that I kept using a string value for the second `%d` argument. Since `scanf("%d")` interprets 4-byte integers, my string `"testing"` became some random hex bytes that I misinterpreted as something hardcoded.

Because of that, I spent a lot of time trying to find ways to overwrite the ASCII sum, manipulate the comparison instruction, overwrite .rodata, or patch return addresses, so a couple of hours in `gef` and a lot of SEGFAULTS. Turns out the specific hex value was literally just the second integer, which I had broken it myself by feeding it a string.

And also the challenge had nothing to do with the heap either.

So maybe the lesson to be learned is to be a lot more careful with "testing" input values. 


---

## The exploit

![challenge-screenshot](pic8.png#center)

Let's take a look at the assembly code for this `if`:

```python
mov     eax, [ebp+number1] #eax = number1
mov     ecx, ds:(fun - 804C000h)[ebx+eax*4] #ecx = fun[number1]
mov     edx, [ebp+var_90] # edx = number2
mov     eax, [ebp+number1] # eax = numbers
add     edx, ecx # edx += ecx
mov     ds:(fun - 804C000h)[ebx+eax*4], edx # fun[number1] = edx
```

Or more simply put, 

```python
fun_table[number1 * 4] += number2;
```

![challenge-screenshot](pic17.png#center)

Here we can see `number2` getting loaded into `edx`. And `ebx + 0x80` is just the address of `fun`.

![challenge-screenshot](pic18.png#center)

Here is `fun` in `.data`, located at `0804C080`.

![challenge-screenshot](pic16.png#center)


Another interesting thing was how the `hard_checker` function was called:

```python
v0 = check;
return v0((int)input, input_size);
```
Where check holds the address of `hard_checker`:
`0x804c040 <check>: 0x08049436`

And guess what, `check` is, just like `fun`, located in the `.rodata`!

Since the condition in `hard_checker` was `sum == 13371337`, which is impossibe to reach, and we have a similar function called `easy_checker` that presents us with a much more attainable `sum == 1337`, we can already guess we are supposed to somehow modify the address in check from `hard_checker` to `easy_checker`.

Since we can choose a negative `[numbers]` index, we can modify data out of bounds to control the value of `check`. 

Double checking with `vmmap`, the area is `rw`, so we can modify values!

`0x0804c000 0x0804d000 0x00003000 rw- /home/kali/Downloads/vuln`

Okay, so

`fun - check` is  `0x804C080 - 0x804C040`,

 which is `0x40`.
 
Since we need to modify `fun[-0x40]`, that means`number1*4` should be `-0x40` = `-64`.
So we already figured out `number1` = `-16`.

Taking care of the `sum`, our *inputexample* was already close to 1337.
`1337 - 1308 = 29`, so instead of `e` (101 ASCII) I added two `A`'s (`65+65` = `101 +29`).


Now, to figure out `number2`, we just need to calculate the offset between `hard_checker` and `easy_checker`.

`hard_checker : 0x08049436`

`easy_checker : 0x80492FC`

So out offset is `-0x13A`, `-314` in hex.

And we're done!

![challenge-screenshot](win.png#center)



The rest of the code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/pico/functionoverwrite.py)**.
