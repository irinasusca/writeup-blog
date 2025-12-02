+++
date = '2025-12-10'
draft = true
title = 'Pico Bizz Fuzz Writeup'
ShowToc = true
tags = ["picoCTF", "pwn", "buffer-overflow", "rop"]
+++

## Challenge overview

FizzBuzz was too easy, so I made something a little bit harder... There's a buffer overflow in **[this problem](https://play.picoctf.org/practice/challenge/292)**, good luck finding it!

![challenge-screenshot](pic1.png#center)

At first glance, the **vuln** looks like a 32-bit executable, and the description hints that we are dealing with a buffer overflow vulnerability.

---

## Identifying the vulnerabilities

Analyzing the binary, we can see the main function is made of a bunch of `puts("buzz")`, `puts("fizz")`, and a *lot* of function calls.

![challenge-screenshot](pic2.png#center)

Well, we can start by going through each function being called and forming an idea of what everything here does. And it looks like we have to look at about 100 unnamed functions, and after looking at 3 of them, I think we should just start looking for the function looks like it could have a buffer overflow.


![challenge-screenshot](pic3.png#center)

A bunch of these functions look the same - about 250 lines of this - all comparing the return of `checker` to some values, and then calling other functions, and checking them to `result` again.

Now let's take a look at `checker` (I named the function checker myself).

```python

unsigned int __cdecl checker(unsigned int counter)
{
  int input_to_number; // eax
  char input_string[9]; // [esp+Fh] [ebp-19h] BYREF
  int input_size; // [esp+18h] [ebp-10h]
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = 1;
  while ( v5 < counter )
  {
    printf("%zu? ", v5);                        
    # print size of v5, '?'
    __isoc99_scanf("%9s", input_string);
    input_string[8] = 0;
    input_size = strnlen(input_string, 8);      
    # strlen <= 8
    if ( input_string[input_size - 1] == '\n' )
      input_string[input_size - 1] = 0;
    if ( v5 % 15 )    # v5 % 15 != 0
    {
      if ( v5 % 3 )   # v5 % 3 != 0
      {
        if ( v5 % 5 ) # v5 %5 !=0, v5 %3 !=0
        {
          input_to_number = strtol(input_string, 0, 10);
          # str -> numeric value until first letter ("123abc2" -> 123)
          if ( v5 != input_to_number )
            return v5;
          ++v5;
        }
        else  # %5 == 0, %3 != 0
        {
          if ( strncmp(input_string, "buzz", 8u) )
            return v5;
          ++v5;
        }
      }
      else  # %5 != 0, %3 == 0
      {
        if ( strncmp(input_string, "fizz", 8u) )
          return v5;
        ++v5;
      }
    }
    else  # v5 %15 == 0
                        
    {
      if ( strncmp(input_string, "fizzbuzz", 8u) )
        return v5;
      ++v5;
    }
  }
  return v5;
}

```




After further inspections, there are two functions in memory after `main`:

![challenge-screenshot](pic4.png#center)

First, a function that returns a variable named `retaddr`

![challenge-screenshot](pic5.png#center)

Then, a much stranger function. But we'll take a look at this later. For now, let's inspect all of the functions, in the order they appear in memory.

![challenge-screenshot](pic6.png#center)

We have a win function, so that's good.

![challenge-screenshot](pic7.png#center)

After win, about half the functions look like this (about 300), except with different `s` sizes, and a different amount of input read characters - One of these might be susceptible to a buffer overflow.

![challenge-screenshot](pic8.png#center)

Then, we start to see a few that look similar but also include some function calls to previous functions of the previous type.

![challenge-screenshot](pic9.png#center)

Then, some that look like this, a little more different. At this point, they aren't in a specific order anymore, and we see all three types of functions in random order.

The rest of the functions before main look like

```python
result = checker(n)
if(result != n)
{
    #a bunch of ifs and function calls
}
return result
```

I will refer to each to as`is_checker_n` (returns if `checker(n) == n`). Since there are some identical functions, I will append another `_x`, where `x` is the xth time we encounter such a function, since we can't give two of them the same name.

So we need to sort through this mess, to see if we can end up in a function with a buffer overflow, that we first of all need to look for. 

But before that, I wanted to see if I can see if any of these functions call `win` directly, using cross reference tree in IDA.

![challenge-screenshot](pic10.png#center)

Well, I guess not.


---

## The Exploit



---

![challenge-screenshot](pic9.png#center)

And it works!

The rest of the code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/pico/ropfu.py)**.
