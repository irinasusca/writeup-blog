+++
date = '2026-05-05'
draft = false
title = 'Dreamhack sint Writeup'
ShowToc = true
tags = ["Dreamhack", "pwn"]
+++

## Challenge overview

이 문제는 서버에서 작동하고 있는 서비스(sint)의 바이너리와 소스 코드가 주어집니다.
프로그램의 취약점을 찾고 익스플로잇해 get_shell 함수를 실행시키세요.
셸을 획득한 후, "flag" 파일을 읽어 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.

---

32-bit.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [esp+0h] [ebp-104h] BYREF
  _BYTE buf[256]; // [esp+4h] [ebp-100h] BYREF

  initialize();
  signal(11, get_shell);
  printf("Size: ");
  __isoc99_scanf("%d", &v4);
  if ( v4 > 256 )
  {
    puts("Buffer Overflow!");
    exit(0);
  }
  printf("Data: ");
  read(0, buf, v4 - 1);
  return 0;
}
```

And we also have a `get_shell` function. What's interesting is the `signal(11, get_shell);`. `get_shell` is the handler for Signal 11 (SIGSEGV, also known as segmentation violation).

## Identifying the vulnerabilities

So `v4` is an unsigned int. And `read(0, buf, v4 - 1)` will, for a negative value, wrap `v4-1` around, no? Meaning, if we input 0 for size, it will read -1 bytes. And since that's impossible, we'll get a huge value instead.

![challenge-screenshot](aha.png#center)

Well, that was easy! Now let's connect remotely and get the flag:

![challenge-screenshot](flag.png#center)


