+++
date = '2026-01-30'
draft = false
title = 'CyberEdu digikey Writeup'
ShowToc = true
tags = ["CyberEdu", "misc"]
+++


## Challenge overview

This challenge contains the extracted ELF data from a compiled atTiny85 avr chip The device was automatically being detected as a keyboard and inputs in a loop the ctf flag as string.

---

We receive an Atmel AVR 8-bit file, which is the code for a microcontroller, so we can't run it locally on our kali (since it's COMPILED). So we need a decompiler, but of course IDA Pro is too expensive and ghidra looks absolutely awful, so we have to look for one online.

First I tried `strings`, and we get this flag that doesn't work: `ctf{x4978aef327x5064ab48xa1cx8x34x7eea6ffc121fe0e17b0c47b5680b13x98b}`. A lot of weird `x` characters for a flag.

I tried a bunch of decompilers, ghidra and avr ones (simavr, avr-objdump), but it didn't work so I thought I'd give the [dog decompiler](https://dogbolt.org/?id=70c23fbe-f882-413f-9aa5-aa46b22fc015#Hex-Rays=1&Ghidra=873) a chance.

```c
void FUN_code_00029b(void)

{
  byte bVar1;
  char cVar2;
  byte bVar3;
  char cVar4;
  char *pcVar5;
  undefined2 unaff_Y;
  char *pcVar6;
  char *pcVar7;
  byte bVar8;
  bool bVar9;
  bool bVar10;
  bool bVar11;
  char in_Hflg;
  char cVar12;
  char in_Tflg;
  char cVar13;
  char in_Iflg;
  char cVar14;
  undefined1 uStack_2;
  undefined1 uStack_1;
  
  uStack_1 = (undefined1)((uint)unaff_Y >> 8);
  bVar3 = (byte)&uStack_2;
  bVar8 = (byte)((uint)&uStack_2 >> 8);
  bVar1 = bVar3 + 0xba;
  bVar9 = bVar3 < 0x46;
  cVar2 = bVar8 - bVar9;
  pcVar7 = (char *)CONCAT11(cVar2,bVar1);
  cVar12 = in_Hflg == '\x01';
  cVar13 = in_Tflg == '\x01';
  cVar14 = in_Iflg == '\x01';
  SREG = bVar8 < bVar9 | (bVar1 == 0 && cVar2 == '\0') << 1 | (cVar2 < '\0') << 2 |
         SBORROW1(bVar8,bVar9) << 3 | ((char)bVar8 < bVar9) << 4 | cVar12 << 5 | cVar13 << 6 |
         cVar14 << 7;
  cVar4 = 'F';
  pcVar6 = &DAT_mem_008b;
  pcVar5 = pcVar7;
  do {
    pcVar5 = pcVar5 + 1;
    *pcVar5 = *pcVar6;
    cVar4 = cVar4 + -1;
    pcVar6 = pcVar6 + 1;
  } while (cVar4 != '\0');
  while( true ) {
    pcVar7 = pcVar7 + 1;
    if (*pcVar7 == '\0') break;
    if (*pcVar7 == 'x') {
      *pcVar7 = 'd';
    }
  }
  *(undefined3 *)(CONCAT11(cVar2,bVar1) + -2) = 0x2c0;
  FUN_code_00049e(0xdc,CONCAT11(cVar2 - ((bVar1 != 0xff) + -1),bVar3 + 0xbb));
  bVar9 = bVar1 < 0xba;
  bVar11 = SBORROW1(cVar2,-1) != SBORROW1(cVar2 + 1U,bVar9);
  bVar10 = (char)(cVar2 - (bVar9 + -1)) < '\0';
  SREG = (cVar2 != -1 || (byte)(cVar2 + 1U) < bVar9) |
         (bVar1 == 0xba && cVar2 == (char)(bVar9 + -1)) << 1 | bVar10 << 2 | bVar11 << 3 |
         (bVar10 != bVar11) << 4 | (cVar12 == '\x01') << 5 | (cVar13 == '\x01') << 6 |
         (cVar14 == '\x01') << 7;
  return;
}
```

This function looked particularly interesting, especially this part: 

```c
while( true ) {
    pcVar7 = pcVar7 + 1;
    if (*pcVar7 == '\0') break;
    if (*pcVar7 == 'x') {
      *pcVar7 = 'd';
    }
  }
```

It looks like iterating trough a string, replacing each `x` occurrence with a `d`. I didn't think it would work but gave it a shot anyways, but, the flag worked!

Here it is: `ctf{d4978aef327d5064ab48da1cd8d34d7eea6ffc121fe0e17b0c47b5680b13d98b}`










