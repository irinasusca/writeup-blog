+++
date = '2026-01-15'
draft = false
title = 'CyberEdu js-magic Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++


## Challenge overview

Javascript Obfuscation 101.

---

Already sounds bad, and I just noticed the *Cryptography* tag, but let's give it a go. We're only given a `chall_clean.js` file, and no instance. 
## Identifying the vulnerabilities

I tried running it in an online compiler, but it required the `window` component, so I locally added an index.html buddy for it and ran them together, and what it did was open a lot of porn tabs.

![challenge-screenshot](wtf.png#center)

Moving on to LLM help, what this does is open a bunch of popups then print an encoded flag to the console. And here is the console - 

![challenge-screenshot](console.png#center) 

That looks like an encrypted flag! The `function(p,a,c,k,e,d)` is a form of packing/obfuscating js, and we can find and use an online depacker. This is the result:

```js
var _11 = ['moc.margatsnI', 'reverse', '%%', 'N%', 'moc.enozekO', 'moc.koobecaF', 'moc.dJ', 'floor', '87b', 'moc.yfipohsyM', 'MQ\x20', 'moc.swennubirT', '$!!', '%MR', 'moc.kV', 'su.mooZ', 'wLM', 'nc.063', 'moc.llamt.nigoL', '/gQ', 'pj.oc.nozamA', 'nc.aynaiT', '4fb', 'moc.nozamA', 'moc.enilnotfosorciM', 'ac4', 'JHM', 'gro.aidepikiW', 'moc.ebutuoY', 'moc.wolfrevokcatS', 'moc.rettiwT', 'moc.revaN', 'kh.moc.elgooG', '29b', '1cf', 'moc.sserpxeilA', '0b3', 'popUpWindow', '4e1', 'nc.moc.aniS', 'random', 'moc.llamt.segaP', 'split', 'moc.uhoS', 'join', 'moc.obieW', 'moc.tenauhniX', 'moc.topsgolB', 'moc.qQ', 'log', 'fromCharCode', 'vt.adnaP', 'pj.oc.oohaY', 'height=137,width=137,left=137,top=137', 'vt.hctiwT', '.{1,', 'length', '%$', 'match', 'vt.iqnahZ', 'moc.udiaB', 'YWg', 'moc.eviL', 'moc.tfosorciM', 'moc.llamT', 'ni.oc.elgooG', 'charCodeAt', 'moc.oaboaT', 'moc.smacagnoB', 'HFK', 'IFv', 'push', 'HMI', 'moc.yabE'];
(function(_1, _8) {
  var _7 = function(_20) {
    while (--_20) {
      _1['push'](_1['shift']())
    }
  };
  _7(++_8)
}(_11, 0x1ae));
var _0 = function(_1, _8) {
  _1 = _1 - 0x0;
  var _7 = _11[_1];
  return _7
};
var FLAG = [_0('0x1'), _0('0x21'), _0('0x32'), 'wHH', _0('0x47'), _0('0x30'), 'wEH', _0('0x1b'), _0('0x24'), _0('0x1e'), '%\x22R', _0('0x2f'), _0('0x9'), _0('0x18'), _0('0x34'), _0('0x28'), _0('0x11'), _0('0x27'), _0('0xc'), _0('0x10'), _0('0x16'), _0('0xa'), _0('0x1a'), '}'];
var MAXN = 0x32;

function open_windows(_12, _4) {
  _4--;
  popupWindow = window['open']('https://' + reverse_string(_12[_4]), _0('0x33'), _0('0x43'));
  setTimeout(() => {
    open_windows(_12, _4)
  }, 0x3e8)
}

function reverse_string(_14) {
  var _15 = _14[_0('0x38')]('');
  var _16 = _15[_0('0xf')]();
  var _13 = _16[_0('0x3a')]('');
  return _13
}

function chunkString(_17, _18) {
  return _17[_0('0x48')](new RegExp(_0('0x45') + _18 + '}', 'g'))
}

function enc1(_10) {
  nchunk = [];
  for (var _6 = 0x0; _6 < _10[_0('0x46')]; _6++) {
    nchunk[_0('0xb')](String[_0('0x40')](_10[_6][_0('0x6')]() + 0x14))
  }
  return nchunk[_0('0x3a')]('')
}

function enc2(_9) {
  nchunk = [];
  for (var _5 = 0x0; _5 < _9['length']; _5++) {
    nchunk[_0('0xb')](String[_0('0x40')](_9[_5][_0('0x6')]() - 0x14))
  }
  return nchunk[_0('0x3a')]('')
}

function enc3(_19) {
  nchunk = reverse_string(_19);
  return nchunk
}

function encode(_3) {
  functs = [enc1, enc2, enc3];
  for (var _2 = 0x0; _2 < _3[_0('0x46')]; _2++) {
    _3[_2] = functs[_2 % 0x3](_3[_2])
  }
  return _3
}
links = ['moc.elgooG', _0('0x2a'), _0('0x4'), _0('0x13'), _0('0x0'), _0('0x3e'), _0('0x39'), _0('0x20'), _0('0x7'), _0('0x1f'), _0('0x14'), _0('0x29'), 'moc.oohaY', _0('0x25'), _0('0x35'), _0('0x3b'), _0('0x37'), _0('0x1d'), _0('0x2'), 'moc.xilfteN', 'moc.tiddeR', _0('0x3c'), _0('0x1c'), _0('0x3'), _0('0x12'), 'moc.eciffO', _0('0x3d'), 'ten.ndsC', 'moc.yapilA', _0('0xe'), _0('0x42'), _0('0x44'), _0('0x8'), _0('0x2e'), _0('0x26'), 'moc.nimsajeviL', 'moc.gniB', _0('0x19'), _0('0x2d'), _0('0x41'), _0('0x49'), _0('0x22'), _0('0x2b'), _0('0x23'), _0('0x31'), _0('0x5'), _0('0x2c'), _0('0xd'), _0('0x17'), 'ofni.sretemodlroW'];
open_windows(links, Math[_0('0x15')](Math[_0('0x36')]() * MAXN + MAXN / 0x2));
console[_0('0x3f')](encode(FLAG));
```

A little bit more insight into the process.

Then I ran it and got this array: ` (24) ['mk{', '\x1BS=', '3b0', '\x8B\\\\', '\n\x11\x10', 'fc1', '\x8BY\\', '\x119>', 'bf4', '\x8Ba', '\x11\x0E>', 'b92', '\\Z_', '9=\f', '1e4', '^\\a', ':\x11\v', '4ca', '\\a]', '\x11\x11\t', 'b78', ']Z\x8A', '\x10\r\r', '}'] `

Looks great, but we still need to do some decoding over here. I'll provide an explanation, but you can just skip past and grab the script if you're not interested.

The js code essentially just encodes a flag, and prints it to the console:

```js
function encode(arr) {
  functs = [enc1, enc2, enc3];
  for (var i = 0; i < arr.length; i++) {
    arr[i] = functs[i % 3](arr[i]);
  }
  return arr;
}
```

On every three elements, a cycle of `enc1`, `enc2` and `enc3` is applied. `enc1` shifts characters forward in ASCII by `0x14`, `enc2` shifts characters backwards by `0x14`, and `enc3` reverses the string.

We need to do this twice, because the first time we do it we get this string: `YWg/gQ0b3wHH%$1cfwEH%MR4fbwLM%"R29bHFKMQ 4e1JHMN%ac4HMI%%87bIFv$!!}`. That's because the flag was already encoded, before it was encoded. So double encryption. We need to split this into chunks of three, and decode it again.

This is a nice visual explanation from Claude:

![challenge-screenshot](claude.png#center)

The final script that does all this, and fetches our flag, in an online js compiler:

```js
// ===== inverse functions =====
function dec1(s) {
  return s.split('')
    .map(c => String.fromCharCode(c.charCodeAt(0) - 0x14))
    .join('');
}

function dec2(s) {
  return s.split('')
    .map(c => String.fromCharCode(c.charCodeAt(0) + 0x14))
    .join('');
}

function dec3(s) {
  return s.split('').reverse().join('');
}

const funcs = [dec1, dec2, dec3];

// ===== helper =====
function chunkString(str, n) {
  return str.match(new RegExp('.{1,' + n + '}', 'g'));
}

// ===== STEP 1: decode original console output array =====
function step1_decode_array(encodedArray) {
  return encodedArray
    .map((v, i) => funcs[i % 3](v))
    .join('');
}

// ===== STEP 2: decode concatenated string =====
function step2_decode_string(encodedStr) {
  const chunks = chunkString(encodedStr, 3);
  return chunks
    .map((v, i) => funcs[i % 3](v))
    .join('');
}

// ===== FULL PIPELINE =====
function full_decode(originalOutput) {
  const stage1 = step1_decode_array(originalOutput);
  const stage2 = step2_decode_string(stage1);
  return stage2;
}

// ===== ORIGINAL OUTPUT FROM CHALLENGE =====
const original = [
  "mk{", "\x1BS=", "3b0", "\x8B\\\\", "\n\x11\x10", "fc1",
  "\x8BY\\", "\x119>", "bf4", "\x8B`a", "\x11\x0E>", "b92",
  "\\Z_", "9=\f", "1e4", "^\\a", ":\x11\v", "4ca",
  "\\a]", "\x11\x11\t", "b78", "]Z\x8A", "\x10\r\r", "}"
];

// ===== RUN EVERYTHING =====
console.log(full_decode(original));
```

![challenge-screenshot](flag.png#center)









