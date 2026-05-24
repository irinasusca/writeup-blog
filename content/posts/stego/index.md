+++
date = '2026-05-14'
draft = false
title = 'steganography'
ShowToc = true
tags = ["Materials"]
+++


## Why

I have some notes in a text file on my kali VM, so I'm just going to be dumping that here.

---

```bash
binwalk
	#Combining two flags recursively extract firmware file
 	binwalk -Me --dd=".*" firmware.bin
 	Use binwalk -Mve to recursively extract files. It's super cool!
 	! gunoiul asta daca ii dai -e nu iti zice tot timpul ca exista
 	

binwalk
zsteg
stegsolve
exiftool
steghide / stegseek
CyberChef
Audacity
HxD

java -jar stegsolve.jar
zsteg -a img.png
foremost

# Analyze key length
xortool mystery.bin

# Guess key length = 5, most common byte = 0x00 (for binary/nulls)
xortool -l 5 -b 0x00 mystery.bin (on ctfweb)

# If you expect printable text output
xortool -l 5 -c ' ' mystery.bin   # space is most common English byte

# Single-byte XOR brute force (all 256 keys)
xortool-xor -f mystery.bin        # then inspect outputs
Output: generates 256+ candidate files — use xortool-guess or grep for known strings:
bashxortool mystery.bin
cd xortool-out/
grep -rl "flag{" .
grep -rl "CTF" .
grep -rl "PK" .    # 


#audio:
#spectogram
sox audio.wav -n spectrogram -o spec.png

#convert format 
sox audio.mp3 audio.wav

#reverse audio 
sox audio.wav reversed.wav reverse

#view waveform 
sox audio.wav -n stat          # statistics
sox audio.wav -n stats         # more detailed stats

#separate channels
sox stereo.wav left.wav remix 1     # left channel only
sox stereo.wav right.wav remix 2    # right channel only
```


