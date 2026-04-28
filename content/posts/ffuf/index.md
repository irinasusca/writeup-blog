+++
date = '2026-03-12'
draft = false
title = 'ffuf'
ShowToc = true
tags = ["Materials"]
+++


## Why

I realized I don't know how to use this outside of just specifying a website and a wordlist. Well, here is everything (relevant) it can do.

## ffuf

[Source](https://hackviser.com/tactics/tools/ffuf).

Here's what to keep in mind:

 - `-X POST` - if you want to try different HTTP methods.
 
 - `-H "Authorization: Bearer token"` - add your own headers.
 
 - `-w /path/wordlist1.txt:/path/wordlist2.txt` - multiple wordlists at the same time.
 
 - `-p 10` - limit the amount of concurrent requests; if you don't want to dos by mistake.
 
 - `-r` - follow redirects.
 
 - `-d 2` - set delay between requests (in seconds).
 
 - `-fr "regex"` - filter by regex. So doesn't show responses containing that regex.
 
 - `-c` - add pretty colors.

 - `-fc` - filter code, if I don't want to see any 404, just add it to this flag.
 
 - `-mc` - just show me this specific code.
 
 - `-e .js,.html,.txt`  - try all of these extensions after the words in the wordlist.
 
 - `--recursion --recursion-depth 2` - self explanatory
 
 I usually use the `/usr/share/wordlists/dirb/common.txt` wordlist for directory fuzzing, as it usually does the trick for most ctf challenges, accompanied by file extensions in some cases. Although sometimes, I admit, `rockyou.txt` is needed.
 
 For parameter fuzzing, I'd say `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt`. For this you can just run `sudo apt -y install seclists` for kali.
 
