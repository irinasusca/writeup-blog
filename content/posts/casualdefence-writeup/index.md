+++
date = '2026-03-29'
draft = false
title = 'CyberEdu casual-defence Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++

I haven't done a web challenge outside a ctf in quite a while, so let's see how this goes!

## Challenge overview

In light of recent events related to the cyber attack, we have prepared a mirror environment of the defaced website so you can have a look. Moreover, both the mirror and production environments retain a copy of the defacement file and up-to-date security policies that prevent any access to our systems.

---

Opening the website, we just get back the text *Hacked by NotRealH4ck3rN4m3! You shall not elevate me!*. Doing a ffuf reveals only the .htpasswd and .htaccess forbidden files, so we're working with Apache here.

## Identifying the vulnerabilities

OPTIONS didn't reveal anything and fuzzing more didn't either. I tried looking online for the hacker name but didn't find anything. And this just seemed to return 200 at about anything we throw at it.

There was also a forbidden *.html* file, along the classic apache ones.

The challenge description suggests we have to find a copy of the defacement file and the *up-to-date security policies*. There isn't any CSP in the headers of the response, so what the hell is that supposed to mean? 

I tried adding custom headers, about all of them, but nothing.

Doing `/index.php/anything` would just return 200, but adding `/index.php/../test` would suddenly turn to 404... but I left it at that.

---

After about a 3 week break, because of the finals exams simulations I begrudgingly studied for, I finally returned to this, and I tried this again. The issue was I was trying to fuzz for a parameter using the `dirb/common.txt` file. Very clever. I downloaded `seclists` and finally got a hit:

![challenge-screenshot](HIT.png#center)

Yeah I changed the terminal look on my kali, glad you noticed! Moving on, I tried fuzzing the parameter values, and some started hitting a blacklist (the 200 just meant Try Harder! here).

![challenge-screenshot](tryharder.png#center)

The blacklist consists of `.`, `exec`, `system`, `shell`, `'`, `"`, `/`, `$`, `[` and so on. URL encoding the whole thing didn't bypass this.

So, this is most likely some sort of php RCE, so let's look into it. 

At first, doing a `GET /index.php?cmd=phpinfo();` worked immediately, so we're on the right path.

![challenge-screenshot](disabled.png#center)

And here is our situation. `cmd=print_r(getcwd());` does show us */var/www/html*, and we can view its contents:

![challenge-screenshot](files.png#center)

Now, sadly, we can't use closed brackets to access any one of the elements. But I snooped around and found this StackOverflow conversation: 

![challenge-screenshot](stacky.png#center)

But this only let us properly view the first `.` and the last useless file. So I needed a way to remove the dots from the scandir. More StackOverflow:

![challenge-screenshot](stacky2.png#center)

Awesome! So `cmd=print_r(array_slice(scandir(getcwd()),2));` now begins with *index.php*. So we can single it out with `cmd=print_r(reset(array_slice(scandir(getcwd()),2)));`. Now, we can just swap the `print_r` with `highlight_file` and there we have it!

![challenge-screenshot](flag.png#center)


