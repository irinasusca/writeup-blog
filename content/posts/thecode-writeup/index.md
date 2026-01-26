+++
date = '2026-01-25'
draft = false
title = 'CyberEdu the-code Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++

## Challenge overview

Look, the code is there. Enjoy.

## Identifying the vulnerabilities

More php fun.

![challenge-screenshot](src.png#center)
 
We have two arguments here, `start` (actually start the challenge) and `arg`. Then, after blacklisting the following in `arg`: `php > & $ :`, they execute `shell_exec("find /tmp -iname ".escapeshellcmd($_GET['arg']))`.

That means they return the `toupper` version of what that command returns, which is b64 encoded, and more exactly the result of the files that are named like `arg` in /tmp.

They are using `.escapeshellcmd`. I had to google that, and here is what it does - 

![challenge-screenshot](escape.png#center)

So, before any shell-injection-character, it adds a backslash, meaning it just ends up getting cockblocked.

Sending `?arg=*` gives us a `L3RTCAOVDG1WL3N0YXJ0LNNOCG==` response. In case you didn't notice what's wrong, is that the `toupper` destroys the b64 string, since b64 is case sensitive.

I ran a script that bruteforced the possible pre-uppered b64 and the closest thing to an ASCII I got was this - 

![challenge-screenshot](test.png#center)

So we do have a start.sh file in /tmp. No flag though.

And since all our evil commands are getting sanitized, I started looking into `escapeshellcmd` vulnerabilities, and turns out we can use multiple parameters.

![challenge-screenshot](vulny.png#center)

Then I bumped into this [goldmine](https://github.com/kacperszurek/exploits/blob/master/GitList/exploit-bypass-php-escapeshellarg-escapeshellcmd.md).

![challenge-screenshot](win.png#center)

Looks familiar right? 

So we need to send something like `GET /?arg=sth -or -exec ls ; -quit&start=1 HTTP/1.1` (url encoded of course).

We find a `index.php` and `flag` after a `ls` - since the message was short - but we get this really long response for `cat flag`: `Y3RMEZM4MGEXYZAYMGM0NGYYZJI5MJNINTCYMTE1ZTK1MJK0YMI2MJJMNGRLMZI4NJRJZJNJZTNHNTI0YJQWZTU2N2R9` . So is it time to put our 32GB RAM to good use?

The `// Do not even think to add files.` comment is obviously a hint to save us a couple of hours; what if we paste the flag over index.php? Strange that they're in the same folder already.

I tried accessing `/flag` to check its behavior, and the flag's already there. I'm guessing someone solved this challenge and we're working in the same instance as them already. But the challenge flow would've been something like what I started doing.

Anyways, here's the flag!

![challenge-screenshot](flag.png#center)

---




