+++
date = '2026-01-15'
draft = false
title = 'CyberEdu rundown Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++

## Challenge overview

A rundown, informally known as a pickle or the hotbox, is a situation in the game of baseball that occurs when the baserunner is stranded between two bases, also known as no-man's land, and is in jeopardy of being tagged out." ... if you stopped in the first part of the definition you are one of ours.

---

![challenge-screenshot](pin.png#center) 

This is *EXACTLY* like [slightly-broken](irinasusca.github.io/writeup-blog/slightly-broken) (you could take a look at it, it's short), except the `pin` things are actually being used!

## Identifying the vulnerabilities

Because of this message, *You can find the PIN printed out on the standard output of your shell that runs the server.*, I thought about doing an `nmap` to see if there's any interesting ports open.

There were, but it was a bunch of other challenges.

I stopped using LLMs and googled for known exploits, and **[getting the pin ourselves](https://angelica.gitbook.io/hacktricks/network-services-pentesting/pentesting-web/werkzeug)** *IS* possible, but we need some sort of path traversal vulnerability. 

In the last challenge, we had access to the error page directly, but this time we need a way to reach it by ourselves. sending a `POST` request with curl gives us this!

![challenge-screenshot](err.png#center) 

I almost missed this because I didn't feel like reading the entire page. Alright, so this `POST` accepts some data, in which we aren't allowed to add `' '`, and `pickle` is the one who takes care of this.

Let's talk about `pickle` a little bit. It's an object serialization for python, that can serialize functions, classes, all that. Please read this [document](https://dev.to/leapcell/hacking-with-pickle-python-deserialization-attacks-explained-2gkl).

Since this challenge uses python 2.7, we also need to use python 2.7. And I used an online compiler because I am *not* wrestling with installing crap I'm only using once on kali.

![challenge-screenshot](2.7.png#center) 

This didn't work. I tried a sleep command too, but didn't work either. I got stuck for a while, and I found the gotcha in another writeup. Flask does this thing, where if it recognizes the Content-Type of our body, it consumes it and puts it somewhere else like `request.form`, `request.json`, whatever.

This means our body aka `request.data` becomes a big `b""`. So we need to send a Content-Type it has no idea about, like for example, `application/testing`. 

This time, my `(time.sleep, (5,))` command worked! By this I mean, it took them 5 to respond. I tried using `os.system`, but that didn't work, because since it was spawning a separate process, I couldn't see the I/O. And creating files didn't work. So we have to use `eval`, because it's executed in the same process as the pickle.

And to actually see what's getting displayed, we need to raise an exception, like we did by sending a bad POST. 

The final working payload was
```python
import cPickle
import base64
import os

class X(object):
    def __reduce__(self):
        return (eval, ("eval(open('flag').read())",))

payload = cPickle.dumps(X(), protocol=2)
print(base64.urlsafe_b64encode(payload))
```

Because it would first `eval` and fetch the flag contents, and then display an error about `eval`ing it. 


![challenge-screenshot](flag.png#center) 

I guess that's it!



