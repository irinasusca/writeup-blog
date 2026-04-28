+++
date = '2026-01-30'
draft = false
title = 'requests library'
ShowToc = true
tags = ["Materials"]
+++


## Why

Since I actually (sadly) have to learn python myself for the OSC since AIs got banned, I decided it's time to lay down the foundation of the requests library instead of letting an AI slave do the dirty python work for me. That means it's time to learn the requests library.

It really wasn't as difficult as I thought, and I really wish I'd done this sooner. Who would've ever guessed learning is really useful?

---

## Requests

Alright, let's actually get into it. The docs I used for this are [here](https://requests.readthedocs.io/en/latest/user/quickstart/).

The format of making a request is this:

```python
import requests
data = {
    "username":"test",
    "password":"test"
}
res = requests.post(url, data = data)
```

Of course we can make all kinds of requests, `requests.get`, `requests.options`, you get the idea.

We can also send parameters in a similar way:

```python
payload = {
    "param1": "val1",
    "param2": ["val2", "val3"]
}
res = requests.get(url, params=payload)
```

To check the url created by requests, just `print(res.url)`. To view the response content, just print `res.text`.

We can also modify the encoding, and view through `r.encoding` (automatically utf-8).

To add our own headers, done similarly to data:

```python
headers = {
    "Cookie": "test123",
    "Host": "127.0.0.1"
}
res = requests.get(url, headers=headers)
```

We can also send a file like so:

```python
files = {'file': ('report.xls', open('report.xls', 'rb'), 'application/vnd.ms-excel')}
#here, rb stands for read binary. just how python opens files.
#the application type is optional.

res = requests.post(url, files=files)
```

Or more files!

```python
files = [
    ('images', ('foo.png', open('foo.png', 'rb'), 'image/png')),
    ('images', ('bar.png', open('bar.png', 'rb'), 'image/png'))
]
res = requests.post(url, files=files)
```

And stream an upload:

```python
with open('massive-body', 'rb') as f:
    requests.post(url, data=f)
```

Difference is, this is a way to upload larger files, as the raw body.

We can check status code by `res.status_code`. We may test them like `res.status_code == requests.codes.ok` if we're too uncultured to recognize status codes.

To view the response headers just use `r.headers`. A specific one by `r.headers['Content-Type']` or `r.headers.get('content-type')`. Capitalization not important.

There's also a `allow_redirects` param (True or False), and a `timeout` (if no response in that time, just pack it up). 

## Hooks

We can add hooks, so functions that are called whenever a response happens. Say we have this function we want to hook:

```python
def print_url(r, *args, **kwargs):
    print(r.url)

#the args and kwargs are there just in case the response decides to throw some args in there internally.
    
requests.get(url, hooks = {'response' : print_url})
```

The response is passed as an argument to the hook function. We can stack hooks, like `hooks = {'response': [hook1, hook2]}`.

The string 'response' needs to be respected since it's the library name for an event. And apparently the *only* event. 

## Sessions

If we want to use a single session, like a normal user would, without having to write all those annoying cookies and headers every time, we can use `requests.Session()`.

```python
s = requests.Session()
s.headers.update({
    'x-test': 'true',
    'Host': '127.0.0.1'
})
```

To add a session hook, we need to do `s.hooks['response'].append(print_url)`. 

So instead of params to requests functions, we pass them as attributes of the Session object. 

---

And we're done with this library!

---

## pretty_print

Two months after I made this post, I finally had enough of reading barely legible requests and responses and I decided to do something about it. This means creating a python `pretty_print.py` to import in our scripts.

The problem is, they all look like this, with `print(res.text)`, and they get significantly harder to comprehend when there's 100 of them in a row.

![challenge-screenshot](bland.png#center)

Obviously if you need your code to run fast just don't use it, but I don't think such a troublesome bruteforce would be necessary for most ctf challenges.

You can customize the theme as you like, here are some "presets" I made:

![challenge-screenshot](coloring.png#center)
![challenge-screenshot](coloring2.png#center)
![challenge-screenshot](coloring3.png#center)

I have a `ctfweb` dir where I save all my scripts, and inside a `utils` subdir where I added the script. If you're using the same setup, you can just import it with `from utils.pretty_print import pretty_print`.

I'll drop the code here, but it can also be found on **[my github page](https://github.com/irinasusca/ctf-writeups/blob/main/misc/pretty_print.py).**

```python
# pretty_print.py

# DONT USE THIS IF YOU NEED PERFORMANCE
# obviously its not that big of a deal, just keep that in mind.
# this uses rich for text coloring and so on.
import re
from rich.console import Console
from rich.syntax import Syntax
from rich.panel import Panel
from rich.theme import Theme

#in case you want to customize your own theme, or choose one I made, just modify the "selection" var

themes = {
    "default": {
        "rich": Theme({
            "status_ok": "green",
            "status_error": "red",
            "url_dim": "dim",
            "border_normal": "blue",
            "border_flag": "bright_magenta",
            "flag_text": "blink bold yellow",
            "lexer_info": "dim"
        }),
        "syntax": "monokai"
    },
    "pink": {
        "rich": Theme({
   	    "info": "hot_pink",
    	    "url": "pale_violet_red1 underline",
    	    "status_ok": "spring_green3",
    	    "status_error": "deep_pink3",
    	    "border_normal": "magenta",
    	    "border_flag": "hot_pink",
    	    "flag_text": "blink bold hot_pink",
    	    "lexer_info": "dim"
	}),
        "syntax": "dracula"
    },
    "arctic": {
        "rich": Theme({
            "status_ok": "medium_spring_green",  
            "status_error": "indian_red",        
            "url_dim": "light_sky_blue1 underline dim",
            "border_normal": "steel_blue",       
            "border_flag": "cyan1",              
            "flag_text": "bold black on cyan1", 
            "lexer_info": "grey70"
        }),
        "syntax": "nord"  
    }
}

# SELECT YOUR THEME HERE!
selection = "pink"  # "pink" or "default" etc
active = themes[selection]
console = Console(theme=active["rich"])


def pretty_print(res):

    # status summary
    status_style = "status_ok" if res.status_code < 300 else "status_error"
    console.print(f"[{status_style}] {res.status_code} {res.reason} [/{status_style}] | [url]{res.url}[/url]")

    # content type for the highlighter
    ctype = res.headers.get('Content-Type', '').lower()
    lexer = "json" if "json" in ctype else "html" if "html" in ctype else "text"

    # look for the flag with regex. 
    flag_patterns = r"\b(ctf|unr|ocsc|ocsj|rocsc|flag)\{.*?\}"
    found_flag = re.search(flag_patterns, res.text, re.IGNORECASE)

    # prepare the Body
    syntax = Syntax(res.text, lexer, theme=active["syntax"], word_wrap=True)
    
    if found_flag:
        title = f"[flag_text]🚩 POTENTIAL FLAG DETECTED: {found_flag.group(0)}[/flag_text]"
        border_style = "border_flag"
    else:
        title = f"[lexer_info]{lexer} output[/lexer_info]"
        border_style = "border_normal"

    # print the result
    console.print(Panel(syntax, title=title, border_style=border_style))
```
