+++
date = '2026-01-30'
draft = false
title = 'requests library'
ShowToc = true
tags = ["Materials", "web"]
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
