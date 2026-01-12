+++
date = '2026-01-10'
draft = false
title = 'CyberEdu ping-station Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++

## Challenge overview

Just another ping service to audit.

---

We get an `app(1).py` file to look at.

```python
from flask import Flask, render_template, url_for, request, redirect

import subprocess
import re
import string

app = Flask(__name__)

def is_valid_ip(ip):
    ipv = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\S{1,9})|(/s)\.(\d{1,3})$",ip)
    return bool(ipv) 

@app.route('/', methods=['POST', 'GET'])
def index():
    if request.method == 'POST':
        ip = request.form['content']
        if (is_valid_ip(ip)==True):
            for i in range(0,2):
                return '<pre>'+subprocess.check_output("ping -c 4 "+ip,shell=True).decode()+'</pre>'
                break
        else:
            return"That's not a valid IP"
    else:
        return render_template('index.html')

if __name__ == "__main__":
    app.run(host = "0.0.0.0")
```

## Identifying the vulnerabilities

Looking at that `"ping -c 4 "+ip,shell=True)`, if we manage to smuggle a command past this `is_valid_ip` function, it will get executed.

Let's look at this:
`ipv = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\S{1,9})|(/s)\.(\d{1,3})$",ip)`

The first part, `\d{1,3})\.(\d{1,3})\.(\S{1,9})`, is a `x.y.z`, where `x` and `y` are up-to-three numbers and `z` is any non-whitespace. 

The second one, `(/s)\.(\d{1,3})$`, checks whether it's a `/s.x` where `x` is an up-to-three digit number. 

So we can just craft our command.

![challenge-screenshot](pic1.png#center) 

And here is our flag:

![challenge-screenshot](pic2.png#center) 


---






