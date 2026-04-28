+++
date = '2026-04-14'
draft = false
title = 'Pico Super Serial writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

Try to recover the flag stored on this website

---

We have a login page, which upon trying any credentials, we get back the error `Fatal error: Uncaught Exception: Unable to open database: unable to open database file in /var/www/html/index.php:5 Stack trace: #0 /var/www/html/index.php(5): SQLite3->__construct('../users.db') #1 {main} thrown in /var/www/html/index.php on line 5`.

## Identifying the vulnerabilities

I tried fuzzing, and we got some interesting pages: 

![challenge-screenshot](fuzz.png#center)

The authentication.php one would just redirect to index and clear our cookies, the cookie.php one was just empty, and set us a PHP session id, and in robots.txt was `Disallow: /admin.phps`, a file which did not exist.

Looking at the error when trying to log in, it's probably a permissions issue, so the php doesn't have permission to access the `../users.db` file; Quite strange, so that's not the way to go.

What's interesting is that the `.phps` from the admin file is normally used for source code with syntax highlighting, and sure enough, looking at `index.phps`, we get to see the source code; that applies to all the other files, too.

Looking at this part of `cookie.phps`, looks like we're dealing with a php deserialization vulnerability, encapsulated as the base64 cookie "login". More on php serialization [here](https://portswigger.net/web-security/deserialization/exploiting).

![challenge-screenshot](ciikie.png#center)

So, we need an object of the class `permissions`, with a `username` and `password`, right? I tried making one, like this, `O:4:"permissions":2:{s:8:"username";s:11:"' OR 1=1;--";s:8:"password";s:1:"a";}`. But my lack of php knowledge caught up to me again; the SQL wasn't vulnerable, and the `__toString()` magic method was broken on their side, so it would have thrown an error anyways.

Now, let's take a look at `authentication.phps`:

![challenge-screenshot](auth.png#center)

Clearly the `read_log()` is our way to reach the flag - if we set the `log_file` string to "../flag" as the hint suggests, it will simply print it out. Now, the code just assumes that what we send is a `permissions` object that has an `is_admin()` method. But, we can just send anything we like!

The magic method `__toString()` of the `acces_log` object will be automatically called and it will invoke the `read_log` function. So, that's it! We sneak a different class-ed object, since no one is really checking anything.

I ran this using a php sandbox:
```php
<?php
class acces_log {
    public $log_file;

    function __construct($lf) {
		$this->log_file = $lf;
	}
}

// instance
$obj = new acces_log("../flag");
echo urlencode(base64_encode(serialize($obj)));

?>
```

However, upon loading it up in a login cookie:

![challenge-screenshot](err.png#center)

So, in `cookie.php`, it has no idea what that class could possibly be. Upon great inspection, turns out I fucking misspelled "access". I fixed that in the snippet above, got the cookie "TzoxMDoiYWNjZXNzX2xvZyI6MTp7czo4OiJsb2dfZmlsZSI7czo3OiIuLi9mbGFnIjt9", and finally, the flag:

![challenge-screenshot](fla.png#center)

