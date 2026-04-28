+++
date = '2026-03-12'
draft = false
title = 'php'
ShowToc = true
tags = ["Materials"]
+++


## Why

I am so sick and tired of all these php challenges, and I'm just always aimlessly trying crap from the internet without understanding half of it. This ends NOW!!

And keep in mind this is a work in progress file that I will add to when I feel the need to.

## trivia

`.php` are normal php, but `.phps` is often used to display the source code of a script with syntax highlighting.

## commands

[Amazing Source](https://angelica.gitbook.io/hacktricks/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass). Feel free to check this out. I will just be adding functions I feel are useful with a short explanation. 

About 90% of ctf challenges have to do with file upload vulnerabilities when php is involved somehow, so all the sources I found when looking for commands with blacklists and disable_functions were so, so, so bad. So sadly, these must be learned.

- `phpinfo();`

- `print_r();` - print but php; you need this to view the result of the functions you call.

- `getcwd();` 

- `scandir();` - the php *ls*, you give it the dir as a parameter. It always starts with the `.` and `..` directories.

- `reset(array)` - returns the first element of the array.

- `end(array)` - returns the last element of the array.

- `array_slice(array, offset, optional_length);` - in case you need a slice of a certain portion of the scandir, useful when `[]` is blacklisted.

- `highlight_file(file)` - just a way to display a certain file.

- `show_source(file)` - just a way to display a certain file.

- `implode()` - technically a string-maker for arrays, but turns the result into a string, which is more useful for us.

## serialization stuff

If you want to create a serialized payload, this is how that looks in php:

```php
<?php
$a = [
    "username" => "' OR 1=1;--",
    "password" => "a"
];

echo serialize($a);
// Output: a:2:{s:8:"username";s:11:"' OR 1=1;--";s:8:"password";s:1:"a";}
?>
```

Call this an associative array, or dictionary, or whatever you want. However, if you're talking about an object, it should look like this:

```php
<?php
class User {
    public $username;
    public $password;

    function __construct($u, $p) {
        $this->username = $u;
        $this->password = $p;
    }
}

// instance
$user_obj = new User("a' OR 1=1;--", "a");

echo serialize($user_obj);

// Output: O:4:"User":2:{s:8:"username";s:12:"a' OR 1=1;--";s:8:"password";s:1:"a";}
?>
```


## file uploads
