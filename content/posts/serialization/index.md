+++
date = '2026-01-08'
draft = false
title = 'Serialization and Deserialization'
ShowToc = true
tags = ["Materials", "web"]
+++


## Why

I decided to get more into this subject because of the challenge **[jargon](irinasusca.github.io/writeup-blog/posts/jargon-writeup/)**. I was struggling with AIs and it was really getting on my nerves, because I felt I didn't *really* understand what was going on. So I decided to write a little article about this, to make myself fully grasp serialization, deserialization and the subset of vulnerabilities that may come with them. So, let's get into it.

---

## What are they?

First of all, let's clarify serialization and deserialization. I'm going to be getting most of my information from this [Portwsigger Lab](https://portswigger.net/web-security/deserialization). 

>  Serialization is the process of converting complex data structures, such as objects and their fields, into a "flatter" format that can be sent and received as a sequential stream of bytes. Serializing data makes it much simpler to:
> - Write complex data to inter-process memory, a file, or a database
> - Send complex data, for example, over a network, between different components of an application, or in an API call

So essentially, just packing something like an object into something tighter, so that it doesn't take up that much space.

>Deserialization is the process of restoring this byte stream to a fully functional replica of the original object, in the exact state as when it was serialized. The website's logic can then interact with this deserialized object, just like it would with any other object. 

This is the server interpreting that data in a way to make it usable again.

![challenge-screenshot](diagram.jpg#center)

Every language handles this differently. The main ones are *PHP*, *Ruby*, *Java* and *python*.

---

## Vulnerabilities

Insecure deserialization comes when the server deserializes user-controlled data. This way, we could send harmful data that will affect the application. We could even send a serialized object of an entirely different class than expected, and the website would just deserialize it like normal.

This is why this is sometimes called an *object injection* vulnerability.

To avoid this, ideally, user input should just *never* be deserialized. When is trusting the user ever a good idea?

Some people don't do this though, and add their on deserialization-protection-sanitization-logic which can always be bypassed, you simply can't account for everything. 

---

## Exploits

Now, the interesting part; How can we take advantage of this educationally? And how can we identify them?

**PHP**:

- uses a human-readable format, with letters representing the data type, and numbers representing the length of each entry.
- data: `$user->name = "carlos"; $user->isLoggedIn = true;`
- serialized: `O:4:"User":2:{s:4:"name":s:6:"carlos";s:10:"isLoggedIn":b:1;}`

The native PHP methods for this are `serialize()` and `deserialize()`. Just investigate around the `deserialize()`.

Here, keep in mind these (older) `7.x` PHP vulnerabilities:
- 5 == "5" or 5 == "5 lalala" both are evaluated as true
- 0 == "string" is always true

So just replacing the password with `0` would grant auth.

**Java**:

- uses binary serialization, obviously harder to read
- always begin with the same bytes; `ac ed` in hex, `ro0` in Base64
- classes that implement `java.io.Serializable` can be serialized and deserialized. 

Look for any code using `readObject()`, used to read and deserialize.

---



## Magic Methods

We also need to talk a little bit about *magic methods*. They're a "special subset of methods that you do not have to explicitly invoke". They happen a lot in OOP, and sometimes they have that `__` prefix.

They're added by developers to control what code should be executed when a scenario occurs. That sounds complicated, but take for example the PHP `__construct()`, or the python `__init__`, it's something that happens when the object is instantiated. Developers can make their own such methods, for anything. 

Why is this relevant whatsoever you may ask? It's because some languages have magic methods that are invoked automatically during deserialization. 

PHP's `unserialize()` looks for and invokes an object's `__wakeup()` magic method.

`__wakeup()` has a sibling `__sleep()` and they're needed because some properties shouldn't be serialized using the `serialize()` function. To let PHP know which properties should be ignored and which shouldn't, we use:
- `__sleep()` for returning an array of all the properties that should be included in the serialized object, and a *null* for properties that shouldn't; It's called before serialization to let PHP know which properties should be included in the string representation
- `__wakeup()` for any initialization code that should be executed once the object has been re-created. Like internal object relationships, configuration stuff...

Java's `ObjectInputStream.readObject()` reads the data, and acts like a sort of constructor for re-initializing a serialized object. But `Serializable` classes can also declare their own `readObject()` method, that acts like that `__wakeup()` thing I mentioned. This stuff is important for more advanced exploits, though.

---

## Injecting Objects

As I said before, injecting arbitrary objects is possible sometimes. In OOP, the methords available to an Object are determined by its class. So, if you manually change that class, we can influence the code executed around deserialization.

If you have access to the source code, you can study all the classes, and their magic methods and whether they have any malicious potential to be used. 

Aka using a different class' methods on our injected Object. 

---

## Gadget chains

>A "gadget" is a snippet of code that exists in the application that can help an attacker to achieve a particular goal. 

Like our ROP gadgets in pwn, I guess we have gadgets here too! 

We have pre-built gadget chains, since manually finding them is a total pain, and we have a couple of tools for that, like `ysoserial`:

- Install from [here](https://github.com/frohoff/ysoserial)
- Choose a gadget chain, pass a command

You need Java 8 because of course it's not compatible with newer Javas; If you want to use Java 16 and above, you need a bunch of command line arguments:

```python
java -jar ysoserial-all.jar \
   --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
   --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
   --add-opens=java.base/java.net=ALL-UNNAMED \
   --add-opens=java.base/java.util=ALL-UNNAMED \
   [payload] '[command]'
```

There's a lot of trial and error that comes with this.

For PHP-based sites, they're called *PHP Generic Gadget Chains* (PHPGGC).

Even if there's no tools for exploiting gadget chains, you could just look online for documented exploits (duh).

---

## PHAR deserialization

This is the special case in PHP, where we can exploit deserialization without the obvious use of the `unserialize()` mentioned earlier. 

PHP has some special wrappers for different protocols when accessing file paths; For example, `phar://`, an interface to access PHP archive (`.phar`) files.

This is very interesting; `PHAR` manifest files contain *serialized metadata*, and if we perform any filesystem operation on it, this metadata gets deserialized. So if we can pass this stream into a *filesystem method*, there's our vuln.

Some dangerous *filesystem methods* are `include()`, `fopen()` (more protected) and `file_exists()` (usually not so protected).

This is when we can upload a `PHAR`, maybe tricking the server into thinking its a `jpg` or something. If we can force the website to load this jpg-phar with the `phar://` stream, any harmful injected metadata will be deserialized! This doesn't check whether the extension is `jpg` and whatnot, just loads it. 

This way, both the `__wakeup()` and `__destruct()` magic methods can be invoked. 
