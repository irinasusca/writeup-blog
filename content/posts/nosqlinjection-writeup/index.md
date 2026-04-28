+++
date = '2026-04-20'
draft = false
title = 'Pico No Sql Injection writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

Can you try to get access to this website to get the flag?

--- 

We have access to the source, the most interesting part being this:

```js
const initialUser = new User({
      firstName: "pico",
      lastName: "player",
      email: "picoplayer355@picoctf.org",
      password: crypto.randomBytes(16).toString("hex").slice(0, 16),
    });
    await initialUser.save();
    
#...
    
app.post("/login", async (req, res) => {
      const { email, password } = req.body;

      try {
        const user = await User.findOne({
          email:
            email.startsWith("{") && email.endsWith("}")
              ? JSON.parse(email)
              : email,
          password:
            password.startsWith("{") && password.endsWith("}")
              ? JSON.parse(password)
              : password,
        });

        if (user) {
          res.json({
            success: true,
            email: user.email,
            token: user.token,
            firstName: user.firstName,
            lastName: user.lastName,
          });
        } else {
          res.json({ success: false });
        }
      } catch (err) {
        res.status(500).json({ success: false, error: err.message });
      }

```


## Identifying the vulnerabilities

This is a Mongo db, with nosql, as suggested by the challenge name. What's immediately interesting is that the email and password are parsed as *json*. Here is a portswigger [article](https://portswigger.net/web-security/nosql-injection) talking about NoSQL injection. I also watched [this video](https://www.youtube.com/watch?v=zHxgZJCy9fA).

The problem was, I kept getting errors related to the `startsWith`. The `startsWith` requires its argument to be a string. So entering json, to make it consider itself json, would break it; it needed to start with a "{", not {.

![challenge-screenshot](startswith.png#center)

At this point I'm going crazy, I was looking up JSON parsing and how to avoid errors, since the app was using `JSON.parse`: if it's a valid json once parsed, it SHOULD work! 

![challenge-screenshot](parse.png#center)

So why sending this: `{"email": "picoplayer355@picoctf.org", "password": '{"$ne":"foo"}'}` would give me a `SyntaxError: Unexpected token ' in JSON at position 54`? I guess it was upset that I was trying to send a '' string in JSON instead of the expected "".

We need a way for our json password's value to be considered as the string `'{"$ne":"foo"}'`. The final payload that worked was `{"email": "picoplayer355@picoctf.org", "password": "{\"$ne\":\"foo\"}"}`; Just making sure that the value string wasn't escaping through the "" inside it.

![challenge-screenshot](json.png#center)
