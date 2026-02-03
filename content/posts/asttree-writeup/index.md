+++
date = '2026-01-29'
draft = false
title = 'CyberEdu ast-tree Writeup'
ShowToc = true
tags = ["CyberEdu", "misc"]
+++


## Challenge overview

A careless developer left behind some code that reads sensitive files directly from disk.

---

We're prompted with a "Paste your AST-Grep YAML rule here" and an option to run it. `ast-grep` is a code tool for structural search and replace, like syntax-aware grep.

We can also use jQuery like utility methods to traverse syntax tree nodes.


## Identifying the vulnerabilities

Upon entering an invalid file, we get this ChatGPT written error:

```bash
✅ Output:
Error: Cannot parse rule /tmp/psu6fojepi.yaml
Help: The file is not a valid ast-grep rule. Please refer to doc and fix the error.
See also: https://ast-grep.github.io/guide/rule-config.html

✖ Caused by
╰▻ Fail to parse yaml as RuleConfig
╰▻ invalid type: string "node napi.js", expected struct SerializableRuleConfig
```

Trying `grep flag`, we get `🚫 Blacklisted keyword "flag" detected!`.

They even give us the docs, can it get easier than this?!

The format of a rule looks something like this:
```sh
id: no-await-in-promise-all
language: TypeScript
rule:
  pattern: Promise.all($A)
  has:
    pattern: await $_
    stopBy: end
```

I told myself I won't be using ChatGPT anymore since OSC is interdicting it, so I actually read docs and Stack Overflow questions for this. 

So we can find a string through the `regex` instead of `pattern` (search for the actual string through rust's regex finder), but we need to specify the `kind`, which was `string` in this case. Adding the `all` specifier for `rule` was what made it work, finally. And I looped through some languages, and js was the winner in this case.

Anyway, here's the full rule and the flag:


![challenge-screenshot](flag.png#center)









