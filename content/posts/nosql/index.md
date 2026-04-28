+++
date = '2026-03-31'
draft = false
title = 'nosql'
ShowToc = true
tags = ["Materials"]
+++


## Why

Why not 

## nosql

[Video](https://www.youtube.com/watch?v=zHxgZJCy9fA).

Unlike SQL, NoSQL (not only SQL) works without relational tables; It's often used when you can't be sure enough about the definite structure of an object to make it into a table.

So, think of JSON, with some columns being optional; This is often used with documents for blog apps. Or, maybe a graph structure, with nodes being users and arcs being relationships between them. There's a bunch of different stuff you can do, and its usage is pretty different to SQL. We're using *collections* instead of tables. 

Most often used for nosql are MongoDB and maybe Redis.

Everything I'm about to say is also written in the NoSQL [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection) page, but I'm doing this to memorize the essentials.

The operators, that you can pass as json, to inject stuff like `{"price":{ "$gt": 0 } }` are:

- `$ne`: not equal

- `$regex`: ...

- `$gt`: greater than

- `$lt`: lower than

- `$nin`: not in

Obviously, if you have to pass the json as a string, escape the " characters inside it with a backslash.
