+++
date = '2026-03-31'
draft = false
title = 'sql'
ShowToc = true
tags = ["Materials"]
+++


## Why

SQL injection is a pretty boring subject to me but I ran into it through some pico challenges so I thought I'd make some notes anyways. sqlmap usage is probably necessary just for really beginner ctf challs, but I'll include it anyways. 

Obviously this stuff is not that hard to google yourself, so don't think of this as a *complete guide*, just as my own personal notes because I will most likely forget about this in a week.

## sql

To get SQLi, you need to get SQL. And it really doesn't hurt to know this stuff. [Great source](https://www.w3schools.com/sql/).

The first type, *Data Definition Language*, where you define tables and such.

- `CREATE` 
  - `CREATE TABLE user (id INT PRIMARY KEY, username VARCHAR(50));`

- `ALTER` 
  - modify a db structure, like add a constraint, column, etc: 
  - `ALTER TABLE user ADD COLUMN email VARCHAR(100);`

- `DROP`
  - deletes a table: 
  - `DROP TABLE user;`

- `TRUNCATE` 
  - just removes all records, but doesn't delete the table.
 
Next up is *Data Manipulation Language*, where you work with entries rather than the tables themselves.

- `SELECT` 
  - fetches data: 
  - `SELECT username, email FROM user WHERE id = 1;`

- `INSERT` 
  - add new rows: 
  - `INSERT INTO user (id, username) VALUES (2, 'fufu');`

- `UPDATE` - update data: 
  - `UPDATE user SET email = 'fufu@gmail.com' WHERE id = 1;`

- `DELETE` 
  - `DELETE FROM user WHERE id = 1;`

Now, let's go over the logical operators.

- `OR`
  - `SELECT * FROM user WHERE (role = 'admin' OR role = 'staff');`
  - this might seem familiar due to the classic `' OR '1'='1` SQLi.

- `AND`
  - `SELECT * FROM user WHERE role = 'default' AND money > 500;`
  
There is also a "wildcard":

- `LIKE`
  - in sql, `%` means any number of characters while `_` means a single character.
  - `SELECT * FROM products WHERE name LIKE 'ctf%';` matches ctf{a}, ctfbubu etc.
  - in SQLi, for blind SQLi you can guess stuff character by character like `AND password LIKE 'a%'`.

Finally, for combining data:

- `UNION` 
  - combines the result of two or more `SELECT`. They MUST have the same number of columns and compatible data types:
  - `SELECT location FROM user UNION SELECT location FROM shop;`
  - this is also used in SQLi to exfiltrate data, e.g. `UNION SELECT null, username, password from user--`.

- `JOIN`
  - links tables based on a common column, usually a *foreign key*.
  - `INNER JOIN` means A ∩ B
  - `FULL JOIN` means A ∪ B
  - `LEFT JOIN` means A and matching rows from B
  - `RIGHT JOIN` means B and matching rows from A
  - `SELECT user.username, oder.amount FROM user INNER JOIN order ON user.id = order.user_id;`
  
There is also a separate category for this one:

- `GROUP BY`
 - this is used for grouping stuff together. Like, if you have a bunch of orders, made by users, for items with different prices, and you want to see how much each user spent.
 - `SELECT user_id, SUM(price) AS total_spent FROM order GROUP BY user_id`.
 - to filter, we don't use the where, but `HAVING`.
 
Often group by is used with something called *Aggregate Functions* aka math helpers:

- `COUNT()`
  - `SELECT category, COUNT(*) AS items_count FROM products GROUP BY category;`
- `SUM()`
- `MAX()` 
  - finds the biggest fish in the bucket; like, if you have some items with price = 10 and one with price = 20, for the same user, and you use `GROUP BY user_id`, it will display the one with the biggest price.
- `MIN()`
- `AVG()` calculates the average.

These were the most relevant ones. There are also some "miscellaneous" things you ought to know, for blacklists and such; I will update this list as I go:

- Concatenation
 - for example, the word "admin" is blaclisted;
 - `'ad'||'min'` (SQLite)
 - `CONCAT('ad','min')` (MySQL)
 - `'ad'+'min'` (MSSQL)
 
- Double url-encoding
 - if `'` is blacklisted, and so is its `%27` form, then `%2527` which decodes to `%27` might not be.
 
- Spaces 
 - when, blacklisted can just be replaced with a `/**/`.
 
- `IS NOT`
 - like in Web Gauntlet 2, where just about anything was banned, we needed to turn the password=something into a true statement
 - injecting `password="a' IS NOT 'b"` worked, because it's checking FALSE is not 'b'.
 - usually this is used as `IS NOT NULL`, but it can be useful to us in this other way.
 
- `BETWEEN`
 - when > and < are blocked, we can use `column BETWEEN 'a' AND 'z'`.
 
- `IN`
 - when = is blacklisted, doing something like `OR '1' IN ('1')--` would work.
 
- `GLOB`
 - when `LIKE` is blacklisted, `WHERE password GLOB '*'` 

 
## sqlmap

For this, the way I do it is I save my request as text in Burpsuite as `request.txt`. Now let's get into parameters:

- `-r request.txt` (pretty straight-forward)

- `-u http://link.com?id=1`

- `-v`:

   - `-v 3` shows the payloads being sent;
   
   - `-v 4` shows the requests
   
   - `-v 5` shows the responses
   
   - `-v 6` just shows the whole raw page.

- `--dbms=sqlite` in case you already know the db engine; this just skips fingerprinting;

- `--level=5` increases the number of payloads and includes headers in the scan;

- `--risk=3` enables the heavier payloads, whatever that means;

- `--batch` just says yes to all the annoying prompts.

- `--random-agent` in case a WAF gives you trouble;

- `--tables` dumps the NAMES of the tables found;

- `--dump` actually dumps the data;

- `-A agent`

- `-H header`

- `--host=example`

- `--cookie=example`

Sometimes we know that injection was successful based on the text in the response. For example, if the wrong query results in `Invalid captcha`, you might wanna add `--not-string="Invalid"`. Or, on the contrary, `--string="Success!!!!!"`.

## table stuff

For SQLite, which I see extremely often, the table names can be extracted with `'UNION SELECT name FROM sqlite_master--`.
