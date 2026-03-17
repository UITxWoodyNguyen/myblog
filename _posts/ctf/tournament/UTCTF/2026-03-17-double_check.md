---
title: "Double Check - UTCTF 2026 write up"
date: 2026-03-17
categories: [CTF, Tournament]
tags: [UTCTF, OSINT]
description: "No Description"
---

## Challenge Description
We're planning on deploying some new static sites for our officers. We've cloned a template from Hugo's Static Site Generator (SSG). Can you make sure that our website is clean before it's deployed?

> https://github.com/Jarpiano/utctf-profile

## Osint Path
Based on the description, we first cloned the GitHub repository; here is the repository tree:
> [tree.sh](https://github.com/UITxWoodyNguyen/CTF/blob/main/UTCTF-2026/misc/double-check/tree.sh)

Next, try checking the git log:
```bash
$ git log --oneline --max-count=30
ff2ac47 (HEAD -> main, origin/main, origin/HEAD) updated site
a1546af added key file to integrate with AWS
b5b893f new clone
3d3bbd7 Support adding content after "about" section (#994)
0450553 Move counterdev to the end of body (#993)
b476d77 SFMono-Regular is not recognized by Firefox, uses the standard name "SF Mono" (#990)
a3d7d40 Add Counter.dev analytics support (#988)
eea6dfd Adds `rel` parameter to the social icons configuration documentation (#987)
145401d Added TOC support (#985)
cb13ec4 Fix pagination (#979)
a5fc33e Upstreaming updates to theme to be compatible with Hugo v0.146.0 >= (#981)
70c0792 Remove trailing space from headline. (#970)
4b61a60 fix: don't wrap external link CSS content (#967)
6bc0059 Catalan il8n (#957)
```

From the result, we can see a suspicious commit:
```bash
a1546af added key file to integrate with AWS
```

Inspecting that commit shows:
```bash
$ git show --name-status a1546af
commit a1546afedb6edeffa9227d70b1f5e110bda9f7e6
Author: Jarpiano <barcousticjp@gmail.com>
Date:   Thu Mar 12 10:33:12 2026 -0500

    added key file to integrate with AWS

A       static/fonts/secret-keys/AWS-key.txt
```

The result includes a path to `AWS-key.txt`; showing the file's contents revealed the flag:
```bash
$ git show a1546af:static/fonts/secret-keys/AWS-key.txt
utflag{n07h1n6_70_h1d3}
```