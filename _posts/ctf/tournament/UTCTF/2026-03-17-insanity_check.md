---
title: "Insanity Check - UTCTF 2026 write up"
date: 2026-03-17
categories: [CTF, Tournament]
tags: [UTCTF, OSINT]
description: "No Description"
---

## Challenge Description
After a gap year, the sequel to "Insanity Check: Redux" and "Insanity Check: Reimagined" is finally here!

The flag is in CTFd, but, as always, you'll have to work for it.

(This challenge does not require any brute-force -- as per the rules of the competition, brute-force tools like dirbuster are not allowed, there is a clear solution path without it if you know where to look.)

## Osint Path
The challenge description tells us that the flag is in CTFd. Because this contest platform uses CTFd, we predicted the flag might be located somewhere on the contest site.

Inspecting the contest site, when we accessed `https://utctf.live/robots.txt` we found two hidden `.html` files: `/2065467898.html` and `/3037802467.html`:

![robot](https://www.notion.so/image/attachment%3A0a1b2a66-de5d-46de-a557-b811cf1ac0c8%3Aimage.png?table=block&id=3261b638-5371-8095-a2cf-d9bd033f7aeb&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=880&userId=&cache=v2)

Both files returned 404 Not Found when opened:

![404_1](https://www.notion.so/image/attachment%3A8e897dbe-e154-43b2-aeb7-888ccd3d2918%3Aimage.png?table=block&id=3261b638-5371-80f4-80ec-cf0ff223ef81&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1410&userId=&cache=v2)

![404_2](https://www.notion.so/image/attachment%3A9f1c0362-b2a6-4591-92bd-d9ae269136c1%3Aimage.png?table=block&id=3261b638-5371-80b0-b8a3-dd49b5a00bf0&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1410&userId=&cache=v2)

However, viewing the source of the two hidden files, we found a suspicious array of numbers:

![string](https://www.notion.so/image/attachment%3A2a30cf08-73fb-49f0-baf5-f5a551d79f4d%3Aimage.png?table=block&id=3261b638-5371-80f6-b83f-f6a5619b85d2&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1410&userId=&cache=v2)

This looks like XOR-encrypted data, so we wrote a script to decode it:
```python
cipher = [2, 7, 9, 7, 8, 13, 17, 39, 85, 4, 57, 4, 93, 30, 104, 27, 44, 23, 89, 8, 30, 68, 107, 112, 54, 0, 30, 11, 2, 92, 66, 23, 31] 
key = [119, 115, 111, 107, 105, 106, 106, 110, 114, 105, 102, 106, 50, 106, 55, 122, 115, 101, 54, 106, 113, 48, 52, 57, 105, 112, 108, 100, 111, 53, 49, 114, 98]

flag = "".join([chr(c ^ k) for c, k in zip(cipher, key)]) 
print(f"Flag: {flag}")
```

Run result:
```bash
$ python3 solve.py
Flag: utflag{I'm_not_a_robot_I_promise}
```