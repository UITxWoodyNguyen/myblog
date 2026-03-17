---
title: "Jail break - UTCTF 2026 write up"
date: 2026-03-17
categories: [CTF, Tournament]
tags: [UTCTF, OSINT]
description: "No Description"
---

## Challenge Description
We've built the world's most secure Python sandbox. Nothing can escape. Probably. Hopefully. Run it locally: 
```
python3 jail.py 
```

## Analyzing Path
The challenge gives us a Python source file; first, try to open it:
```python
import sys

_ENC = [0x37, 0x36, 0x24, 0x2e, 0x23, 0x25, 0x39, 0x32, 0x3b, 0x1d, 0x28, 0x23, 0x73, 0x2e, 0x1d, 0x71, 0x31, 0x21, 0x76, 0x32, 0x71, 0x1d, 0x2f, 0x76, 0x31, 0x36, 0x71, 0x30, 0x3f]
_KEY = 0x42

def _secret():
    return ''.join(chr(b ^ _KEY) for b in _ENC)

BANNED = [
    "import", "os", "sys", "system", "eval",
    "open", "read", "write", "subprocess", "pty",
    "popen", "secret", "_enc", "_key"
]

SAFE_BUILTINS = {
    "print": print,
    "input": input,
    "len": len,
    "str": str,
    "int": int,
    "chr": chr,
    "ord": ord,
    "range": range,
    "type": type,
    "dir": dir,
    "vars": vars,
    "getattr": getattr,
    "setattr": setattr,
    "hasattr": hasattr,
    "isinstance": isinstance,
    "enumerate": enumerate,
    "zip": zip,
    "map": map,
    "filter": filter,
    "list": list,
    "dict": dict,
    "tuple": tuple,
    "set": set,
    "bool": bool,
    "bytes": bytes,
    "hex": hex,
    "oct": oct,
    "bin": bin,
    "abs": abs,
    "min": min,
    "max": max,
    "sum": sum,
    "sorted": sorted,
    "reversed": reversed,
    "repr": repr,
    "hash": hash,
    "id": id,
    "callable": callable,
    "iter": iter,
    "next": next,
    "object": object,
}

# _secret is in globals but not documented - players must find it
GLOBALS = {"__builtins__": SAFE_BUILTINS, "_secret": _secret}

print("=" * 50)
print("  Welcome to PyJail v1.0")
print("  Escape to get the flag!")
print("=" * 50)
print()

while True:
    try:
        code = input(">>> ")
    except EOFError:
        break

    blocked = False
    for word in BANNED:
        if word.lower() in code.lower():
            print(f"  [BLOCKED] Nice try!")
            blocked = True
            break

    if blocked:
        continue

    try:
        exec(compile(code, "<jail>", "exec"), GLOBALS)
    except Exception as e:
        print(f"  [ERROR] {e}")
```

Based on the Python script, we identified some suspicious points:

-- First, there is a secret function in this source code:
    ```python
    def _secret():
        return ''.join(chr(b ^ _KEY) for b in _ENC)
    ```

-- Next, there is a blacklist containing some banned strings:
    ```python
    BANNED = [
        "import", "os", "sys", "system", "eval",
        "open", "read", "write", "subprocess", "pty",
        "popen", "secret", "_enc", "_key"
    ]
    ```

-- Finally, `GLOBALS` is passed into `exec`, but it still contains `_secret`:
    ```python
    GLOBALS = {"__builtins__": SAFE_BUILTINS, "_secret": _secret}
    ```

-- So we can observe that this program only blocks static strings; runtime-generated strings remain usable.

Overall, this source code contains some important points:
- `_ENC` is the encoded bytes array.
- `_KEY = 0x42` is the XOR key.
- `_secret()` decodes `_ENC` with `_KEY`.
- The blacklist contains `secret`, but does not ban `vars`, `chr`, `map`, or `getattr`.

There is no embedded binary data, so `binwalk`/`exiftool` are not needed.

## Decoding
Based on the secret function, we can decode directly by XOR with the `KEY = 0x42`:
```python
''.join(chr(b ^ 0x42) for b in _ENC)
```

We created a payload, ran `jail.py` with it, and obtained the flag:

- Payload:
    ```python
    name="_"+"".join(map(chr,[115,101,99,114,101,116]))
    fn=vars()[name]
    print(fn())
    ```

- Run result:
    ```bash
    $ python3 jail.py
    ==================================================
    Welcome to PyJail v1.0
    Escape to get the flag!
    ==================================================

    >>> name="_"+"".join(map(chr,[115,101,99,114,101,116]))
    fn=vars()[name]
    print(fn())>>> >>> 
    utflag{py_ja1l_3sc4p3_m4st3r}
    ```