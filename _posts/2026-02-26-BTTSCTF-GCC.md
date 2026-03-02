---
title: "GCC - BITSCTF Write Up"
date: 2026-02-26
tags: [BITSCTF, reverse]
description: "This is the write up for GCC chall - BITSCTF contest"
---

> - Category: Reverse Engineering
> - Author: Woody Nguyen

## Challenge Descriptiom
I have made a successful safe to use C compiler, try it once it's amazing and manages to be as fast as gcc in respect of runtime.

## Analyzing
The challenge gives us a binary. Let's check it:
```bash
$ file ghost_compiler
ghost_compiler: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d64d20a0400553456624de78cd58afb878a5eb02, for GNU/Linux 3.2.0, stripped

$ checksec --file=ghost_compiler
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols        No    0               3               ghost_compiler
```
We observed that this is a stripped ELF-64 bit LSB binary file.

Trying to decompile this binary with IDA, we have found that this binary is a Binary Patcher Tool containing Self - Executing wrapper. This binary can read itself and load into the memory, changing data then rewrite in the system. Then it can run a system command line base on input:
- We can see its process in the `main()` function:
    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <sys/stat.h>

    // Các hàm giả định từ binary
    long long find_offset(const char* filename);     // sub_1349
    long long get_metadata(const char* filename, long long offset); // sub_14B5
    int verify_content(char* buffer, long long offset, long long meta); // sub_1583

    int main(int argc, const char **argv) {
        FILE *stream;
        long long size;
        char *ptr;
        long long offset;
        long long metadata;
        unsigned int sys_result;
        
        char command[1024]; // dest + v13 + v14 kết hợp lại
        unsigned long long canary = __readfsqword(0x28);

        // 1. Phân tích chính tệp thực thi hiện tại (argv[0])
        offset = find_offset(argv[0]);
        if (offset == -1) return 1;

        metadata = get_metadata(argv[0], offset);
        if (!metadata) return 1;

        // 2. Đọc toàn bộ nội dung tệp vào bộ nhớ
        stream = fopen(argv[0], "rb");
        if (!stream) return 1;

        fseek(stream, 0, SEEK_END);
        size = ftell(stream);
        fseek(stream, 0, SEEK_SET);

        ptr = (char *)malloc(size);
        if (!ptr) {
            fclose(stream);
            return 1;
        }

        if (fread(ptr, 1, size, stream) != size) {
            free(ptr);
            fclose(stream);
            return 1;
        }
        fclose(stream);

        // 3. Thực hiện Patching (Chỉnh sửa nhị phân)
        if (size > offset + 63) {
            // Kiểm tra tính hợp lệ trước khi sửa
            if (!verify_content(ptr, offset, metadata)) {
                free(ptr);
                return 1;
            }
            // Xóa sạch 64 bytes (0x40) tại vị trí offset
            memset(&ptr[offset], 0, 64);
        }

        // 4. Ghi đè lại chính tệp thực thi
        if (unlink(argv[0])) { // Xóa tệp cũ để tránh lỗi "text file busy"
            free(ptr);
            return 1;
        }

        FILE *s = fopen(argv[0], "wb");
        if (!s) {
            free(ptr);
            return 1;
        }
        fwrite(ptr, 1, size, s);
        fclose(s);
        free(ptr);

        // Khôi phục quyền thực thi (chmod 755 - 0x1ED)
        chmod(argv[0], 0x1ED);

        // 5. Xây dựng và thực thi lệnh hệ thống mới
        // "543384423" trong ASCII (Little Endian) có thể là một chuỗi lệnh như "gcc " hoặc tương tự
        memset(command, 0, sizeof(command));
        strcpy(command, "target_cmd "); // Giả định dựa trên hằng số 543384423

        for (int i = 1; i < argc; ++i) {
            strcat(command, argv[i]);
            strcat(command, " ");
            // strcmp(argv[i], "-o") để kiểm tra option nhưng không thay đổi luồng ở đây
        }

        sys_result = system(command);
        return (sys_result != 0) ? sys_result : 0;
    }
    ```
    - The flow of main can be seen as a flowchart:
    ```mermaid
    flowchart TD
        A["main(argc, argv)"] --> B["sub_1349(argv[0])\nOpen ghost_compiler itself\nScan for magic blob byte 0x9A\n→ blob_offset = 0x3020"]
        B --> C["sub_14B5(argv[0], blob_offset)\nCompute FNV-1a variant hash\nover entire binary, skip blob region\n→ hash = 0x5145DD89C16375D8"]
        C --> D["sub_1583(file_buf, blob_offset, hash)\nDecrypt blob[0:8] via XOR + ROR64\nCheck decrypted == 'BITSCTF{'"]
        D -- "Invalid" --> E["Exit / Error"]
        D -- "Valid ✓" --> F["memset blob region to 0\nWrite cleaned .c file back to disk\n(self-destruct the flag)"]
        F --> G["execv / system\ngcc compile the .c file\nas a normal compiler"]
    ```
    - Base on the `main()`, this binary has 3 main functions, which is `sub_1349` - finding the offset of **magic blob** in file, `sub_14B5` - calculate hash FNV-1a, `sub_1583` - decode and check flag.

Looking at the `sub_1349` function, this function will input a file path, then it will open the file and read each bytes. When it find the byte `0x9A` - the first byte of **magic blob**, it will read the next 7 bytes and check if it match with `byte_4020[1..7]`.
```c
__int64 __fastcall sub_1349(const char *a1)
{
  int v2; // [rsp+10h] [rbp-30h]
  int i; // [rsp+14h] [rbp-2Ch]
  __int64 v4; // [rsp+18h] [rbp-28h]
  FILE *stream; // [rsp+20h] [rbp-20h]
  __int64 off; // [rsp+28h] [rbp-18h]
  _BYTE ptr[8]; // [rsp+30h] [rbp-10h] BYREF
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  stream = fopen(a1, "rb");
  if ( !stream )
    return -1;
  v4 = 0;
  while ( fread(ptr, 1u, 1u, stream) == 1 )
  {
    if ( ptr[0] == byte_4020[0] )
    {
      off = ftell(stream);
      if ( fread(ptr, 1u, 7u, stream) == 7 )
      {
        v2 = 1;
        for ( i = 0; i <= 6 && v2; ++i )
        {
          if ( ptr[i] != byte_4020[i + 1] )
            v2 = 0;
        }
        if ( v2 )
        {
          fclose(stream);
          return v4;
        }
      }
      fseek(stream, off, 0);
    }
    ++v4;
  }
  fclose(stream);
  return -1;
}    
```
- However, this function is called in main with `argv[0]`, which means it call the main path of binary `ghost_compiler`, instead of `.c` input file:
    ```asm
    ; main + 0x38
    mov  rax, [rbp+var_460]   ; argv
    mov  rax, [rax]           ; argv[0] = "ghost_compiler"
    mov  rdi, rax
    call sub_1349             ; mở chính ghost_compiler, tìm blob
    ```

    or we can see it in the decompile code of `main()`:
    ```c
    // decompile:
    v6 = sub_1349(*a2, a2, a3);
    if ( v6 == -1 )
        return 1;

    // re-sub:
    offset = find_offset(argv[0]);
    ```
- Because of this reason, the function will return to the file offset of blob in binary at `0x3020`.

Checking the `sub_14B5`, this function will calculate hash FNV-1a of all file, but it **skip** 64 byte at the blob memory
```c
unsigned __int64 __fastcall sub_14B5(const char *a1, __int64 a2)
{
    int v3; // [rsp+14h] [rbp-1Ch]
    __int64 v4; // [rsp+18h] [rbp-18h]
    __int64 v5; // [rsp+20h] [rbp-10h]
    FILE *stream; // [rsp+28h] [rbp-8h]

    stream = fopen(a1, "rb");
    if ( !stream )
        return 0;
    v4 = 0xCBF29CE484222325LL;
    v5 = 0;
    while ( 1 )
    {
        v3 = fgetc(stream);
        if ( v3 == -1 )
        break;
        if ( a2 < 0 || v5 < a2 || v5 > a2 + 63 )
        {
            v4 = 0x100000001B3LL * (v4 ^ v3);
            ++v5;
        }
        else
        {
            ++v5;
        }
    }
    fclose(stream);
    return v4 ^ 0xCAFEBABE00000000LL;
}
```
- Specifically, the process of hash calculation can be seen as this flow:
    ``` python
    FNV_OFFSET = 0xCBF29CE484222325
    FNV_PRIME  = 0x100000001B3

    for mỗi byte b tại vị trí pos:
        nếu offset <= pos <= offset+63:
            bỏ qua (skip)
        hash = (hash XOR b) * FNV_PRIME  [mod 2^64]

    return 0xCAFEBABE00000000 XOR hash
    ```
- Since hashed file is `ghost_compiler` - a constant binary, so the output hash will be a constant value:
    ```c
    Hash = 0x5145DD89C16375D8
    ```
The function `sub_1583` will input `(ptr, offset blob, hash)`, then it will encode first 8 bytes of blob by XOR with lower byte of hash before ROR 64-bit:
```c
_BOOL8 __fastcall sub_1583(__int64 a1, __int64 a2, __int64 a3)
{
  int i; // [rsp+24h] [rbp-1Ch]
  _BYTE v6[8]; // [rsp+30h] [rbp-10h]
  unsigned __int64 v7; // [rsp+38h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  for ( i = 0; i <= 7; ++i )
  {
    v6[i] = *(_BYTE *)(i + a2 + a1) ^ a3;
    a3 = __ROR8__(a3, 1);
  }
  return v6[0] == 66
      && v6[1] == 73
      && v6[2] == 84
      && v6[3] == 83
      && v6[4] == 67
      && v6[5] == 84
      && v6[6] == 70
      && v6[7] == 123;
}
```
- The real process can be seen here:
    ```python
    for i in range(8):
        decrypted[i] = blob[i] XOR (hash & 0xFF)
        hash = ROR64(hash, 1)
    ```
- This code will check: `decrypted[0:8] == b"BITSCTF{"` - flag format. Since blob is 64 bytes and the flag format is `BITSCTF{`, we need to decode all 64 byte to get the real flag.

## Reversing
Looking in IDA, at address `0x4020` - file offset = `0x3020`, we can find 64 encoded bytes:
```asm
.data:0000000000004020 byte_4020       db 9Ah                  ; DATA XREF: sub_1349+5D↑r
.data:0000000000004020                                         ; sub_1349+C1↑o
.data:0000000000004021                 db 0A5h
.data:0000000000004022                 db  22h ; "
.data:0000000000004023                 db 0E8h
.data:0000000000004024                 db  1Eh
.data:0000000000004025                 db 0FAh
.data:0000000000004026                 db  91h
.data:0000000000004027                 db  90h
.data:0000000000004028                 db  1Bh
.data:0000000000004029                 db  8Eh
.data:000000000000402A                 db 0B3h
.data:000000000000402B                 db  5Eh ; ^
.data:000000000000402C                 db  5Ah ; Z
.data:000000000000402D                 db  2Ah ; *
.data:000000000000402E                 db 0F9h
.data:000000000000402F                 db 0F5h
.data:0000000000004030                 db  10h
.data:0000000000004031                 db 0EEh
.data:0000000000004032                 db  6Ch ; l
.data:0000000000004033                 db  42h ; B
.data:0000000000004034                 db  72h ; r
.data:0000000000004035                 db  54h ; T
.data:0000000000004036                 db  76h ; v
.data:0000000000004037                 db 0B1h
.data:0000000000004038                 db 0ADh
.data:0000000000004039                 db  86h
.data:000000000000403A                 db  2Fh ; /
.data:000000000000403B                 db  5Ch ; \
.data:000000000000403C                 db 0AFh
.data:000000000000403D                 db  3Dh ; =
.data:000000000000403E                 db  53h ; S
.data:000000000000403F                 db  61h ; a
.data:0000000000004040                 db 0FCh
.data:0000000000004041                 db 0A7h
.data:0000000000004042                 db  16h
.data:0000000000004043                 db 0EEh
.data:0000000000004044                 db 0E8h
.data:0000000000004045                 db  99h
.data:0000000000004046                 db    4
.data:0000000000004047                 db  8Bh
.data:0000000000004048                 db 0BFh
.data:0000000000004049                 db 0DEh
.data:000000000000404A                 db    5
.data:000000000000404B                 db  8Bh
.data:000000000000404C                 db  2Eh ; .
.data:000000000000404D                 db  53h ; S
.data:000000000000404E                 db  17h
.data:000000000000404F                 db  8Bh
.data:0000000000004050                 db  45h ; E
.data:0000000000004051                 db 0A2h
.data:0000000000004052                 db  51h ; Q
.data:0000000000004053                 db  28h ; (
.data:0000000000004054                 db  14h
.data:0000000000004055                 db  8Ah
.data:0000000000004056                 db  45h ; E
.data:0000000000004057                 db 0A2h
.data:0000000000004058                 db  51h ; Q
.data:0000000000004059                 db  28h ; (
.data:000000000000405A                 db  14h
.data:000000000000405B                 db  0Ah
.data:000000000000405C                 db  85h
.data:000000000000405D                 db 0C2h
.data:000000000000405E                 db  61h ; a
.data:000000000000405F                 db 0B0h
.data:000000000000405F _data           ends
```
- We can rewrite those bytes in this order:
    ```
    9A A5 22 E8 1E FA 91 90  1B 8E B3 5E 5A 2A F9 F5
    10 EE 6C 42 72 54 76 B1  AD 86 2F 5C AF 3D 53 61
    FC A7 16 EE E8 99 04 8B  BF DE 05 8B 2E 53 17 8B
    45 A2 51 28 14 8A 45 A2  51 28 14 0A 85 C2 61 B0
    ```
Base on the flow of `main`, we can have the exploit script:
```python
#!/usr/bin/env python3

MASK64     = 0xFFFFFFFFFFFFFFFF
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME  = 0x100000001B3
CAFEBABE   = 0xCAFEBABE00000000

blob = bytes([
    0x9A, 0xA5, 0x22, 0xE8, 0x1E, 0xFA, 0x91, 0x90,
    0x1B, 0x8E, 0xB3, 0x5E, 0x5A, 0x2A, 0xF9, 0xF5,
    0x10, 0xEE, 0x6C, 0x42, 0x72, 0x54, 0x76, 0xB1,
    0xAD, 0x86, 0x2F, 0x5C, 0xAF, 0x3D, 0x53, 0x61,
    0xFC, 0xA7, 0x16, 0xEE, 0xE8, 0x99, 0x04, 0x8B,
    0xBF, 0xDE, 0x05, 0x8B, 0x2E, 0x53, 0x17, 0x8B,
    0x45, 0xA2, 0x51, 0x28, 0x14, 0x8A, 0x45, 0xA2,
    0x51, 0x28, 0x14, 0x0A, 0x85, 0xC2, 0x61, 0xB0,
])

def ror64(val, n):
    val &= MASK64
    return ((val >> n) | (val << (64 - n))) & MASK64

def compute_hash(data, skip_offset):
    h = FNV_OFFSET
    for pos, b in enumerate(data):
        if 0 <= (pos - skip_offset) <= 0x3F:
            continue
        h = ((h ^ b) * FNV_PRIME) & MASK64
    return (CAFEBABE ^ h) & MASK64

def decrypt(blob, h):
    out = bytearray()
    for b in blob:
        out.append(b ^ (h & 0xFF))
        h = ror64(h, 1)
    return bytes(out)

with open("ghost_compiler", "rb") as f:
    data = f.read()

# Tìm blob trong binary
offset = data.index(blob[:8])  # = 0x3020

h = compute_hash(data, offset)
flag = decrypt(blob, h)
print(flag.split(b'\x00')[0].decode())
```

The flag is `BITSCTF{n4n0m1t3s_4nd_s3lf_d3struct_0ur0b0r0s}`