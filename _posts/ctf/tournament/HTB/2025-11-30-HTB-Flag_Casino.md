---
title: "Flag Casino - Hack The Box CTF Try Out Writeup"
date: 2025-11-30
categories: [CTF, Tournament]
tags: [HTB, reverse]
description: "No Description."
---

## Information
- Category: Reverse Engineering
- Level: Easy
- From HTB

## Description
The team stumbles into a long-abandoned casino. As you enter, the lights and music whir to life, and a staff of robots begin moving around and offering games, while skeletons of prewar patrons are slumped at slot machines. A robotic dealer waves you over and promises great wealth if you can win - can you beat the house and gather funds for the mission?

## Solution
## What we got ?
- Đây là 1 giao diện Casino yêu cầu người chơi "đặt cược" để chơi (thực chất là thu thập nhật ký đầu vào).
- Người dùng sẽ nhập input vào `v4` và chương trình sẽ sử dụng input vừa nhập làm seed cho hàm `srand(v4)`.
- Sau đó, thực hiện gọi `rand()` và so sánh kết quả với `check[i]`.
- **Nhận xét**: Do `srand()` với cùng 1 seed sẽ cùng tạo ra một chuỗi ngẫu nhiên (tức random bao nhiêu lần cũng không đổi kết quả).

## How to get the flag ?
- Từ nhận xét trên, thực hiện Brute-Force để tìm flag. Cụ thể:

    - Thực hiện check 29 kí tự đầu vào.
    - Với mỗi ký tự được dùng làm seed cho `srand()`, sau đó đem ra compare `rand()` với giá trị có sẵn trong `check`.
    - Do seed chỉ là 1 byte, nên có thể dễ dàng Brute-Force từng ký tự một cách độc lập.

- Thực hiện decompile file binary gốc để tìm giá trị của `check[]`, ta tìm được kết quả sau:

    ![check](https://github.com/UITxWoodyNguyen/CTF/blob/main/HTB-CTFTryOut/RE/FlagCasino/Screenshot%202025-12-09%20101841.png)

- Từ đó, ta có script cụ thể:
    ```python
    from ctypes import CDLL, cdll
    import platform

    # Mảng check từ binary
    check = [
        0x244B28BE, 0x0AF77805, 0x110DFC17, 0x07AFC3A1, 0x6AFEC533,
        0x4ED659A2, 0x33C5D4B0, 0x286582B8, 0x43383720, 0x055A14FC,
        0x19195F9F, 0x43383720, 0x63149380, 0x615AB299, 0x6AFEC533,
        0x6C6FCFB8, 0x43383720, 0x0F3DA237, 0x6AFEC533, 0x615AB299,
        0x286582B8, 0x055A14FC, 0x3AE44994, 0x06D7DFE9, 0x4ED659A2,
        0x0CCD4ACD, 0x57D8ED64, 0x615AB299, 0x22E9BC2A
    ]

    # Load thư viện C
    if platform.system() == "Windows":
        libc = cdll.msvcrt
    else:
        libc = CDLL("libc.so.6")

    flag = ""
    for i in range(29):
        found = False
        for c in range(256):  # thử tất cả giá trị byte
            libc.srand(c)
            if libc.rand() == check[i]:
                flag += chr(c)
                found = True
                break
        if not found:
            flag += "?"

    print(f"Flag: {flag}")
    ```