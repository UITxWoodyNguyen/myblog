---
title: "Loot Stash - Hack The Box CTF Try Out Writeup"
date: 2025-11-30
categories: [CTF, Tournament]
tags: [HTB, reverse]
description: "No Description."
---

## Information
- Category: Reverse Engineering
- Level: Easy
- Source: HTB

## Description
A giant stash of powerful weapons and gear have been dropped into the arena - but there's one item you have in mind. Can you filter through the stack to get to the one thing you really need?

## Solution
### What we got
- Chương trình này sẽ sinh ngẫu nhiên một số `v4`, sau đó sẽ "chọn đồ" theo công thức `(v4 % 0x7F8) >> 3`. 
- Kết quả sẽ trả về ngẫu nhiên 1 trong 255 món đồ là 1 chỗ từ `gear`:
    
    ![Ex](https://github.com/UITxWoodyNguyen/CTF/blob/main/HTB-CTFTryOut/RE/LootStash/Screenshot%202025-12-09%20104254.png)

- **Nhận xét**: Chương trình không có biến đổi mã hoá, hay thực hiện quy trình nào, mà chỉ output random ra 1 string.

### How to get flag ?
- Từ nhận xét trên, ta dễ nhận thấy flag có thể là 1 trong 255 string thuộc `gear[]`.
- Sử dụng `strings stash | egrep -i "HTB"` để tìm flag, ta nhận được kết quả sau:

    ![Flag](https://github.com/UITxWoodyNguyen/CTF/blob/main/HTB-CTFTryOut/RE/LootStash/Screenshot%202025-12-09%20104305.png)