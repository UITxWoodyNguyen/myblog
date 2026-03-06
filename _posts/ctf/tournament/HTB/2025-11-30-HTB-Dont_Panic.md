---
title: "Don't Panic - Hack The Box CTF Try Out Writeup"
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
You've cut a deal with the Brotherhood; if you can locate and retrieve their stolen weapons cache, they'll provide you with the kerosene needed for your makeshift explosives for the underground tunnel excavation. The team has tracked the unique energy signature of the weapons to a small vault, currently being occupied by a gang of raiders who infiltrated the outpost by impersonating commonwealth traders. Using experimental stealth technology, you've slipped by the guards and arrive at the inner sanctum. Now, you must find a way past the highly sensitive heat-signature detection robot. Can you disable the security robot without setting off the alarm?

## Solution

### What we got ?
- Mở file binary `dontpanic` và decompile bằng IDA, ta nhận thấy đây là một chương trình được viết bằng **Rust**. 
- Ta thực hiện kiểm tra `main()` của chương trình. `main()` được tóm tắt như sau:
    ```c
    // src::main::hf9bc229851763ab9
    void src::main::hf9bc229851763ab9() {
        // 1. In prompt
        std::io::stdio::_print::h5c2f653c9c3347e5();
        
        // 2. Đọc input từ stdin
        std::io::stdio::stdin::h8c974ef3a60924c0();
        std::io::stdio::Stdin::read_line::hdb4e3d7cbacc71a9();
        
        // 3. Loại bỏ newline
        v5 = src::remove_newline::h49daf0023bf5b77c(v8, v9);
        
        // 4. Kiểm tra flag ← QUAN TRỌNG
        src::check_flag::h397d174e03dc8c74(v5, v6);
        
        // 5. In kết quả
        std::io::stdio::_print::h5c2f653c9c3347e5();
    }
    ```
- Ta nhận thấy, flow xử lý của chương trình là `nhận input --> xoá newline --> check flag --> in result`. Vậy điều ta cần quan tâm chính là step `check flag` thực hiện như thế nào.
- Thực hiện kiểm tra hàm `check_flag()`:
    ```c
    __int64 __fastcall src::check_flag::h397d174e03dc8c74(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6) {
        __int64 (__fastcall *v6)(); // rdx
        __int64 (__fastcall *v7)(); // rcx
        __int64 result; // rax
        __int64 v9; // r14
        __int64 v10; // [rsp+0h] [rbp-148h] BYREF
        __int64 v11; // [rsp+8h] [rbp-140h] BYREF
        __int64 (__fastcall *v12)(); // [rsp+10h] [rbp-138h]
        __int64 (__fastcall *v13)(); // [rsp+18h] [rbp-130h]
        __int64 (__fastcall *v14)(); // [rsp+20h] [rbp-128h]
        __int64 (__fastcall *v15)(); // [rsp+28h] [rbp-120h]
        __int64 (__fastcall *v16)(); // [rsp+30h] [rbp-118h]
        __int64 (__fastcall *v17)(); // [rsp+38h] [rbp-110h]
        __int64 (__fastcall *v18)(); // [rsp+40h] [rbp-108h]
        __int64 (__fastcall *v19)(); // [rsp+48h] [rbp-100h]
        __int64 (__fastcall *v20)(); // [rsp+50h] [rbp-F8h]
        __int64 (__fastcall *v21)(); // [rsp+58h] [rbp-F0h]
        __int64 (__fastcall *v22)(); // [rsp+60h] [rbp-E8h]
        __int64 (__fastcall *v23)(); // [rsp+68h] [rbp-E0h]
        __int64 (__fastcall *v24)(); // [rsp+70h] [rbp-D8h]
        __int64 (__fastcall *v25)(); // [rsp+78h] [rbp-D0h]
        __int64 (__fastcall *v26)(); // [rsp+80h] [rbp-C8h]
        __int64 (__fastcall *v27)(); // [rsp+88h] [rbp-C0h]
        __int64 (__fastcall *v28)(); // [rsp+90h] [rbp-B8h]
        __int64 (__fastcall *v29)(); // [rsp+98h] [rbp-B0h]
        __int64 (__fastcall *v30)(); // [rsp+A0h] [rbp-A8h]
        __int64 (__fastcall *v31)(); // [rsp+A8h] [rbp-A0h]
        __int64 (__fastcall *v32)(); // [rsp+B0h] [rbp-98h]
        __int64 (__fastcall *v33)(); // [rsp+B8h] [rbp-90h]
        __int64 (__fastcall *v34)(); // [rsp+C0h] [rbp-88h]
        __int64 (__fastcall *v35)(); // [rsp+C8h] [rbp-80h]
        __int64 (__fastcall *v36)(); // [rsp+D0h] [rbp-78h]
        __int64 (__fastcall *v37)(); // [rsp+D8h] [rbp-70h]
        __int64 (__fastcall *v38)(); // [rsp+E0h] [rbp-68h]
        __int64 (__fastcall *v39)(); // [rsp+E8h] [rbp-60h]
        __int64 (__fastcall *v40)(); // [rsp+F0h] [rbp-58h]
        __int64 (__fastcall *v41)(); // [rsp+F8h] [rbp-50h]
        __int64 (__fastcall *v42)(); // [rsp+100h] [rbp-48h]
        _QWORD v43[8]; // [rsp+108h] [rbp-40h] BYREF

        v12 = core::ops::function::FnOnce::call_once::h32497efb348ffe3c;
        v13 = core::ops::function::FnOnce::call_once::h827ece763c8c7e2e;
        v14 = core::ops::function::FnOnce::call_once::h784eba9476a4f0f4;
        v15 = core::ops::function::FnOnce::call_once::hc26775751c1be756;
        v16 = core::ops::function::FnOnce::call_once::hc599f6727ca8db95;
        v17 = core::ops::function::FnOnce::call_once::h40d00bd196c3c783;
        v18 = core::ops::function::FnOnce::call_once::h4e1d94269d5dab9f;
        v19 = core::ops::function::FnOnce::call_once::h1e50475f0ef4e3b2;
        v6 = core::ops::function::FnOnce::call_once::h28c42c5fb55e3f9f;
        v20 = core::ops::function::FnOnce::call_once::h28c42c5fb55e3f9f;
        v21 = core::ops::function::FnOnce::call_once::h08f069e45c38c91b;
        v22 = core::ops::function::FnOnce::call_once::h70ddab66eb3eaf7e;
        v23 = core::ops::function::FnOnce::call_once::h4e1d94269d5dab9f;
        v24 = core::ops::function::FnOnce::call_once::h5935cc8a67508b36;
        v25 = core::ops::function::FnOnce::call_once::h2ed86dfdd0fc9ca5;
        v26 = core::ops::function::FnOnce::call_once::h28c42c5fb55e3f9f;
        v27 = core::ops::function::FnOnce::call_once::h2ed86dfdd0fc9ca5;
        v28 = core::ops::function::FnOnce::call_once::h70ddab66eb3eaf7e;
        v29 = core::ops::function::FnOnce::call_once::h1e50475f0ef4e3b2;
        v30 = core::ops::function::FnOnce::call_once::h2ed86dfdd0fc9ca5;
        v31 = core::ops::function::FnOnce::call_once::h076f93abc7994a2b;
        v32 = core::ops::function::FnOnce::call_once::h28c42c5fb55e3f9f;
        v33 = core::ops::function::FnOnce::call_once::h1e50475f0ef4e3b2;
        v34 = core::ops::function::FnOnce::call_once::h076f93abc7994a2b;
        v35 = core::ops::function::FnOnce::call_once::ha0a2d91800448694;
        v36 = core::ops::function::FnOnce::call_once::h28c42c5fb55e3f9f;
        v37 = core::ops::function::FnOnce::call_once::hd3a717188d9c9564;
        v38 = core::ops::function::FnOnce::call_once::h4aee5a63c69b281c;
        v39 = core::ops::function::FnOnce::call_once::h4aee5a63c69b281c;
        v7 = core::ops::function::FnOnce::call_once::h3dae80a6281f81f5;
        v40 = core::ops::function::FnOnce::call_once::h3dae80a6281f81f5;
        v41 = core::ops::function::FnOnce::call_once::h4aee5a63c69b281c;
        v42 = core::ops::function::FnOnce::call_once::he29dc24b9b003076;
        v10 = a2;
        v11 = 31;
        if ( a2 != 31 )
        {
            v43[0] = 0;
            ((void (__fastcall __noreturn *)(__int64 *, __int64 *, _QWORD *))core::panicking::assert_failed::hb9915114bebb1f93)(
            &v10,
            &v11,
            v43);
        }
        result = 0;
        do
        {
            v9 = result + 1;
            ((void (__fastcall *)(_QWORD, __int64, __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64, __int64, __int64, __int64, __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)(), __int64 (__fastcall *)()))*(&v12 + result))(
            *(unsigned __int8 *)(a1 + result),
            31,
            v6,
            v7,
            a5,
            a6,
            v10,
            v11,
            v12,
            v13,
            v14,
            v15,
            v16,
            v17,
            v18,
            v19,
            v20,
            v21,
            v22,
            v23,
            v24,
            v25,
            v26,
            v27,
            v28,
            v29,
            v30,
            v31,
            v32,
            v33,
            v34,
            v35,
            v36,
            v37,
            v38,
            v39,
            v40,
            v41,
            v42);
            result = v9;
        }
        while ( v9 != 31 );
        return result;
    }
    ```
- Ta có thể tóm tắt process check flag và có một số nhận xét như sau:
    ```c
    __int64 __check_flag(__int64 a1, __int64 a2, ...)
    {
        // Khởi tạo mảng 31 function pointers
        v12 = core::ops::function::FnOnce::call_once::h32497efb348ffe3c;
        v13 = core::ops::function::FnOnce::call_once::h827ece763c8c7e2e;
        v14 = core::ops::function::FnOnce::call_once::h784eba9476a4f0f4;
        // ... (tổng 31 hàm từ v12 đến v42)
        
        // Kiểm tra độ dài phải = 31
        if ( a2 != 31 )
            core::panicking::assert_failed(...);
        
        // Lặp qua từng ký tự
        result = 0;
        do
        {
            v9 = result + 1;
            // Gọi hàm thứ [result] với input[result]
            (*(&v12 + result))(*(unsigned __int8 *)(a1 + result), ...);
            result = v9;
        }
        while ( v9 != 31 );
        
        return result;
    }
    ```

    - Độ dài của flag sẽ là 31 kí tự.
    - Mỗi kí tự được kiểm tra bởi một hàm `call_once` riêng biệt.

### How to get flag ?
- Từ nhận xét trên, hướng xử lý sẽ là kiểm tra từng hàm `call_once` để xem chúng được mapping với kí tự nào.
- Kiểm tra assembly với từng hàm `call_once::hXXXX`. Ta thấy các hàm gần như có cấu trúc giống nhau như sau:
    ```asm
    ; Ví dụ: h32497efb348ffe3c - kiểm tra ký tự 'H'
    push    rax
    cmp     dil, 48h        ; So sánh input với 0x48 = 'H'
    jb      short panic     ; Nếu nhỏ hơn → panic
    jnz     short panic     ; Nếu khác → panic
    pop     rax             ; Nếu bằng → OK
    retn

    panic:
    call core::panicking::panic  ; Crash chương trình
    ```

    - Logic: Nếu input khác expected, thực hiện gọi `panic!`, dẫn đến crash.
- Ta chỉ cần trích xuất kí tự được mapping ở từng hàm để tìm flag.
    ```python
    # Mapping từ hash của hàm call_once → ký tự tương ứng
    hash_to_char = {
        "h32497efb348ffe3c": "H",   # 0x48
        "h827ece763c8c7e2e": "T",   # 0x54
        "h784eba9476a4f0f4": "B",   # 0x42
        "hc26775751c1be756": "{",   # 0x7B
        "hc599f6727ca8db95": "d",   # 0x64
        "h40d00bd196c3c783": "0",   # 0x30
        "h4e1d94269d5dab9f": "n",   # 0x6E
        "h1e50475f0ef4e3b2": "t",   # 0x74
        "h28c42c5fb55e3f9f": "_",   # 0x5F
        "h08f069e45c38c91b": "p",   # 0x70
        "h70ddab66eb3eaf7e": "4",   # 0x34
        "h5935cc8a67508b36": "1",   # 0x31
        "h2ed86dfdd0fc9ca5": "c",   # 0x63
        "h076f93abc7994a2b": "h",   # 0x68  ← SỬA TỪ ! THÀNH h
        "ha0a2d91800448694": "e",   # 0x65
        "hd3a717188d9c9564": "3",   # 0x33
        "h4aee5a63c69b281c": "r",   # 0x72
        "h3dae80a6281f81f5": "o",   # 0x6F
        "he29dc24b9b003076": "}",   # 0x7D
    }

    # Thứ tự các hàm được gọi trong check_flag (31 vị trí)
    func_order = [
        "h32497efb348ffe3c",  # 0  - H
        "h827ece763c8c7e2e",  # 1  - T
        "h784eba9476a4f0f4",  # 2  - B
        "hc26775751c1be756",  # 3  - {
        "hc599f6727ca8db95",  # 4  - d
        "h40d00bd196c3c783",  # 5  - 0
        "h4e1d94269d5dab9f",  # 6  - n
        "h1e50475f0ef4e3b2",  # 7  - t
        "h28c42c5fb55e3f9f",  # 8  - _
        "h08f069e45c38c91b",  # 9  - p
        "h70ddab66eb3eaf7e",  # 10 - 4
        "h4e1d94269d5dab9f",  # 11 - n
        "h5935cc8a67508b36",  # 12 - 1
        "h2ed86dfdd0fc9ca5",  # 13 - c
        "h28c42c5fb55e3f9f",  # 14 - _
        "h2ed86dfdd0fc9ca5",  # 15 - c
        "h70ddab66eb3eaf7e",  # 16 - 4
        "h1e50475f0ef4e3b2",  # 17 - t
        "h2ed86dfdd0fc9ca5",  # 18 - c
        "h076f93abc7994a2b",  # 19 - h  ← SỬA
        "h28c42c5fb55e3f9f",  # 20 - _
        "h1e50475f0ef4e3b2",  # 21 - t
        "h076f93abc7994a2b",  # 22 - h  ← SỬA
        "ha0a2d91800448694",  # 23 - e
        "h28c42c5fb55e3f9f",  # 24 - _
        "hd3a717188d9c9564",  # 25 - 3
        "h4aee5a63c69b281c",  # 26 - r
        "h4aee5a63c69b281c",  # 27 - r
        "h3dae80a6281f81f5",  # 28 - o
        "h4aee5a63c69b281c",  # 29 - r
        "he29dc24b9b003076",  # 30 - }
    ]

    # Ghép flag
    flag = ""
    for i, func_hash in enumerate(func_order):
        char = hash_to_char[func_hash]
        flag += char
        print(f"[{i:2d}] {func_hash} -> '{char}'")

    print("\n" + "="*50)
    print(f"🚩 FLAG: {flag}")
    print("="*50)
    ```
- Flag là `HTB{d0nt_p4n1c_c4tch_the_3rror}`