---
title: "Tunnel Madness - Hack The Box CTF Try Out Writeup"
date: 2025-11-30
categories: [CTF, Tournament]
tags: [HTB, reverse]
description: "No Description."
---

## Information
- Category: RE
- Level: Medium
- Source: HTB

## Description
Within Vault 8707 are located master keys used to access any vault in the country. Unfortunately, the entrance was caved in long ago. There are decades old rumors that the few survivors managed to tunnel out deep underground and make their way to safety. Can you uncover their tunnel and break back into the vault?

## Solution

## What we got ?
- Trước hết, decompile file binary từ đề bài bằng IDA. Trước hết, kiểm tra `main()`, ta nhận thấy đây là 1 game di chuyển trong không gian 3 chiều Oxyz. Khi người chơi đạt được vault, game sẽ in ra flag.

    ```c
    int __fastcall main(int argc, const char **argv, const char **envp)
    {
        _DWORD v4[5]; // [rsp+4h] [rbp-14h] BYREF

        v4[0] = 0;
        v4[1] = 0;
        v4[2] = 0;
        while ( *(_DWORD *)(get_cell(v4, argv, envp) + 12) != 3 )
        {
            putchar(10);
            prompt_and_update_pos(v4);
        }
        puts("You break into the vault and read the secrets within...");
        get_flag();
        return 0;
    }
    ```
- Kiểm tra qua hàm `get_flag()`, ta nhận thấy flag thật nằm trong `flag.txt` khi kết nối đến server. Flag size tối đa 128 ký tự. 

    ```c
    int get_flag()
    {
        FILE *v0; // rax
        FILE *v1; // rbx
        _QWORD v3[19]; // [rsp+0h] [rbp-98h] BYREF

        v0 = fopen("/flag.txt", "r");
        if ( !v0 )
            return puts("HTB{fake_flag_for_testing}");
        v1 = v0;
        memset(v3, 0, 128);
        fgets((char *)v3, 128, v0);
        puts((const char *)v3);
        return fclose(v1);
    }
    ```
- Hàm `get_cell()` được sử dụng để tính `address` ô trong mê cung theo công thức

    ```c
    address = maze + 6400*a1[0] + 320*a1[1] + 16*a1[2]
    // z = a1[0], y = a1[1], x = a1[2]
    ```
- Từ công thức trên, ta có nhận định về size của maze 3D:

    - Kích thước cell là 16 bytes
    - Mỗi hàng gồm 20 cells (20 * 16 = 320 bytes)
    - Mỗi tầng gồm 20 hàng, 20 cột, tổng là 400 cells (6400 bytes)
    - Cấu trúc của cells:
        ```c
        struct Cell {
            int field_0;   // offset 0
            int field_4;   // offset 4
            int field_8;   // offset 8
            int type;      // offset 12 - đây là trường được check (== 3 là đích)
        };
        ```
- Từ `main()`, ta nhận thấy flag chỉ được trả về khi ta tìm được `cell` có `type = 3` tại offset 12. Tức `maze[z][y][x].type == 3`.

## How to get flag ?
- Trước hết, tìm address của `maze` trong `.rodata`. Ta tìm được address tại `0x20E0`. Sử dụng BFS loang để tìm đường đi tối ưu nhất trong không gian Oxyz. Cụ thể:

    - Ta thực hiện Brute Force toàn bộ `maze` để tìm `cell` có `type = 3`.
    - Khởi tạo deque ở vị trí xuất phát (0,0,0). Tại mỗi vị trí, thử di chuyển theo 6 hướng đi hợp lệ (Back - B/Forward - F/Left - L/Right - R/Down - D/Up - U).
    - Đánh dấu lại các vị trí đã đi qua để tránh lặp lại.
    - Thực hiện lưu lại trace vào file mới.

- Script BFS loang trong không gian Oxyz:
    ```python
    from pwn import *
    from collections import deque

    # Maze config
    MAZE_VA = 0x20E0
    CELL_SIZE = 16
    SIZE = 20  # 20x20x20 maze

    def get_cell_offset(z, y, x):
        """offset = (z*400 + y*20 + x) * 16"""
        return (z * 400 + y * 20 + x) * 16

    def get_cell_data(data, base, z, y, x):
        offset = base + get_cell_offset(z, y, x)
        if offset + 16 > len(data):
            return None
        cell = data[offset:offset+16]
        return {
            'field_0': u32(cell[0:4]),
            'field_4': u32(cell[4:8]),
            'field_8': u32(cell[8:12]),
            'type': u32(cell[12:16])
        }

    def can_move(data, base, z, y, x):
        """Kiểm tra có thể di chuyển đến cell không"""
        if not (0 <= z < SIZE and 0 <= y < SIZE and 0 <= x < SIZE):
            return False
        cell = get_cell_data(data, base, z, y, x)
        if cell is None:
            return False
        # type == 2 là wall, không đi được
        return cell['type'] != 2

    def main():
        binary_path = './tunnel'
        
        print("[*] Loading binary...")
        elf = ELF(binary_path, checksec=False)
        
        with open(binary_path, 'rb') as f:
            raw = f.read()
        
        # Tìm file offset của maze
        base_offset = None
        for section in elf.sections:
            sec_start = section.header.sh_addr
            sec_end = sec_start + section.header.sh_size
            if sec_start <= MAZE_VA < sec_end:
                base_offset = section.header.sh_offset + (MAZE_VA - sec_start)
                print(f"[+] Section: {section.name}")
                print(f"[+] Maze file offset: {hex(base_offset)}")
                break
        
        if base_offset is None:
            base_offset = MAZE_VA
            print(f"[*] Using VA as offset: {hex(base_offset)}")
        
        # Tìm goal (type = 3)
        print("\n[*] Searching for GOAL (type=3)...")
        goal = None
        
        for z in range(SIZE):
            for y in range(SIZE):
                for x in range(SIZE):
                    cell = get_cell_data(raw, base_offset, z, y, x)
                    if cell and cell['type'] == 3:
                        goal = (z, y, x)
                        print(f"[+] GOAL at: z={z}, y={y}, x={x}")
                        print(f"    Cell data: {cell}")
                        break
                if goal:
                    break
            if goal:
                break
        
        if not goal:
            print("[!] Goal not found!")
            return None
        
        # Start cell
        print("\n[*] Start cell (0,0,0):")
        start_cell = get_cell_data(raw, base_offset, 0, 0, 0)
        print(f"    {start_cell}")
        
        # BFS
        directions = [
            (0, -1, 0, 'B'),   # Back:    y-1
            (0, 1, 0, 'F'),    # Forward: y+1
            (-1, 0, 0, 'L'),   # Left:    z-1
            (1, 0, 0, 'R'),    # Right:   z+1
            (0, 0, -1, 'D'),   # Down:    x-1
            (0, 0, 1, 'U'),    # Up:      x+1
        ]
        
        print("\n[*] Finding path with BFS...")
        
        start = (0, 0, 0)
        queue = deque([(start, "")])
        visited = {start}
        
        while queue:
            (z, y, x), path = queue.popleft()
            
            if (z, y, x) == goal:
                print(f"\n[+] PATH FOUND! ({len(path)} moves)")
                print(f"    {path}")
                
                # Auto save to path.txt
                with open('path.txt', 'w') as f:
                    f.write(path)
                print(f"\n[+] Path saved to 'path.txt'")
                
                return path
            
            for dz, dy, dx, cmd in directions:
                nz, ny, nx = z + dz, y + dy, x + dx
                
                if (nz, ny, nx) in visited:
                    continue
                
                if can_move(raw, base_offset, nz, ny, nx):
                    visited.add((nz, ny, nx))
                    queue.append(((nz, ny, nx), path + cmd))
        
        print("[!] No path found!")
        return None

    if __name__ == "__main__":
        main()
    ```
- Sau khi thực hiện BFS, ta tìm được đường đi thoả mãn là:

    ```
    UUURFURURRFRRFFUUFURRUFUFFRFUFUUUUFFRRUUUFURFDFFUFFRRRRRFRR
    ```

    ![Path](https://github.com/UITxWoodyNguyen/CTF/blob/main/HTB-CTFTryOut/RE/TunnelMadness/Screenshot%202025-12-09%20234423.png)

- Tạo thêm 1 script kết nối với server của bài cung cấp và input bằng file `.txt` lưu path trên, ta dễ dàng tìm được flag:

    ```python
    from pwn import *

    # Config
    LOCAL = False  # Đổi thành False để connect remote
    HOST = "94.237.63.176"
    PORT = 52434

    def main():
        # Đọc path từ file
        try:
            with open('path.txt', 'r') as f:
                path = f.read().strip()
            print(f"[+] Loaded path ({len(path)} moves)")
        except FileNotFoundError:
            print("[!] path.txt not found! Run script.py first.")
            return
        
        # Connect
        if LOCAL:
            print("[*] Running locally...")
            p = process('./tunnel')
        else:
            print(f"[*] Connecting to {HOST}:{PORT}...")
            p = remote(HOST, PORT)
        
        # Send each direction
        print("[*] Solving maze...")
        for i, c in enumerate(path):
            p.sendlineafter(b"? ", c.encode())
            if (i + 1) % 50 == 0:
                print(f"    [{i+1}/{len(path)}] moves sent...")
        
        print(f"[+] All {len(path)} moves sent!")
        print("[*] Getting flag...\n")
        
        # Get output
        p.interactive()

    if __name__ == "__main__":
        main()
    ```

- Kết quả:

    ![Flag](https://github.com/UITxWoodyNguyen/CTF/blob/main/HTB-CTFTryOut/RE/TunnelMadness/Screenshot%202025-12-09%20234448.png)