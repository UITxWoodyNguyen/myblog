---
title: "El Diablo - BITSCTF Write Up"
date: 2026-02-26
tags: [BITSCTF, reverse]
description: "This is the write up for El Diablo chall - BITSCTF contest"
---

## Challenge Info

| Field | Details |
|-------|---------|
| **Name** | Diablo |
| **Category** | Reverse Engineering |
| **Flag format** | `BITSCTF{}` |
| **Description** | *"I bought this program but I lost the license file..."* |
| **File** | `challenge` — ELF 64-bit LSB PIE executable, x86-64, statically linked |

## Flag

```
BITSCTF{l4y3r_by_l4y3r_y0u_unr4v3l_my_53cr375}
```

> Read in leetspeak: **"layer by layer you unravel my secrets"** — perfectly describing the approach to solving this challenge: peeling off one protection layer at a time.

---

## Vulnerability Summary

The challenge implements **five stacked protection layers**:

1. **UPX packing** — real code is compressed inside the binary
2. **Anti-debug protection** — checks `/proc/self/status` TracerPid, WSL detection, parent process name check (gdb, strace, ltrace, ida64, etc.)
3. **Custom bytecode VM** — program logic runs inside a hand-rolled virtual machine
4. **License format obfuscation** — the license key bytes are hex-encoded (not raw binary)
5. **10-byte repeating XOR encryption** — flag characters are XOR'd with a cycling 10-byte key

The core vulnerability exploited is an unintentional **hidden debug interface**: each VM opcode handler calls `getenv("OPCODE_NAME")` at runtime and prints debug info if the environment variable is set. By setting `PRINT_FLAG_CHAR=1`, we force the VM to output each flag character as it is computed, without needing to reverse the full VM bytecode. Combined with a **known-plaintext XOR attack** using the known flag prefix `BITSCTF{`, the full 10-byte key can be recovered.

---

## Step 1: Initial Reconnaissance

### 1.1 Identify the binary

```bash
$ file challenge
challenge: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
           statically linked, no section header
```

Key observations:
- **Statically linked + no section header**: The binary has been stripped or packed. There is no symbol table for IDA/Ghidra to resolve function names. All analysis must be done on raw bytes.
- **PIE executable**: The load address changes every run (ASLR). Disable it in GDB with `set disable-randomization on` to keep addresses reproducible.

### 1.2 Run `strings` to find clues

```bash
$ strings challenge | head -20
6UPX!P
/lib64
nux-x86-
strchr
fseek
atoimn
...
GLIBC_2.7
```

The very first meaningful string is `UPX!` — the magic marker of **UPX (Ultimate Packer for eXecutables)**. UPX compresses the original binary and prepends a small *decompression stub* that inflates the real code into memory at runtime. This means:

- The actual program logic is compressed inside the binary and invisible to static analysis tools.
- IDA/Ghidra can only disassemble the decompression stub; the real functions are hidden.
- We must either unpack the binary statically (using `upx -d`) or — if UPX is modified and `upx -d` fails — dump the decompressed code from memory at runtime using GDB.

### 1.3 Open with IDA — Confirm UPX

The file `as.asm` (exported from IDA Free) confirms this:

```asm
; String at LOAD:0x30CC:
aInfoThisFileIs db '$Info: This file is packed with the UPX executable packer http://upx.sf.net $',0Ah,0

; String at LOAD:0x311B:
aIdUpx396Copyri db '$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $',0Ah,0
```

IDA can only disassemble the **UPX decompression stub** at the entry point `0x2F88`. The real program code is compressed data at this stage and IDA cannot interpret it.

The UPX entry stub (`start` at `0x2F88`) calls into `sub_2FFA`, which implements the LZ77-based decompression loop. After this runs, the real code is mapped to new anonymous memory regions.

```asm
LOAD:0000000000002F88 start           proc near
LOAD:0000000000002F88                 push    rax
LOAD:0000000000002F89                 push    rdx
LOAD:0000000000002F8A                 call    loc_323E        ; call decompressor setup
LOAD:0000000000002F8F                 push    rbp
LOAD:0000000000002F90                 push    rbx
LOAD:0000000000002F91                 push    rcx
LOAD:0000000000002F92                 push    rdx
LOAD:0000000000002F93                 add     rsi, rdi
LOAD:0000000000002F96                 push    rsi
LOAD:0000000000002F97                 mov     rsi, rdi
LOAD:0000000000002F9A                 mov     rdi, rdx
LOAD:0000000000002F9D                 xor     ebx, ebx
LOAD:0000000000002F9F                 xor     ecx, ecx
LOAD:0000000000002FA1                 or      rbp, 0FFFFFFFFFFFFFFFFh
LOAD:0000000000002FA5                 call    sub_2FFA        ; LZ77 decompressor loop
```

---

## Step 2: Run the Binary — Understand Behavior

### 2.1 Run without arguments

```bash
$ ./challenge
Welcome my DRM-protected application!
To sucessfully get in, you must present a valid license file.
Reverse engineer this binary to figure out the license format, and get the flag. :)
Good luck!

Usage: ./challenge <license file path>
```

The binary simulates a **DRM-protected application** that requires a license file. Supplying the correct file reveals the flag.

### 2.2 Run with a trivial license file

```bash
$ echo "test" > lic.txt
$ ./challenge lic.txt
[i] loaded license file
[!] invalid license format
```

The file is read successfully but fails the format check. We need to find the correct format.

### 2.3 Try the prefix `LICENSE-`

```bash
$ echo "LICENSE-" > lic.txt
$ ./challenge lic.txt
[i] loaded license file
processing... please wait...
[i] running program...
The flag lies here somewhere...
```

**Key discovery**: The prefix `LICENSE-` passes the format check! The binary runs an internal "program", but the flag is not yet printed — something is still missing.

---

## Step 3: Dump Runtime Memory with GDB

### 3.1 Why memory dump?

Because UPX compresses the real code, it only exists **in memory after decompression**. Static analysis tools see only the stub. To analyze the real logic we need to:

1. Let the binary run (UPX decompresses itself).
2. Pause execution *after* decompression, *before* the anti-debug check.
3. Dump all readable memory regions to disk for offline analysis.

### 3.2 GDB dump script

The key insight is to `catch syscall write` — the very first output the binary writes (the "Welcome..." message) happens only after UPX has fully decompressed everything. This is a safe and reliable pause point.

**`dump_memory.gdb`**:

```gdb
set disable-randomization on
set pagination off
set logging file /tmp/gdb_out.log
set logging on

file ./challenge

# Create a dummy license file
shell echo "test" > /tmp/lic_test.txt
set args /tmp/lic_test.txt

# The binary writes "Welcome..." via write() AFTER UPX decompression.
# Catch the first write syscall to pause at the decompressed state.
catch syscall write

run

# At this point UPX has fully decompressed and we're inside the real binary.
# Use embedded Python to dump all readable memory regions.
python
import gdb, os

inf = gdb.selected_inferior()
pid = inf.pid
print(f"[*] Process PID: {pid}")

maps_raw = open(f"/proc/{pid}/maps").read()
print("[*] Memory maps:")
print(maps_raw)

os.makedirs("/tmp/diablo_dump", exist_ok=True)

for line in maps_raw.splitlines():
    parts = line.split()
    if len(parts) < 2:
        continue
    perms = parts[1]
    addr_range = parts[0]
    start, end = [int(x, 16) for x in addr_range.split("-")]
    size = end - start
    if size == 0 or "r" not in perms:
        continue
    try:
        data = bytes(inf.read_memory(start, size))
        fname = f"/tmp/diablo_dump/seg_{start:016x}_{end:016x}_{perms}.bin"
        with open(fname, "wb") as f:
            f.write(data)
        print(f"[+] Dumped {perms} {addr_range} ({size} bytes) -> {fname}")
    except Exception as e:
        print(f"[-] Failed {addr_range}: {e}")

end
quit
```

### 3.3 Resulting memory map

After decompression, the memory layout looks like this:

```
7ffff7c00000-7ffff7e05000  r-xp  libc.so.6           (C standard library)
7ffff7fac000-7ffff7fad000  r--p  challenge            (original binary stub, only 4 KB)
7ffff7ff1000-7ffff7ff3000  r--p  [anonymous]          (read-only data)
7ffff7ff3000-7ffff7ff9000  r-xp  [anonymous]          (REAL CODE — 24 KB!)
7ffff7ff9000-7ffff7ffc000  r--p  [anonymous]          (RODATA — strings!)
7ffff7ffc000-7ffff7fff000  rw-p  [anonymous]          (DATA — heap, globals)
```

**Regions of interest**:
- `0x7ffff7ff3000` (24 KB, `r-xp`) — The **real code segment** containing all program logic after decompression.
- `0x7ffff7ff9000` (12 KB, `r--p`) — The **rodata segment** containing all string constants referenced by the decompressed code.

---

## Step 4: Analyze Strings in Rodata — Discover the Virtual Machine

### 4.1 Extract strings from the rodata dump

From the region at `0x7ffff7ff9000`, we extract all meaningful strings:

```
# Anti-debug strings
'/proc/version'             ← check if running under WSL
'Microsoft', 'microsoft'   ← WSL marker: if present → detected
'/proc/self/status'         ← read TracerPid field
'TracerPid:'                ← if TracerPid != 0 → debugger detected
'/proc/%d/comm'             ← read parent process name
'lldb', 'strace', 'ltrace', 'radare2', 'ida64', 'x64dbg', 'ollydbg', 'windbg'
'DEBUGGER DETECTED! LICENSING TERMS VIOLATED! >:('

# UI / UX strings
'Welcome my DRM-protected application!'
'Usage: ./challenge <license file path>'
'[i] loaded license file'
'[!] invalid license format'
'processing... please wait...'
'[i] running program...'

# License format
'LICENSE-'                  ← mandatory prefix
'%02x'                      ← sscanf format string → HEX DECODE!
'MYVERYREALLDRM'           ← product/DRM name

# ===== VIRTUAL MACHINE STRINGS =====
'GET_LICENSE_BYTE: register out of bounds'
'GET_LICENSE_BYTE[%u] -> 0 (OOB/NULL)'
'PRINT_FLAG_CHAR'
'PRINT_CHAR: register out of bounds'
'[!] failed to create virtual machine instance.'
'Register dump'
'Register %02d - Decimal:%04d [Hex:%04X]'
'Register %02d - str: %s'
'Register %02d has unknown type!'
'Z-FLAG:true'
'Z-FLAG:false'
"The register doesn't contain a string"
"The register doesn't contain an integer"
'RAM allocation failure.'
'%04X - op_unknown(%02X)'
'Register out of bounds'
'Division by zero!'
'Reading from outside RAM'
'Writing outside RAM'
'stack overflow - stack is full'
'stack overflow - stack is empty'
```

### 4.2 Analysis — This Is a Custom Bytecode VM!

From these strings, we can reconstruct the VM architecture without reading a single line of real code:

| Component | Details |
|-----------|---------|
| **Registers** | 10 registers (0–9), supporting both integer and string types |
| **RAM** | Dedicated VM memory with bounds checking |
| **Stack** | Separate stack with overflow and underflow detection |
| **Z-FLAG** | Zero flag used for conditional branching |
| **Opcodes** | Includes `GET_LICENSE_BYTE`, `PRINT_FLAG_CHAR`, arithmetic, memory operations |
| **Debug mode** | Each opcode handler calls `getenv("OPCODE_NAME")` to enable per-opcode tracing |

**The critical detail — hidden debug interface**: Every VM opcode handler checks if an environment variable with the opcode's own name is set. If the variable exists (any value), the handler prints debug output to stdout. This is a developer debugging facility that was left in the binary. Crucially:

- Setting `PRINT_FLAG_CHAR=1` will cause the VM to **actually print each flag character as it is computed**.
- Setting `GET_LICENSE_BYTE=1` will dump each license key byte access.

---

## Step 5: Exploit the Debug Mode — Enable `PRINT_FLAG_CHAR`

### 5.1 The `PRINT_FLAG_CHAR` handler (reconstructed from Capstone disassembly)

Using Python + Capstone to disassemble the code segment dump, we find the handler at `0x7ffff7ff4785`:

```asm
; PRINT_FLAG_CHAR opcode handler
; -----------------------------------------------
; Check if env var "PRINT_FLAG_CHAR" is set

lea  rax, [rip + 0x4af2]    ; rax = ptr to "PRINT_FLAG_CHAR" string
mov  rdi, rax
call getenv                  ; rc = getenv("PRINT_FLAG_CHAR")
test rax, rax                ; if NULL, env var not set
je   skip_print              ; → skip the print entirely

; env var is set → proceed to print the flag character
; Compute:  flag_char = encrypted_byte XOR license_key[i % 10]
; ... (computation instructions) ...

mov  edi, eax                ; edi = flag character to print
call putchar                 ; print it to stdout
```

**Takeaway**: If we export `PRINT_FLAG_CHAR=1` before running the binary, the VM will call `putchar()` for each flag character — effectively bypassing the need to reverse the XOR decryption logic.

### 5.2 Run with env vars enabled

```bash
$ echo "LICENSE-" > lic.txt
$ PRINT_FLAG_CHAR=1 GET_LICENSE_BYTE=1 ./challenge lic.txt
[i] loaded license file
processing... please wait...
[i] running program...
The flag lies here somewhere...
GET_LICENSE_BYTE[0] -> 0 (OOB/NULL)
ۼGET_LICENSE_BYTE[1] -> 0 (OOB/NULL)
¼GET_LICENSE_BYTE[2] -> 0 (OOB/NULL)
3GET_LICENSE_BYTE[3] -> 0 (OOB/NULL)
B...
```

**Result**: The VM prints encrypted bytes (interleaved with `GET_LICENSE_BYTE` debug lines). These bytes are the **encrypted flag characters** — they are not correct yet because the license key bytes are OOB (Out-Of-Bounds / NULL), meaning the XOR key bytes default to `0x00`.

The pattern `GET_LICENSE_BYTE[0]` → `[1]` → ... → `GET_LICENSE_BYTE[9]` → `GET_LICENSE_BYTE[0]` → ... shows the VM reads **exactly 10 license bytes in a cycle** throughout the 46-character flag.

---

## Step 6: Reverse the main() Function — Discover HEX DECODE

### 6.1 Disassemble main() with Capstone

We use Python + Capstone to disassemble the real code segment from the dumps:

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

md = Cs(CS_ARCH_X86, CS_MODE_64)
with open("/tmp/diablo_dump/seg_7ffff7ff3000_7ffff7ff9000_r-xp.bin", "rb") as f:
    code = f.read()

CODE_BASE = 0x7ffff7ff3000

# Disassemble from main() at 0x7ffff7ff3fcf
offset = 0x7ffff7ff3fcf - CODE_BASE
for insn in md.disasm(code[offset:offset+512], 0x7ffff7ff3fcf):
    print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
```

### 6.2 Reconstructed main() logic

From the disassembly, we reconstruct the following pseudocode:

```c
int main(int argc, char *argv[]) {
    if (argc <= 1) {
        // Print welcome message and usage
        puts("Welcome my DRM-protected application!");
        puts("Usage: ./challenge <license file path>");
        return -1;
    }

    // 1. Read the license file into memory
    char *file_data = read_file(argv[1]);
    puts("[i] loaded license file");

    // 2. Check mandatory prefix "LICENSE-"
    if (file_data == NULL || strncmp(file_data, "LICENSE-", 8) != 0) {
        puts("[!] invalid license format");
        return -1;
    }

    // 3. Advance past the prefix
    char *hex_data = file_data + 8;          // pointer to hex string
    size_t len = strlen(hex_data);

    // 4. Strip trailing whitespace (\n, \r, space)
    while (len > 0) {
        char c = hex_data[len - 1];
        if (c != '\n' && c != '\r' && c != ' ') break;
        len--;
    }

    // 5. ★★★ HEX DECODE ★★★
    // Each pair of hex digits encodes one raw key byte.
    // The format string "%02x" is stored in rodata and used here.
    size_t key_len = len / 2;                // 2 hex chars → 1 byte
    uint8_t *key = calloc(1, key_len + 1);
    for (size_t i = 0; i < key_len; i++) {
        sscanf(hex_data + i*2, "%02x", &key[i]);  // ← "%02x" in rodata
    }

    // 6. Pass key bytes to the VM
    setup_vm_license(key, key_len);

    // 7. Anti-debug check
    // Reads /proc/self/status → TracerPid field
    // Reads /proc/version     → checks for "Microsoft" (WSL)
    // Reads /proc/<ppid>/comm → checks parent process name
    if (check_debugger()) {
        puts("DEBUGGER DETECTED! LICENSING TERMS VIOLATED! >:(");
        return -1;
    }

    // 8. Trigger SIGILL → signal handler executes the VM
    //    (ud2 = undefined instruction, generates SIGILL)
    __asm__("ud2");      // → SIGILL → installed handler runs VM
    run_vm();

    return 0;
}
```

### 6.3 The key discovery — HEX ENCODING

The line `sscanf(hex_data + i*2, "%02x", &key[i])` is the most important finding. 

The license file **must contain hex-encoded bytes** after the `LICENSE-` prefix — not raw binary data. For example:
- `LICENSE-41424344` → 4 key bytes = `[0x41, 0x42, 0x43, 0x44]` = `"ABCD"`
- `LICENSE-99f5671124d520d5f63c` → 10 key bytes (the correct key)

This explains why all our earlier tests with raw bytes after `LICENSE-` resulted in OOB/NULL readings — the raw chars were not valid two-digit hex sequences, so `sscanf` returned 0 for each.

---

## Step 7: Confirm the XOR Cipher

### 7.1 Baseline — all-zero key

We craft a license where all 10 key bytes are `0x00`:

```bash
$ echo "LICENSE-00000000000000000000" > lic.txt
$ PRINT_FLAG_CHAR=1 ./challenge lic.txt
```

This outputs **46 encrypted bytes**. With key = 0x00, `enc[i] XOR 0x00 = enc[i]` — so the output is the raw encrypted flag bytes:

```
Encrypted hex: dbbc3342678166ae9a08e0c6154e46ac7fb9c245aa87386814a07fa0984ead83547d7bb8598ac30ffa87542611a8
```

### 7.2 Flip one bit — key[0] = 0x01

```bash
$ echo "LICENSE-01000000000000000000" > lic.txt
$ PRINT_FLAG_CHAR=1 ./challenge lic.txt
```

Only the first output byte changes: `0xDB → 0xDA`.

### 7.3 Verification

```
0xDB XOR 0x01 = 0xDA  ✓  (matches the observed output!)
```

**Confirmed**: The encryption is **simple repeating XOR**. The formula is:

```
flag_char[i] = encrypted_byte[i] XOR license_key[i % 10]
```

Where:
- `encrypted_byte[i]` — a fixed byte hardcoded inside the VM bytecode
- `license_key[i % 10]` — one of the 10 key bytes, cycling with period 10
- `flag_char[i]` — the `i`-th character of the flag

### 7.4 Verify XOR at ALL positions

We use `crack_key.py` to verify that XOR holds across all 46 positions:

```python
BINARY = "./challenge"

def get_output(key_bytes: bytes) -> bytes:
    """Run with hex-encoded key, return flag bytes after sentinel."""
    hex_str = key_bytes.hex()
    with open("/tmp/crack_lic.txt", "w") as f:
        f.write(f"LICENSE-{hex_str}\n")
    env = os.environ.copy()
    env["PRINT_FLAG_CHAR"] = "1"
    r = subprocess.run([BINARY, "/tmp/crack_lic.txt"],
                       capture_output=True, timeout=10, env=env)
    marker = b"The flag lies here somewhere...\n"
    idx = r.stdout.find(marker)
    if idx >= 0:
        return r.stdout[idx + len(marker):].rstrip()
    return b""

# Baseline: all-zero key → raw encrypted bytes
enc = get_output(bytes(10))

# Test key: "ABCDEFGHIJ" (0x41..0x4A)
test_key = bytes([0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A])
out_test = get_output(test_key)

all_match = True
for i in range(len(enc)):
    expected = enc[i] ^ test_key[i % 10]
    actual   = out_test[i]
    if expected != actual:
        all_match = False
        print(f"  MISMATCH pos {i}")

if all_match:
    print("  ✓ XOR confirmed at ALL 46 positions!")
```

Output: `✓ XOR confirmed at ALL 46 positions!`

---

## Step 8: Crack the 10-Byte XOR Key

### 8.1 Encrypted bytes table

The 46 encrypted bytes (from the all-zero key run), grouped by their key index (position mod 10):

| Key idx | Pos 0   | Pos 10  | Pos 20  | Pos 30  | Pos 40  |
|---------|---------|---------|---------|---------|---------|
| **0**   | `0xDB`  | `0xE0`  | `0xAA`  | `0xAD`  | `0xFA`  |
| **1**   | `0xBC`  | `0xC6`  | `0x87`  | `0x83`  | `0x87`  |
| **2**   | `0x33`  | `0x15`  | `0x38`  | `0x54`  | `0x54`  |
| **3**   | `0x42`  | `0x4E`  | `0x68`  | `0x7D`  | `0x26`  |
| **4**   | `0x67`  | `0x46`  | `0x14`  | `0x7B`  | `0x11`  |
| **5**   | `0x81`  | `0xAC`  | `0xA0`  | `0xB8`  | `0xA8`  |
| **6**   | `0x66`  | `0x7F`  | `0x7F`  | `0x59`  | —       |
| **7**   | `0xAE`  | `0xB9`  | `0xA0`  | `0x8A`  | —       |
| **8**   | `0x9A`  | `0xC2`  | `0x98`  | `0xC3`  | —       |
| **9**   | `0x08`  | `0x45`  | `0x4E`  | `0x0F`  | —       |

### 8.2 Known-plaintext attack using `BITSCTF{`

We know the flag starts with `BITSCTF{` (8 bytes). Since `enc[i] XOR key[i] = flag[i]`, we can invert this: `key[i] = enc[i] XOR flag[i]`. This gives us **key bytes 0 through 7** directly:

```
pos 0: enc=0xDB, flag='B'=0x42  →  key[0] = 0xDB ^ 0x42 = 0x99
pos 1: enc=0xBC, flag='I'=0x49  →  key[1] = 0xBC ^ 0x49 = 0xF5
pos 2: enc=0x33, flag='T'=0x54  →  key[2] = 0x33 ^ 0x54 = 0x67
pos 3: enc=0x42, flag='S'=0x53  →  key[3] = 0x42 ^ 0x53 = 0x11
pos 4: enc=0x67, flag='C'=0x43  →  key[4] = 0x67 ^ 0x43 = 0x24
pos 5: enc=0x81, flag='T'=0x54  →  key[5] = 0x81 ^ 0x54 = 0xD5
pos 6: enc=0x66, flag='F'=0x46  →  key[6] = 0x66 ^ 0x46 = 0x20
pos 7: enc=0xAE, flag='{'=0x7B  →  key[7] = 0xAE ^ 0x7B = 0xD5
```

### 8.3 Partial decrypt to find key[8] and key[9]

With 8 of the 10 key bytes known, we can decrypt positions 0–7, 10–17, 20–27, 30–37, 40–45 (every position whose index mod 10 < 8). The remaining positions (index % 10 == 8 or 9) remain unknown and are shown as `?`:

```
B I T S C T F { ? ? y 3 r _ b y _ l ? ? 3 r _ y 0 u _ u ? ? 4 v 3 l _ m y _ ? ? c r 3 7 5 }
0 1 2 3 4 5 6 7 8 9 ...
```

Partial decrypted string: `BITSCTF{??y3r_by_l??3r_y0u_u??4v3l_my_??cr375}`

### 8.4 Infer from leetspeak context

The pattern is clearly **leetspeak** (where certain letters are replaced with visually similar digits: `a→4`, `e→3`, `s→5`, `o→0`). Reading the partial result:

| Positions | Partial | Inference | Plain text |
|-----------|---------|-----------|------------|
| 8–14      | `??y3r_b` | `l4y3r_b` | "layer" (a→4, e→3) |
| 18–24     | `l??3r_y0` | `l4y3r_y0` | "layer" again |
| 28–34     | `u??4v3l_` | `unr4v3l_` | "unravel" (a→4, e→3) |
| 38–44     | `??cr375}` | `53cr375}` | "secrets" (e→3, s→5) |

Reconstructed full content: `l4y3r_by_l4y3r_y0u_unr4v3l_my_53cr375`

Therefore:
```
pos 8:  flag char = 'l' = 0x6C  →  key[8] = enc[8] ^ 0x6C = 0x9A ^ 0x6C = 0xF6
pos 9:  flag char = '4' = 0x34  →  key[9] = enc[9] ^ 0x34 = 0x08 ^ 0x34 = 0x3C
```

### 8.5 Verify key[8] and key[9] at other positions

We cross-check by applying these key bytes to other positions with the same index:

```
key[8] = 0xF6:
  pos 18: 0xC2 ^ 0xF6 = 0x34 = '4'  ✓  (l4y3r → the 'a'→'4')
  pos 28: 0x98 ^ 0xF6 = 0x6E = 'n'  ✓  (unravel → 'n')
  pos 38: 0xC3 ^ 0xF6 = 0x35 = '5'  ✓  (secrets → 's'→'5')

key[9] = 0x3C:
  pos 19: 0x45 ^ 0x3C = 0x79 = 'y'  ✓  (l4y3r → 'y')
  pos 29: 0x4E ^ 0x3C = 0x72 = 'r'  ✓  (unr4v3l → 'r')
  pos 39: 0x0F ^ 0x3C = 0x33 = '3'  ✓  (53cr375 → 'e'→'3')
```

All positions check out perfectly! ✓

---

## Step 9: Create the License File and Get the Flag

### 9.1 Full 10-byte XOR key

```
Key (10 bytes):  99  F5  67  11  24  D5  20  D5  F6  3C
Hex string:      99f5671124d520d5f63c
```

### 9.2 Create the license file

The license file format is `LICENSE-` followed by the key bytes hex-encoded:

```bash
$ echo "LICENSE-99f5671124d520d5f63c" > license.txt
```

### 9.3 Run the binary

```bash
$ PRINT_FLAG_CHAR=1 ./challenge license.txt
[i] loaded license file
processing... please wait...
[i] running program...
The flag lies here somewhere...
BITSCTF{l4y3r_by_l4y3r_y0u_unr4v3l_my_53cr375}
```

🎉 **FLAG: `BITSCTF{l4y3r_by_l4y3r_y0u_unr4v3l_my_53cr375}`**

---

## Full Solver Script

**`final_solve.py`** — complete solve script from scratch:

```python
#!/usr/bin/env python3
"""
Diablo CTF Solver
Derives the 10-byte XOR key using a known-plaintext attack against "BITSCTF{"
then verifies by running the binary.
"""
import subprocess, os

BINARY = "./challenge"

def get_output(key_bytes: bytes) -> bytes:
    """Run binary with hex-encoded key; return flag bytes after the sentinel line."""
    hex_str = key_bytes.hex()
    fname = "/tmp/final_lic.txt"
    with open(fname, "w") as f:
        f.write(f"LICENSE-{hex_str}\n")
    env = os.environ.copy()
    env["PRINT_FLAG_CHAR"] = "1"
    r = subprocess.run([BINARY, fname], capture_output=True, timeout=10, env=env)
    marker = b"The flag lies here somewhere...\n"
    idx = r.stdout.find(marker)
    if idx >= 0:
        return r.stdout[idx + len(marker):].rstrip()
    return b""

# Step 1: Get the 46 encrypted bytes (XOR with all-zero key = identity)
enc = get_output(bytes(10))
print(f"[*] Encrypted bytes ({len(enc)}): {enc.hex()}")

# Step 2: Known-plaintext attack with flag prefix "BITSCTF{"
prefix = b"BITSCTF{"
key = [enc[i] ^ prefix[i] for i in range(8)]
# key[0..7] = [0x99, 0xF5, 0x67, 0x11, 0x24, 0xD5, 0x20, 0xD5]

# Step 3: Partial decrypt to find key[8] and key[9]
partial = []
for i in range(len(enc)):
    idx = i % 10
    if idx < 8:
        partial.append(chr(enc[i] ^ key[idx]))
    else:
        partial.append('?')
print(f"[*] Partial flag: {''.join(partial)}")
# → BITSCTF{??y3r_by_l??3r_y0u_u??4v3l_my_??cr375}

# Step 4: Infer key[8] and key[9] from leetspeak context
# pos 8 = 'l' (from "l4y3r"),  pos 9 = '4' (from "l4y3r")
key.append(enc[8] ^ ord('l'))   # key[8] = 0x9A ^ 0x6C = 0xF6
key.append(enc[9] ^ ord('4'))   # key[9] = 0x08 ^ 0x34 = 0x3C

# Step 5: Full decryption
flag = ''.join(chr(enc[i] ^ key[i % 10]) for i in range(len(enc)))
print(f"\n[+] KEY:  {bytes(key).hex()}")
print(f"[+] FLAG: {flag}")

# Step 6: Verify by running the binary with the real key
out = get_output(bytes(key))
print(f"\n[+] Binary verification: {out.decode(errors='replace')}")

# Expected output:
# [+] KEY:  99f5671124d520d5f63c
# [+] FLAG: BITSCTF{l4y3r_by_l4y3r_y0u_unr4v3l_my_53cr375}
```

---

## Technical Summary

```
┌─────────────────────────────────┐
│        UPX Packed Binary        │  ← Layer 1: Packing
│   (strings → UPX signature)     │
└───────────────┬─────────────────┘
                ↓  GDB catch syscall write + memory dump
┌─────────────────────────────────┐
│    Anti-Debug Protection        │  ← Layer 2: Anti-debug
│  TracerPid, /proc/version,      │
│  parent process name check      │
└───────────────┬─────────────────┘
                ↓  Bypass: run without GDB, use env vars instead
┌─────────────────────────────────┐
│   Custom Bytecode VM            │  ← Layer 3: VM obfuscation
│  10 registers, stack, RAM,      │
│  Z-FLAG, custom opcodes         │
└───────────────┬─────────────────┘
                ↓  PRINT_FLAG_CHAR env var → enable putchar output
┌─────────────────────────────────┐
│   License Format Obfuscation    │  ← Layer 4: Hex encoding
│  LICENSE-<hex encoded bytes>    │
│  sscanf("%02x", ...) decode     │
└───────────────┬─────────────────┘
                ↓  Capstone disassembly → discover sscanf("%02x")
┌─────────────────────────────────┐
│   10-byte Repeating XOR         │  ← Layer 5: Encryption
│  flag[i] = enc[i] ^ key[i%10]  │
└───────────────┬─────────────────┘
                ↓  Known-plaintext: BITSCTF{ + leetspeak reasoning
┌─────────────────────────────────┐
│              FLAG               │
│  BITSCTF{l4y3r_by_l4y3r_y0u_   │
│  unr4v3l_my_53cr375}           │
└─────────────────────────────────┘
```

### Tools Used

| Tool | Purpose |
|------|---------|
| `strings` | Identify UPX packing from signature string |
| **GDB** + `catch syscall write` | Pause after UPX decompression, dump all memory |
| **Capstone** (Python) | Disassemble x86-64 machine code from raw dumps |
| **Python** `subprocess` | Run binary with controlled inputs and env vars |
| Environment variables | Activate per-opcode VM debug mode (`PRINT_FLAG_CHAR`, `GET_LICENSE_BYTE`) |
| Known-plaintext XOR attack | Recover 10-byte key from known flag prefix `BITSCTF{` |
| Leetspeak pattern analysis | Infer the 2 remaining unknown key bytes from context |

### Key Lessons

1. **`strings` is never useless** — even on a packed binary, the presence of `UPX!` in the output reveals the packing mechanism. Always run `strings` as a first step.

2. **Runtime analysis beats static analysis for packed/obfuscated binaries** — catching a first `write()` syscall with GDB gives you a perfect decompression pause point that works universally for UPX-packed binaries.

3. **Always check `getenv()` calls** — developer debug backdoors left in production code are one of the most valuable findings in reverse engineering. Scan for `getenv` in every binary you analyze.

4. **Known-plaintext XOR attack is devastatingly effective** — if you know any part of the plaintext (e.g., a flag format prefix), you can directly recover the corresponding key bytes without needing to find the key elsewhere.

5. **Context-aware cryptanalysis** — when you can decrypt most of a message, human language patterns (leetspeak, natural language, repeated words) let you infer the remaining unknown parts, closing the last gap in a partial key.