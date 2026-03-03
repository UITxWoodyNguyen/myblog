---
title: "Startfield Relay - UniVsThreats26 Quals Writeup"
date: 2026-03-02
tags: [UVT, reverse]
description: "My team's write up for UVT contest"
---

## Challenge Description
A recovered spacecraft utility binary is believed to validate a multi-part unlock phrase.
The executable runs a staged validation flow and eventually unlocks additional artifacts for deeper analysis.
Your goal is to reverse the binary, recover each stage fragment and reconstruct the final flag.

## Find the target
The challenge gives us an `.exe` file. The binary presents a 10-stage challenge. Each stage accepts a text input, validates it internally, and reveals the next stage if correct.

## Reverse

### Stage 1
At step 1, the binary prints `"Stage 1/10: recover and enter the base prefix (4 chars)"` then reads a line from stdin. It validates the 4 bytes against the hardcoded string `UVT{` using a sequential byte-compare loop. Here is the validate process:
```asm
movzx   eax, byte ptr [rax]       ; load expected byte 0 from binary constant
cmp     [rcx], al                 ; compare with input byte 0
jnz     short loc_fail            ; fail if mismatch

movzx   eax, byte ptr [rax+1]
cmp     [rcx+1], al
jnz     short loc_fail

movzx   eax, byte ptr [rax+2]
cmp     [rcx+2], al
jnz     short loc_fail

movzx   eax, byte ptr [rax+3]    ; 4th byte for Stage 1
cmp     [rcx+3], al
jnz     short loc_fail
```
- `rax` → pointer to the expected constant bytes inside the binary
- `rcx` → pointer to the user-supplied input buffer (read from stdin)
The expected bytes for Stage 1 (visible in `strings` output and confirmed by the compare):
```
'U' (0x55)  'V' (0x56)  'T' (0x54)  '{' (0x7B)
```
So, the answer of the Stage 1 is the flag format **`UVT{`**. 

### Stage 2
At this stage, the binary uses function **`sub_140115860`**. The process is:
- Prints `"enter fragment (3 chars): "` → reads 3-char input
- Calls `sub_140115AA0` to *build* the expected fragment in a local buffer
- Compares the input byte-by-byte against the built fragment (3 comparisons)

Specifically, looking at the assembly source code:
- `sub_140115860` - Input reading:
    - First it prints `"enter fragment (3 chars): "`:
        ```asm
        lea     rdx, aEnterFragment3    ; "enter fragment (3 chars): "
        lea     rcx, qword_14043A5E0
        call    sub_14010C790           ; print the prompt
        ```
    - Then reads input and checks length == 3:
        ```asm
        cmp     [rbp+var_18], 3         ; was exactly 3 chars entered?
        jz      short loc_140115947     ; yes → go validate
        xor     sil, sil                ; no → fail (return 0)
        jmp     loc_140115A32
        ```
- `sub_140115AA0`:
    - First, it builds the expected fragment:
        ```asm
        mov     byte ptr [rcx], 4Bh     ; 'K'
        ...
        mov     byte ptr [rcx+1], 72h   ; 'r'
        ...
        mov     byte ptr [rcx+2], 34h   ; '4'
        ```
    - Then it validate user input via a checker:
        ```asm
        movzx   eax, byte ptr [rax]
        cmp     [rcx], al               ; input[0] == 'K'?
        jnz     short loc_1401159E8     ; fail

        movzx   eax, byte ptr [rax+1]
        cmp     [rcx+1], al             ; input[1] == 'r'?
        jnz     short loc_1401159E8

        movzx   eax, byte ptr [rax+2]
        cmp     [rcx+2], al             ; input[2] == '4'?
        jnz     short loc_1401159E8
        ```
So, the answer of Stage 2 is **`Kr4`**.

### Stage 3
At stage 3, the binary uses function **`sub_140115B80`**. The process is:
- Prints `"enter stage2 token (8 chars): "` and reads 8-char input
- Verifies `length == 8`: `cmp [rbp+60h+var_B0], 8` / `jnz loc_1401161FD`
- Embeds two hardcoded 4-byte constants (the "scrambled" expected result) on the stack
- Runs a per-byte transform loop on the input and compares each transformed byte against the stored constant

Checkout the stage process in the assembly source:
- First, embedding expected constant (`sub_140115B80`)
    ```asm
    mov     dword ptr [rbp+60h+var_98], 0FADC2431h
    mov     dword ptr [rbp+60h+var_98+4], 0C5E42C25h
    ```
    These 8 bytes (little-endian) hold the expected *transformed* values: `31 24 DC FA 25 2C E4 C5`.
- Next, it do a validation loop for each byte:
    ```asm
    loc_140115C80:
        lea     rcx, [rbp+60h+var_C0]
        cmp     r10, 0Fh
        cmova   rcx, r9                   ; rcx → input buffer

        movzx   eax, r8b                  ; i = loop index (0..7)
        imul    edx, eax, 11h             ; edx = i * 0x11
        add     dl, 6Dh                   ; dl += 0x6d  ('m')
        xor     dl, [rcx+r8]              ; dl ^= input[i]

        movzx   eax, r8b
        imul    ecx, eax, 7               ; ecx = i * 7
        add     dl, 13h                   ; dl += 0x13
        add     dl, cl                    ; dl += (i*7) & 0xFF

        cmp     dl, byte ptr [rbp+r8+60h+var_98]  ; compare with expected[i]
        jnz     loc_1401161FD             ; fail if mismatch

        inc     r8
        cmp     r8, 8
        jb      short loc_140115C80       ; loop for 8 bytes
    ```
    - **Transform per byte `i`:** `(i*0x11 + 0x6d) XOR input[i] + 0x13 + (i*7)` must equal `expected[i]`. 
    - We got a python reverse source code here:
        ```python
        expected = [0x31, 0x24, 0xDC, 0xFA, 0x25, 0x2C, 0xE4, 0xC5]
        result = []
        for i in range(8):
            e = expected[i]
            # e = ((i*0x11 + 0x6d) XOR input[i]) + 0x13 + (i*7)
            # => (i*0x11 + 0x6d) XOR input[i] = (e - 0x13 - i*7) & 0xFF
            transformed = (e - 0x13 - i*7) & 0xFF
            result.append(transformed ^ ((i*0x11 + 0x6d) & 0xFF))
        print(bytes(result))   # => b'st4rG4te'
        ```
Run the python source and we will find the answer for Stage 3: `st4rG4te`. 

### Stage 4
Overall, the process of Stage 4 looks similarly to Stage 3. Here is the assembly source to find the answer for Stage 4:
- First, embedding expected constant:
    ```asm
    mov     [rsp+340h+var_300], 0EDA7D1D7h
    mov     [rsp+340h+var_2FC], 49683954h
    ```
    Expected bytes (little-endian 8 bytes): `D7 D1 A7 ED 54 39 68 49`.
- Next, it do a validation loop for each byte:
    ```asm
    loc_140116620:
        lea     rdx, [rbp+240h+var_110]
        cmp     r11, 0Fh
        cmova   rdx, r10                  ; rdx → input buffer

        movzx   eax, r9b                  ; i = loop index (0..7)
        imul    ecx, eax, 0Bh             ; ecx = i * 11
        mov     r8d, 0A7h
        sub     r8b, cl                   ; r8b = 0xA7 - (i*11)
        xor     r8b, [rdx+r9]             ; r8b ^= input[i]

        movzx   eax, r9b
        add     al, al                    ; al = i*2
        lea     ecx, [rax+r9]             ; ecx = i*2 + i = i*3
        add     r8b, cl                   ; r8b += i*3

        cmp     r8b, byte ptr [rsp+r9+340h+var_300]  ; compare with expected[i]
        jnz     loc_140116D12             ; fail if mismatch

        inc     r9
        cmp     r9, 8
        jb      short loc_140116620       ; loop for 8 bytes
    ```
    - **Transform per byte `i`:** `(0xA7 - i*0xB) XOR input[i] + i*3` must equal `expected[i]`.
    - So we have the same python reverse source code here:
        ```python
        expected = [0xD7, 0xD1, 0xA7, 0xED, 0x54, 0x39, 0x68, 0x49]
        result = []
        for i in range(8):
            e = expected[i]
            # e = ((0xA7 - i*0xB) XOR input[i]) + i*3
            # => (0xA7 - i*0xB) XOR input[i] = (e - i*3) & 0xFF
            transformed = (e - i*3) & 0xFF
            result.append(transformed ^ ((0xA7 - i*0xB) & 0xFF))
        print(bytes(result))   # => b'pR0b3Z3n'
        ```
Run the python script and we will find the correct answer: `pR0b3Z3n`.

### Stage 5-6
Stages 5 and 6 require no input. The binary contains an embedded blob tagged with:
- Marker string: `uvt::stage2blob::v4` / `UVTBLOB4`

Verify with:
```sh
strings startfield/Startfield/crackme.exe | egrep "uvt::|Stage|UVTBLOB4|zen_void|pings"
```

When stage 5 triggers, the binary runs an internal VM/extractor that decompresses and writes the payload directory to:

```
uvt_crackme_work/stage2/
  starfield_pings/pings.txt      ← Stage 7 data
  logs/system.log                ← Stage 8 data
  void/zen_void.bin              ← Stage 9/10 data
  void/zen_void_readme.txt       ← key hints for Stage 9/10
  probe_extender/probe_extender.py
```

Stage 6 verifies the hash of the extracted payload. The program prints:
```
stage5: payload already extracted (hash match)
stage5: continue in: Z:\...\uvt_crackme_work\stage2
Great! Stage 6/10 done.
```

### Stage 7
At this stage, the binary points to `uvt_crackme_work/stage2/starfield_pings/pings.txt` and asks for the decoded fragment.

Moving to the decoding process, `pings.txt` contains two hex maps (labeled "even" and "odd") and parity hints. The encoding steps (which must be reversed) are:
- The original fragment bytes were split into two groups by index parity (even/odd index).
- **Even-indexed bytes** were XORed with `0x52`.
- **Odd-indexed bytes** were XORed with `0x13`, then the resulting sub-array was **reversed**.
- The two maps were stored separately in the file.

We have the python reverse source for this Stage:
```python
import json

with open("uvt_crackme_work/stage2/starfield_pings/pings.txt") as f:
    data = json.load(f)

even_map = bytes.fromhex(data["even"])   # even-indexed encoded bytes
odd_map  = bytes.fromhex(data["odd"])    # odd-indexed encoded bytes (reversed)

# Undo: reverse odd_map, then XOR each byte back
odd_decoded  = bytes(b ^ 0x13 for b in reversed(odd_map))
even_decoded = bytes(b ^ 0x52 for b in even_map)

# Interleave: even[0], odd[0], even[1], odd[1], ...
fragment = []
for a, b in zip(even_decoded, odd_decoded):
    fragment.append(a)
    fragment.append(b)
print(bytes(fragment).decode())   # => "uR_pR0b3Z_xTND-"
```

The answer is **`uR_pR0b3Z_xTND`**

### Stage 8
At this stage, the binary points to `uvt_crackme_work/stage2/logs/system.log` and asks for the decoded fragment.

Moving to the decoding process, `system.log` contains JSON-formatted `telemetry_rollup` entries. Each entry has two fields:
- `"k"`: a one-byte XOR key (integer)
- `"fragx"`: a hex-encoded byte string (fragment piece)

Base on the analyzing, the reverse source code is:
```python
import json, base64

results = []
with open("uvt_crackme_work/stage2/logs/system.log") as f:
    for line in f:
        entry = json.loads(line.strip())
        k     = entry["k"]                        # one-byte key
        frag  = bytes.fromhex(entry["fragx"])     # raw fragment bytes
        dec   = bytes(b ^ k for b in frag)        # XOR each byte with k
        results.append(dec)

combined = b"".join(results)
# Add padding if needed and base64-decode
padding = (4 - len(combined) % 4) % 4
decoded = base64.b64decode(combined + b"=" * padding)
print(decoded.decode())    # => "I_h1D3_in_l0Gz_"
```

The answer is **`I_h1D3_in_l0Gz_`**

### Stage 9 
At this stage, the binary references `uvt_crackme_work/stage2/void/zen_void.bin`. This is a large, mostly-zero binary file with several small non-zero "islands" scattered at known offsets. The `zen_void_readme.txt` (also extracted) documents the decryption keys.

To finding `islands`, first we create `probe_extender.py` (included in the extracted payload):
```python
fn = 'uvt_crackme_work/stage2/void/zen_void.bin'
data = open(fn, 'rb').read()
# Islands identified by scanning for runs of non-zero bytes:
islands = [
    (0x2345, 0x234b),
    (0x234d, 0x2350),
    (0x9550, 0x9557),
    (0x9d20, 0x9d27),
    (0xa1b2, 0xa1b9),
    (0xe3c4, 0xe3ca),
]
```

Next, in `zen_void_readme.txt` states, we can find the **key `0x2a`** decodes the Stage 8 island.
```python
key = 0x2a
for s, e in islands:
    block = data[s:e+1]
    dec   = bytes(b ^ key for b in block)
    if all(32 <= c < 127 for c in dec):
        print(hex(s), "->", dec.decode())
# Output: 0xa1b2 -> "1n_v01D_"
```

So the Stage 9 answer is **`1n_v01D_`**

### Stage 10
At this stage, the readme states: **Stage 10 key = `sum(bytes(stage9_text)) % 256`**

Base on this, we have a source code for stage 10:
```python
stage9_text = b'1n_v01D_'
key10 = sum(stage9_text) % 256     # = 0x?? (computed at runtime)

for s, e in islands:
    if s == 0xa1b2:                 # skip the Stage 9 island
        continue
    block = data[s:e+1]
    dec   = bytes(b ^ key10 for b in block)
    if all(32 <= c < 127 for c in dec):
        print(hex(s), "->", dec.decode())
# Output: 0xe3c4 -> "iN_ZEN}"
```

The stage 10 answer is **`iN_ZEN}`**

## Get flag
After solving all 10 step, run the binary with `wine` to get the flag:
```bash
printf "UVT{\nKr4\nst4rG4te\npR0b3Z3n\nuR_pR0b3Z_xTND-\nI_h1D3_in_l0Gz_\n1n_v01D_\niN_ZEN}\n" | wine startfield/Startfield/crackme.exe
```

Here is the shell run:
```bash
$  printf "UVT{\nKr4\nst4rG4te\npR0b3Z3n\nuR_pR0b3Z_xTND-\nI_h1D3_in_l0Gz_\n1n_v01D_\niN_ZEN}\n" | wine startfield/Startfield/crackme.exe
Stage 1/10: recover and enter the base prefix (4 chars)
enter base prefix (4 chars): Great! Stage 1/10 done.

Next:
Stage 2/10: enter the 3-char fragment
enter fragment (3 chars): Great! Stage 2/10 done.

Next:
Stage 3/10: enter the stage2 token (8 chars)
enter stage2 token (8 chars): Great! Stage 3/10 done.

Next:
Stage 4/10: enter the token (8 chars)
enter token (8 chars): Great! Stage 4/10 done.

Next:
Stage 5/10: execute the VM (no input)
Great! Stage 5/10 done.

Next:
Stage 6/10: extract the embedded stage2 payload (no input)
stage5: payload already extracted (hash match)
stage5: continue in: Z:\home\kali\Desktop\wargame\uvt_crackme_work\stage2
Great! Stage 6/10 done.

Next:
Stage 7/10: decode starfield pings and enter the recovered fragment
  file: Z:\home\kali\Desktop\wargame\uvt_crackme_work\stage2\starfield_pings\pings.txt
enter fragment: Great! Stage 7/10 done.

Next:
Stage 8/10: recover the hidden hint from logs and enter the decoded fragment
  file: Z:\home\kali\Desktop\wargame\uvt_crackme_work\stage2\logs\system.log
enter fragment: Great! Stage 8/10 done.

Next:
Stage 9/10: find the island in the void container and enter the extracted fragment
  file: Z:\home\kali\Desktop\wargame\uvt_crackme_work\stage2\void\zen_void.bin
enter fragment: Great! Stage 9/10 done.

Next:
Stage 10/10: final: compute the last fragment and enter it
  file: Z:\home\kali\Desktop\wargame\uvt_crackme_work\stage2\void\zen_void.bin
enter fragment: Great! Stage 10/10 done.
UVT{Kr4cK_M3_N0w-cR4Km3_THEN-5T4rf13Ld_piNgS_uR_pR0b3Z_xTND-I_h1D3_in_l0Gz_1n_v01D_iN_ZEN}
```

The flag is **`UVT{Kr4cK_M3_N0w-cR4Km3_THEN-5T4rf13Ld_piNgS_uR_pR0b3Z_xTND-I_h1D3_in_l0Gz_1n_v01D_iN_ZEN}`**