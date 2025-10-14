
# CipherXploit

**A powerful, modular, and automated CTF cryptography & encoding solver — built for real-world challenges.**

**Developed by Shoaib Bin Rashid (R3D_XplOiT)**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)  
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://chatgpt.com/g/g-p-68d273db73a48191b720357409006025-shoaib/c/LICENSE)  
[![GitHub stars](https://img.shields.io/github/stars/Shoaib-Bin-Rashid/CipherXploit?style=social)](https://github.com/Shoaib-Bin-Rashid/CipherXploit/stargazers)


----------

## Overview

`CipherXploit` is an automated tool focused on quickly identifying and attempting to break common encodings and classical ciphers encountered in CTFs and puzzles. It combines many lightweight decoding routines, bruteforce attempts, and heuristics to prioritize outputs that "might make sense" (CTF keywords, English words, or flag-like patterns). The tool balances breadth (many transforms) and speed (cheap heuristics and configurable depth).

----------

## Features

-   ✅ Auto-attempts dozens of encodings and classical ciphers.
    
-   🔁 Multi-layer decoding (configurable depth: single, dual, triple, quad combinations).
    
-   🔎 Key-aware attempts: uses provided key in appropriate ciphers (Vigenère, Autokey, Beaufort, Porta, Gronsfeld, etc.).
    
-   🧠 English-scoring heuristic to prioritize likely plaintexts.
    
-   🔤 Leetspeak normalization for better keyword detection.
    
-   🧾 Generates a `report.txt` filtered into:
    
    -   **Might make sense** (CTF words / flag patterns)
        
    -   **All printable outputs** (filtered)
        
-   🧭 Interactive mode for manual experimentation.
    
-   ⚡ Designed for CTF speed — not exhaustive but effective for common cases.
    

----------

## Supported Ciphers & Encodings

> **Encodings / Compression**

-   Hex / Base16, Binary
    
-   Base32, Base45, Base58, Base64, Base85, Base91, Base92
    
-   URL encoding, HTML entities
    
-   zlib, gzip, bz2, lzma
    

> **Classical & Light Ciphers**

-   Caesar (bruteforce), ROT47, Atbash, Affine
    
-   XOR (single-byte + repeating key guessing)
    
-   Vigenère (guess & keyed), Autokey, Beaufort, Porta, Gronsfeld
    
-   Rail Fence (bruteforce rails 2–10)
    
-   Scytale (bruteforce widths 2–12)
    
-   Baconian, Morse
    
-   Playfair (basic bruteforce using common keys)
    
-   Bifid, ADFGX (light), Nihilist (light)
    
-   Four-Square, Trifid (light), Hill (light/placeholder)
    
-   Substitution heuristics (cheap swaps)
    

> **Notes:** The implementation contains lightweight versions of some complex ciphers (e.g., Hill, Trifid, ADFGX). These are intentionally cheap/fallback approximations to keep runtime reasonable. For very specialized cases use dedicated tools (e.g., dcode, CyberChef, quipqiup).

----------

## Install

```bash
# clone repo
git clone https://github.com/Shoaib-Bin-Rashid/CipherXploit.git
cd CipherXploit

# (optional) create virtualenv
python3 -m venv venv
source venv/bin/activate

# install recommended deps (colorama used for nice terminal colors)
pip install -r requirements.txt

```

`requirements.txt` minimal entries:

```
colorama

```

> The script uses only stdlib + optional `colorama` for colors. It will work without `colorama` (falls back to ANSI escapes).

----------

## Usage

### Quick (non-interactive)

```bash
python3 cipherxploit.py picoctf -c "U2FsdGVkX1+qK2hK..." 

```

### With a key

```bash
python3 cipherxploit.py RCSC -c "RJCAESDKCIMEEN" -k "12345"

```

### Interactive mode

```bash
python3 cipherxploit.py
# will prompt for flag format, ciphertext (or file path), and optional key

```

### Debug mode

Show operations as they are attempted (noisy).

```bash
python3 cipherxploit.py picoctf -c "..." -d

```

### Output

-   The console prints partial/exact flag matches and helpful partial context.
    
-   A filtered `report.txt` is written with sections **Might make sense** and **All printable outputs**.
    

----------

## Report Example

`report.txt` (example content)

```
============================================
               Might make sense
============================================

[railfence(rails=5)] RCSCEIDAJEKMNE -- [rcsc]
[gronsfeld(key='12345')] FLAG{EXAMPLE} -- [flag-pattern]

============================================
          All printable outputs
============================================

[atbash] IQXZVHWPXRNVVM
[base64] TUVzc2FnZQ==
...

```

----------

## Design Notes & Limitations

-   The tool is optimized for **speed and practical CTF usage**. Some implemented algorithms are lightweight approximations of complex ciphers (to avoid heavy math and long runtimes).
    
-   **Key usage:** When a key is provided, the tool will try to use it where applicable (Vigenère, Autokey, Beaufort, Porta, Gronsfeld, XOR single-byte if key is single byte). For broader coverage the script also constructs plausible derived keys (e.g., mapping digits → letters for Vigenère).
    
-   **Search depth:** Multi-layer combinations are configurable. Default runs phase 1 (single-layer) and phase 2 (two-layer); deeper probing is optional and may be slow.
    
-   **False positives:** Heuristics attempt to surface useful candidates but may still show noisy results. The `Might make sense` section is filtered with leetspeak-aware keyword matching to reduce noise.
    
-   **Missing exhaustive solvers:** For very involved ciphers (full Hill decryption, advanced ADFGX with full key schedule, or full substitution solver), dedicated tools are recommended.
    

----------

## Want to add more ciphers?

If you want the script to try additional ciphers or more exhaustive parameter searches, please open an Issue or a PR. I can help integrate the 10 most common useful additions (for example: full Playfair variants, full Hill 2x2/3x3 inverse solver, full substitution solver with simulated annealing, Porta variants, Affine/gamma variants, etc.) while preserving performance.

----------

## Contributing

Contributions, suggestions and PRs are welcome. If you add expensive routines, please ensure:

-   Reasonable default constraints (e.g., small candidate key lists, timeouts).
    
-   A toggle or optional flag so heavy computations are not run by default.
    
-   Unit tests or sample vectors to ensure correctness.
    

Typical workflow:

```bash
git clone https://github.com/Shoaib-Bin-Rashid/CipherXploit.git
git checkout -b feat/new-cipher
# implement
pytest
# make PR

```

----------

## Contact

**Developed by Shoaib Bin Rashid (R3D_XplOiT)**

-   **LinkedIn:** [Shoaib Bin Rashid](https://www.linkedin.com/in/shoaib-bin-rashid/)
    
-   **Email:** [shoaibbinrashid11@gmail.com](mailto:shoaibbinrashid11@gmail.com)
    
-   **GitHub:** [Shoaib Bin Rashid](https://github.com/Shoaib-Bin-Rashid)
    
-   **Twitter / X:** [@ShoaibBinRashi1](https://x.com/ShoaibBinRashi1)
    

----------

## License

MIT License © 2025 Shoaib Bin Rashid (R3D_XplOiT)

