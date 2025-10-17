#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cipherxploit.py — improved version with clean flag output and partial matches
Author: Shoaib Bin Rashid (R3D_XplOiT)
"""

import argparse
import base64
import binascii
import bz2
import html
import lzma
import math
import os
import re
import string
import sys
import urllib.parse
import zlib
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple, Dict

# ---------- Colors ----------
try:
    from colorama import init as _init_colorama, Fore, Style
    _init_colorama(autoreset=True)
    BOLD = Style.BRIGHT; RESET = Style.RESET_ALL
    CYAN, GREEN, YELLOW, BLUE = Fore.CYAN, Fore.GREEN, Fore.YELLOW, Fore.BLUE
except Exception:
    BOLD = "\033[1m"; RESET = "\033[0m"
    CYAN = "\033[36m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; BLUE = "\033[34m"

def cCYN(s): return f"{BOLD}{CYAN}{s}{RESET}"
def cGRN(s): return f"{BOLD}{GREEN}{s}{RESET}"
def cYEL(s): return f"{BOLD}{YELLOW}{s}{RESET}"
def cBLU(s): return f"{BLUE}{s}{RESET}"

def eprint(*a, **k): print(*a, file=sys.stderr, **k)

# ---------- Report (CLEAN FILTERED VERSION) ----------
REPORT_PATH = "report.txt"
_report_all: List[Tuple[str, str]] = []
_report_might: List[Tuple[str, str, str]] = []  # (operation, text, matched_word)

COMMON_WORDS = {
    "flag","ctf","capture","challenge","exploit","crypto","cipher","decode","decrypt","encode",
    "key","password","secret","hidden","plaintext","message","data","binary","hash","xor",
    "caesar","base64","hex","encoded","value","leet","pico","nactf","inctf","ractf","hackthebox",
    "tryhackme","root","user","login","system","success","found","access","result","correct",
    "admin","shell","proof","token","hint","win","unlock","vigenere","beaufort","rail","porta",
    "gronsfeld","solve","keygen","text","true","good","here","rcsc","flagged", "not","cocomelon",
    "easy","hard","medium","simple","complex","fun","funny","nice","great","well","done", "work",
    "box" , "like" ,"chinese" ,"have", "second","first", "third", "fourth", "fifth", "sixth","base"
}

_LEET_TABLE = str.maketrans({
    '4': 'a', '8': 'b', '3': 'e', '6': 'g', '1': 'i', '!': 'i', '|': 'i',
    '0': 'o', '9': 'g', '5': 's', '$': 's', '7': 't', '+': 't', '@': 'a',
})

def printable_only(s: str) -> str:
    """Keep only printable characters."""
    return "".join(ch for ch in s if 32 <= ord(ch) < 127)

def leet_normalize(s: str) -> str:
    """Convert leetspeak to normal for matching."""
    return s.lower().translate(_LEET_TABLE)

def _should_save_to_report(data: bytes, threshold: float = 0.4) -> bool:
    """Keep only reasonably printable results."""
    printable = sum(1 for c in data if 32 <= c < 127) / max(1, len(data))
    return printable >= threshold

def _find_match_word(oneline: str) -> Optional[str]:
    """
    Find a meaningful English/CTF keyword (leet-aware) or flag pattern.
    """
    norm = leet_normalize(oneline)
    for word in COMMON_WORDS:
        if word in norm:
            return word
    # Detect flag-like patterns
    if re.search(r"[A-Z0-9_]+{.*?}", oneline):
        return "flag-pattern"
    return None

def save_report_entry(operation: str, data: bytes):
    """Save printable results and mark meaningful ones."""
    if not data or not _should_save_to_report(data):
        return
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        text = data.decode("latin1", errors="ignore")
    printable = printable_only(text)
    if not printable:
        return
    _report_all.append((operation, printable))
    match = _find_match_word(printable)
    if match:
        _report_might.append((operation, printable, match))

def write_report_file(path: str = REPORT_PATH):
    """Write clean report with 'Might make sense' at the top."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            # 🔹 First section: meaningful results
            f.write("============================================\n")
            f.write("               Might make sense\n")
            f.write("============================================\n\n\n")
            for op, txt, match in _report_might:
                f.write(f"[{op}] {txt} -- [{match}]\n")

            # 🔹 Second section: all printable outputs
            f.write("\n\n\n============================================\n")
            f.write("          All printable outputs\n")
            f.write("============================================\n\n\n")
            for op, txt in _report_all:
                f.write(f"[{op}] {txt}\n")
    except Exception as e:
        print("Failed to write report:", e, file=sys.stderr)

# ---------- Auto-Detection Engine ----------
def detect_base64_pattern(data: bytes) -> float:
    """Detect Base64 encoding patterns. Returns confidence 0.0-1.0"""
    try:
        s = data.decode('utf-8', errors='ignore').strip()
    except Exception:
        return 0.0
    
    if not s:
        return 0.0
    
    # Base64 alphabet check
    base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    if not all(c in base64_chars for c in s):
        return 0.0
    
    # Length should be multiple of 4 (with padding)
    length_score = 0.8 if len(s) % 4 == 0 else 0.3
    
    # Padding check (0-2 '=' at end)
    padding_count = s.count('=')
    if padding_count > 2 or (padding_count > 0 and not s.endswith('=' * padding_count)):
        return 0.0
    
    # Character distribution (Base64 should have varied chars)
    unique_chars = len(set(s.replace('=', '')))
    diversity_score = min(unique_chars / 10.0, 1.0)
    
    return (length_score + diversity_score) / 2.0

def detect_hex_pattern(data: bytes) -> float:
    """Detect hexadecimal encoding. Returns confidence 0.0-1.0"""
    try:
        s = data.decode('utf-8', errors='ignore').strip()
    except Exception:
        return 0.0
    
    if len(s) < 2:
        return 0.0
    
    # Remove common hex prefixes
    s_clean = s.lower()
    if s_clean.startswith('0x'):
        s_clean = s_clean[2:]
    
    # Check if all characters are hex
    hex_chars = set('0123456789abcdef')
    if not all(c in hex_chars for c in s_clean):
        return 0.0
    
    # Even length is more likely for proper hex
    length_score = 0.9 if len(s_clean) % 2 == 0 else 0.6
    
    # Longer hex strings are more confident
    confidence = min(len(s_clean) / 20.0, 1.0) * length_score
    
    return confidence

def detect_binary_pattern(data: bytes) -> float:
    """Detect binary encoding. Returns confidence 0.0-1.0"""
    try:
        s = data.decode('utf-8', errors='ignore').strip()
    except Exception:
        return 0.0
    
    if len(s) < 8:
        return 0.0
    
    # Check if only 0s and 1s (allowing spaces)
    binary_chars = set('01 \t\n')
    if not all(c in binary_chars for c in s):
        return 0.0
    
    # Remove whitespace and check length
    clean_binary = ''.join(c for c in s if c in '01')
    if len(clean_binary) % 8 != 0:
        return 0.5  # Partial confidence
    
    return 0.8

def detect_caesar_pattern(data: bytes) -> float:
    """Detect potential Caesar cipher text. Returns confidence 0.0-1.0"""
    try:
        s = data.decode('utf-8', errors='ignore').upper()
    except Exception:
        return 0.0
    
    # Must be mostly letters
    letters = [c for c in s if 'A' <= c <= 'Z']
    if len(letters) < len(s) * 0.7:  # At least 70% letters
        return 0.0
    
    if len(letters) < 10:  # Too short for frequency analysis
        return 0.3
    
    # Check if frequency distribution is "off" (indicating cipher)
    from collections import Counter
    freq = Counter(letters)
    
    # In English, 'E' should be most common (~12.7%)
    # If 'E' is rare, might be Caesar cipher
    total = len(letters)
    e_freq = freq.get('E', 0) / total
    
    # Low E frequency suggests Caesar cipher
    if e_freq < 0.05:  # Much lower than expected 12.7%
        return 0.6
    elif e_freq < 0.08:
        return 0.4
    
    return 0.2

def detect_numbers_pattern(data: bytes) -> float:
    """Detect ASCII number sequences. Returns confidence 0.0-1.0"""
    try:
        s = data.decode('utf-8', errors='ignore')
    except Exception:
        return 0.0
    
    # Look for space/comma separated numbers
    import re
    numbers = re.findall(r'\b\d{1,3}\b', s)
    if len(numbers) < 3:
        return 0.0
    
    # Check if numbers are in ASCII range (32-126)
    ascii_count = sum(1 for n in numbers if 32 <= int(n) <= 126)
    if ascii_count >= len(numbers) * 0.8:  # 80% in ASCII range
        return 0.7
    
    return 0.3

def detect_morse_pattern(data: bytes) -> float:
    """Detect Morse code patterns. Returns confidence 0.0-1.0"""
    try:
        s = data.decode('utf-8', errors='ignore')
    except Exception:
        return 0.0
    
    # Morse uses dots, dashes, spaces
    morse_chars = set('.- /\t\n')
    if not all(c in morse_chars for c in s):
        return 0.0
    
    # Must have both dots and dashes
    if '.' in s and '-' in s:
        return 0.7
    
    return 0.0

def analyze_and_prioritize(data: bytes) -> List[Tuple[str, float]]:
    """Analyze data and return prioritized list of likely methods."""
    detections = []
    
    # Run all detection functions
    base64_conf = detect_base64_pattern(data)
    if base64_conf > 0.3:
        detections.append(("base64", base64_conf))
    
    hex_conf = detect_hex_pattern(data)
    if hex_conf > 0.3:
        detections.append(("hex", hex_conf))
    
    binary_conf = detect_binary_pattern(data)
    if binary_conf > 0.3:
        detections.append(("binary", binary_conf))
    
    caesar_conf = detect_caesar_pattern(data)
    if caesar_conf > 0.3:
        detections.append(("caesar", caesar_conf))
    
    numbers_conf = detect_numbers_pattern(data)
    if numbers_conf > 0.3:
        detections.append(("ascii_numbers", numbers_conf))
    
    morse_conf = detect_morse_pattern(data)
    if morse_conf > 0.3:
        detections.append(("morse", morse_conf))
    
    # Sort by confidence (highest first)
    return sorted(detections, key=lambda x: x[1], reverse=True)

# ---------- Helpers ----------
def is_file(p: str) -> bool:
    try:
        return os.path.isfile(p)
    except Exception:
        return False

def read_value_or_file(v: Optional[str]):
    if v is None: return None
    if is_file(v):
        with open(v, "rb") as f:
            return f.read()
    return v.encode()

# ---------- Key normalization ----------
def normalize_key_map(key_bytes: Optional[bytes]) -> Dict[str, Optional[bytes]]:
    """
    Return a dictionary with several normalized key forms:
      - raw: bytes (original)
      - text: decoded utf-8/latin1 bytes (full original text)
      - digits: bytes of digits-only portion (b'12345') or None
      - vigenere: letters-only uppercase bytes (b'KEY') if any letters exist
      - vigenere_from_digits: if only digits present, map 0->A,1->B,...,9->J to produce a letter key
    """
    out = {'raw': None, 'text': None, 'digits': None, 'vigenere': None, 'vigenere_from_digits': None}
    if not key_bytes:
        return out
    
    # First, decode the key bytes to text
    try:
        text = key_bytes.decode("utf-8", errors="ignore")
    except Exception:
        text = key_bytes.decode("latin1", errors="ignore")
    
    # Check if this is a hex value (e.g., "0x13" or just "13")
    text_stripped = text.strip()
    if text_stripped.startswith('0x') or text_stripped.startswith('0X'):
        # Parse as hex
        try:
            hex_value = int(text_stripped, 16)
            if 0 <= hex_value <= 255:  # Single byte hex value
                out['raw'] = bytes([hex_value])
            else:
                # Multi-byte hex value, convert to bytes
                hex_str = text_stripped[2:]  # Remove 0x prefix
                if len(hex_str) % 2:
                    hex_str = '0' + hex_str  # Pad with leading zero if odd length
                out['raw'] = bytes.fromhex(hex_str)
        except ValueError:
            # If hex parsing fails, treat as regular text
            out['raw'] = key_bytes
    elif text_stripped.isdigit() and len(text_stripped) <= 3:  # Likely a decimal byte value
        try:
            dec_value = int(text_stripped)
            if 0 <= dec_value <= 255:
                out['raw'] = bytes([dec_value])
            else:
                out['raw'] = key_bytes
        except ValueError:
            out['raw'] = key_bytes
    else:
        out['raw'] = key_bytes
    
    # Now process the text for other key forms
    if text:
        out['text'] = text.encode()
        letters = "".join(ch for ch in text if ch.isalpha())
        if letters:
            out['vigenere'] = letters.upper().encode()
        digits = "".join(ch for ch in text if ch.isdigit())
        if digits:
            out['digits'] = digits.encode()
            mapping = {str(i): chr(ord('A') + i) for i in range(10)}
            mapped = "".join(mapping[d] for d in digits)
            out['vigenere_from_digits'] = mapped.encode()
    return out

# ---------- Data classes ----------
@dataclass
class Hit:
    match: str
    span: Tuple[int, int]
    case: str  # "exact" | "partial" | "extra"

@dataclass
class Result:
    data: bytes
    method: str
    score: float = 0.0
    notes: str = ""

@dataclass
class Candidate:
    data: bytes
    chain: Tuple[str, ...]
    depth: int
    score: float = 0.0

# ---------- Scoring & helpers ----------
EN_FREQ = {
    'a':0.08167,'b':0.01492,'c':0.02782,'d':0.04253,'e':0.12702,
    'f':0.02228,'g':0.02015,'h':0.06094,'i':0.06966,'j':0.00153,
    'k':0.00772,'l':0.04025,'m':0.02406,'n':0.06749,'o':0.07507,
    'p':0.01929,'q':0.00095,'r':0.05987,'s':0.06327,'t':0.09056,
    'u':0.02758,'v':0.00978,'w':0.02360,'x':0.0015,'y':0.01974,'z':0.00074,
}

def printable_ratio(b: bytes)->float:
    if not b: return 0.0
    return sum(1 for x in b if 32<=x<127 or x in (9,10,13))/len(b)

def entropy(b: bytes)->float:
    if not b: return 0.0
    freq=[0]*256
    for x in b: freq[x]+=1
    n=len(b); ent=0.0
    for c in freq:
        if c:
            p=c/n
            ent-=p*math.log2(p)
    return ent

def english_score(b: bytes)->float:
    if not b: return -1e9
    pr=printable_ratio(b)
    if pr<0.2: return -1e6+pr
    text=b.decode('utf-8',errors='ignore').lower()
    if not text: return -1e6+pr
    letters=[ch for ch in text if 'a'<=ch<='z']
    if not letters: return -1e3*(1-pr)
    counts={c:0 for c in EN_FREQ}
    for ch in letters: counts[ch]+=1
    n=len(letters); chi=0.0
    for c,exp in EN_FREQ.items():
        obs=counts[c]; E=exp*n
        chi += (obs-E)**2/(E+1e-9)
    ent=entropy(b)
    return -chi + pr*5.0 - abs(ent-4.5)

# ---------- Flag detection & display ----------
def build_main_regex(flag_format: str) -> re.Pattern:
    pat = rf"{re.escape(flag_format)}\{{.*?\}}"
    return re.compile(pat)

def compile_extra_regex(rx: Optional[str]) -> Optional[re.Pattern]:
    if not rx: return None
    try: return re.compile(rx, re.IGNORECASE)
    except re.error: return None

def find_flags(blob: bytes, main_re: re.Pattern, extra_re: Optional[re.Pattern], flag_format: str) -> List[Hit]:
    hits: List[Hit] = []
    txt = blob.decode('utf-8', errors='ignore')
    # 1) exact
    for m in main_re.finditer(txt):
        hits.append(Hit(m.group(), (m.start(), m.end()), "exact"))
    if hits:
        return hits
    # 2) case-insensitive full token
    try:
        mci = re.compile(main_re.pattern, re.IGNORECASE)
        for m in mci.finditer(txt):
            hits.append(Hit(m.group(), (m.start(), m.end()), "partial"))
        if hits:
            return hits
    except re.error:
        pass
    # 3) loose prefix search
    loose = re.compile(re.escape(flag_format), re.IGNORECASE)
    m = loose.search(txt)
    if m:
        start_search = max(0, m.start()-32)
        end_search = min(len(txt), m.end()+256)
        window = txt[start_search:end_search]
        tok_match = re.search(r"[A-Za-z0-9_]+\{.*?\}", window)
        if tok_match:
            full = tok_match.group()
            abs_start = start_search + tok_match.start()
            abs_end = start_search + tok_match.end()
            hits.append(Hit(full, (abs_start, abs_end), "partial"))
        else:
            # Enhanced flag reconstruction for cipher outputs
            # Look for pattern: flag_format + content (possibly with padding)
            flag_upper = flag_format.upper()
            if txt.upper().startswith(flag_upper):
                remaining = txt[len(flag_format):]
                # Remove common cipher padding (X, Z, etc.) from end
                content = remaining.rstrip('XZ')
                if content:
                    # Reconstruct flag with braces
                    reconstructed = f"{flag_format.lower()}{{{content.lower()}}}"
                    hits.append(Hit(reconstructed, (0, len(txt)), "partial"))
                    return hits
            hits.append(Hit(m.group(), (m.start(), m.end()), "partial"))
        return hits
    # 4) extra regex
    if extra_re:
        for m in extra_re.finditer(txt):
            hits.append(Hit(m.group(), (m.start(), m.end()), "extra"))
    return hits

def print_partial(chain: Sequence[str], hit: Hit, blob: Optional[bytes] = None):
    line = ""
    if blob:
        txt = blob.decode('utf-8', errors='ignore')
        start = txt.rfind("\n", 0, hit.span[0])
        end = txt.find("\n", hit.span[1])
        if start == -1: start = 0
        else: start += 1
        if end == -1: end = len(txt)
        line = txt[start:end].strip()
        if not line:
            ws = max(0, hit.span[0]-80)
            we = min(len(txt), hit.span[1]+80)
            line = txt[ws:we].strip()
    print("---------------------------------------------")
    print(f"Partial match :  [{ ' -> '.join(chain) }]  {cYEL(hit.match)}")
    if line:
        print(cBLU(line))
    print("---------------------------------------------")

def print_flag(chain: Sequence[str], hit: Hit):
    print("\n==============")
    print(f"Flag Found : {cGRN(hit.match)}")
    print(f"Operation :  [{ ' -> '.join(chain) }]")
    print("==============\n")




# ---------- ASCII-decimal / octal decoders & ascii-shift bruteforce ----------

def dec_ascii_numbers(b: bytes) -> List[Result]:
    """
    Decode decimal ASCII code sequences to bytes.
    Accept many separators: spaces, commas, dashes, slashes, or contiguous digits.
    Returns [] if no plausible tokens found.
    Examples handled:
      "65 66 67" -> ABC
      "65,66,67" -> ABC
      "65-66-67" -> ABC
      "656667" -> ABC  (even-length contiguous fallback)
    """
    try:
        s = b.decode('utf-8', errors='ignore').strip()
    except Exception:
        s = b.decode('latin1', errors='ignore').strip()

    # find tokens: 0xhh, decimal 1..3 digits
    tokens = re.findall(r'0x[0-9A-Fa-f]{1,2}|\b\d{1,3}\b', s)
    if not tokens:
        # Fallback: contiguous digits that form even-length string (e.g., "656667")
        compact = "".join(ch for ch in s if ch.isdigit())
        if len(compact) >= 4 and len(compact) % 2 == 0:
            tokens = [compact[i:i+2] for i in range(0, len(compact), 2)]
        else:
            return []

    out = bytearray()
    ok = False
    for tok in tokens:
        if tok.lower().startswith("0x"):
            try:
                val = int(tok, 16)
            except Exception:
                continue
        else:
            try:
                val = int(tok, 10)
            except Exception:
                continue
        if 0 <= val <= 255:
            out.append(val)
            ok = True
    if not ok:
        return []
    return [Result(bytes(out), "ascii(dec)")]


def dec_octal_numbers(b: bytes) -> List[Result]:
    """
    Decode octal ASCII code sequences such as '101 102 103' or '\101\102'.
    Returns [] if nothing plausible.
    """
    try:
        s = b.decode('utf-8', errors='ignore')
    except Exception:
        s = b.decode('latin1', errors='ignore')

    # tokens of backslash + 1-3 octal digits, or standalone octal tokens
    tokens = re.findall(r'\\[0-7]{1,3}|\b[0-7]{2,3}\b', s)
    if not tokens:
        return []
    out = bytearray()
    ok = False
    for tok in tokens:
        tok_clean = tok.lstrip("\\")
        try:
            val = int(tok_clean, 8)
        except Exception:
            continue
        if 0 <= val <= 255:
            out.append(val)
            ok = True
    if not ok:
        return []
    return [Result(bytes(out), "ascii(oct)")]


def ascii_shift_bruteforce(b: bytes, topn:int = 6, span:int = 32) -> List[Result]:
    """
    Try additive shifts on raw bytes: for k in -span..+span (excluding 0),
    produce candidate by (byte + k) & 0xFF and score with english_score.
    Returns topn candidates.
    Default span 32 is cheap (63 candidates).
    """
    outs=[]
    if not b:
        return outs
    for k in range(-span, span+1):
        if k == 0:
            continue
        try:
            cand = bytes(((byte + k) & 0xFF) for byte in b)
            outs.append(Result(cand, f"ascii_shift({k:+d})", english_score(cand)))
        except Exception:
            pass
    outs.sort(key=lambda r: r.score, reverse=True)
    return outs[:topn]


# ---------- Base/encoding decoders ----------

def dec_hex(b: bytes)->List[Result]:
    s = re.sub(rb'[^0-9a-fA-F]', b'', b)
    if len(s) < 2: return []
    if len(s) % 2: s = b'0' + s
    try:
        out = binascii.unhexlify(s)
        return [Result(out, "hex")]
    except Exception:
        return []

def dec_binary(b: bytes)->List[Result]:
    s = re.sub(rb'[^01]', b'', b)
    if len(s) < 8 or len(s) % 8: return []
    try:
        out = bytes(int(s[i:i+8],2) for i in range(0,len(s),8))
        return [Result(out, "binary")]
    except Exception:
        return []

def dec_base64(b: bytes)->List[Result]:
    outs=[]
    s=b.strip()
    for p in (0,1,2,3):
        try:
            cand=base64.b64decode(s+b'='*p, validate=False)
            if cand: outs.append(Result(cand,"base64"))
        except Exception: pass
    try:
        cand=base64.urlsafe_b64decode(s+b'==')
        if cand: outs.append(Result(cand,"base64(urlsafe)"))
    except Exception: pass
    return outs

def dec_base32(b: bytes)->List[Result]:
    outs=[]
    for casefold in (True,False):
        for p in (0,1,4,6):
            try:
                cand=base64.b32decode(b.strip()+b'='*p, casefold=casefold)
                if cand: outs.append(Result(cand,"base32"))
            except Exception: pass
    return outs

B58_ALPH=b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
B58_INDEX={c:i for i,c in enumerate(B58_ALPH)}
def dec_base58(b: bytes)->List[Result]:
    s=bytes(ch for ch in b.strip() if ch in B58_ALPH)
    if not s: return []
    try:
        n=0
        for c in s: n = n*58 + B58_INDEX[c]
        h=f"{n:x}"; h=("0"+h) if len(h)%2 else h
        out=bytes.fromhex(h)
        pad=len(s)-len(s.lstrip(B58_ALPH[:1]))
        out=b"\x00"*pad + out
        if out: return [Result(out,"base58")]
    except Exception: pass
    return []

def dec_base85(b: bytes)->List[Result]:
    outs=[]
    for fn,name in ((base64.b85decode,"base85"), (base64.a85decode,"ascii85")):
        try:
            cand=fn(b.strip())
            if cand: outs.append(Result(cand,name))
        except Exception:
            pass
    return outs

def dec_base36(b: bytes) -> List[Result]:
    """Decode base36 (0-9, a-z) to bytes."""
    try:
        s = b.decode('utf-8', errors='ignore').strip()
    except Exception:
        s = b.decode('latin1', errors='ignore').strip()
    
    # Remove non-base36 chars
    clean = ''.join(ch for ch in s.lower() if ch in '0123456789abcdefghijklmnopqrstuvwxyz')
    if len(clean) < 2:
        return []
    
    try:
        # Convert base36 to integer, then to hex, then to bytes
        num = int(clean, 36)
        hex_str = hex(num)[2:]  # remove '0x'
        if len(hex_str) % 2:
            hex_str = '0' + hex_str
        out = bytes.fromhex(hex_str)
        return [Result(out, "base36")]
    except Exception:
        return []

def dec_base62(b: bytes) -> List[Result]:
    """Decode base62 (0-9, a-z, A-Z) to bytes."""
    try:
        s = b.decode('utf-8', errors='ignore').strip()
    except Exception:
        s = b.decode('latin1', errors='ignore').strip()
    
    base62_chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    clean = ''.join(ch for ch in s if ch in base62_chars)
    if len(clean) < 2:
        return []
    
    try:
        # Manual base62 decode
        num = 0
        for ch in clean:
            if '0' <= ch <= '9':
                num = num * 62 + (ord(ch) - ord('0'))
            elif 'a' <= ch <= 'z':
                num = num * 62 + (ord(ch) - ord('a') + 10)
            elif 'A' <= ch <= 'Z':
                num = num * 62 + (ord(ch) - ord('A') + 36)
        
        hex_str = hex(num)[2:]
        if len(hex_str) % 2:
            hex_str = '0' + hex_str
        out = bytes.fromhex(hex_str)
        return [Result(out, "base62")]
    except Exception:
        return []

def rot5_numbers(b: bytes) -> List[Result]:
    """ROT5 for numbers (0-9 rotated by 5)."""
    try:
        s = b.decode('utf-8', errors='ignore')
    except Exception:
        s = b.decode('latin1', errors='ignore')
    
    # ROT5 (numbers only)
    rot5 = ''.join(
        str((int(ch) + 5) % 10) if ch.isdigit() else ch
        for ch in s
    )
    if rot5 != s:  # only if different from original
        return [Result(rot5.encode(), "rot5")]
    return []

def dec_base92(b: bytes) -> List[Result]:
    base92_mapping = {
        0: '!', 1: '#', 2: '$', 3: '%', 4: '&', 5: "'", 6: '(', 7: ')', 8: '*', 9: '+',
        10: ',', 11: '-', 12: '.', 13: '/', 14: '0', 15: '1', 16: '2', 17: '3', 18: '4', 19: '5',
        20: '6', 21: '7', 22: '8', 23: '9', 24: ':', 25: ';', 26: '<', 27: '=', 28: '>', 29: '?',
        30: '@', 31: 'A', 32: 'B', 33: 'C', 34: 'D', 35: 'E', 36: 'F', 37: 'G', 38: 'H', 39: 'I',
        40: 'J', 41: 'K', 42: 'L', 43: 'M', 44: 'N', 45: 'O', 46: 'P', 47: 'Q', 48: 'R', 49: 'S',
        50: 'T', 51: 'U', 52: 'V', 53: 'W', 54: 'X', 55: 'Y', 56: 'Z', 57: '[', 58: '\\', 59: ']',
        60: '^', 61: '_', 62: 'a', 63: 'b', 64: 'c', 65: 'd', 66: 'e', 67: 'f', 68: 'g', 69: 'h',
        70: 'i', 71: 'j', 72: 'k', 73: 'l', 74: 'm', 75: 'n', 76: 'o', 77: 'p', 78: 'q', 79: 'r',
        80: 's', 81: 't', 82: 'u', 83: 'v', 84: 'w', 85: 'x', 86: 'y', 87: 'z', 88: '{', 89: '|', 90: '}',
    }
    # build reverse map
    symbol_to_index = {v: k for k, v in base92_mapping.items()}

    try:
        s = b.decode('utf-8', errors='ignore')
    except Exception:
        s = b.decode('latin1', errors='ignore')

    # filter only allowed symbols (keep order)
    filtered = "".join(ch for ch in s if ch in symbol_to_index)
    if not filtered:
        return []

    # if odd length, pad with the first symbol '!' (index 0) — same behaviour as your snippet
    if len(filtered) % 2 != 0:
        filtered += '!'

    bit_buffer = 0
    bit_count = 0
    out = bytearray()

    # process pairs -> 0..(91*91-1) -> 13 bits per pair
    for i in range(0, len(filtered), 2):
        ch1 = filtered[i]; ch2 = filtered[i+1]
        idx1 = symbol_to_index.get(ch1)
        idx2 = symbol_to_index.get(ch2)
        if idx1 is None or idx2 is None:
            # skip invalid pair (shouldn't happen after filtering)
            continue
        num = idx1 * 91 + idx2  # in 0..(91*91-1)
        # append 13 bits
        bit_buffer = (bit_buffer << 13) | (num & 0x1FFF)
        bit_count += 13
        # extract bytes while possible (from left-most bits)
        while bit_count >= 8:
            shift = bit_count - 8
            byte = (bit_buffer >> shift) & 0xFF
            out.append(byte)
            bit_count -= 8
            # mask off the top-extracted byte
            bit_buffer &= (1 << shift) - 1 if shift > 0 else 0

    # Return result like other decoders: list of Result
    if out:
        return [Result(bytes(out), "base92")]
    return []

B45_ALPH=b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
B45_INDEX={c:i for i,c in enumerate(B45_ALPH)}
def dec_base45(b: bytes)->List[Result]:
    s=bytes(ch for ch in b.strip() if ch in B45_ALPH)
    if not s: return []
    out=bytearray(); i=0
    try:
        while i<len(s):
            if i+2<len(s):
                x = B45_INDEX[s[i]] + B45_INDEX[s[i+1]]*45 + B45_INDEX[s[i+2]]*45*45
                out.append(x//256); out.append(x%256); i+=3
            elif i+1<len(s):
                x = B45_INDEX[s[i]] + B45_INDEX[s[i+1]]*45
                out.append(x); i+=2
            else: break
        return [Result(bytes(out),"base45")]
    except Exception: return []

B91_ALPH=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
B91_DEC={c:i for i,c in enumerate(B91_ALPH)}
def dec_base91(b: bytes)->List[Result]:
    s=bytes(ch for ch in b if ch in B91_DEC)
    if not s: return []
    v=-1; bval=0; nbits=0; out=bytearray()
    try:
        for ch in s:
            c=B91_DEC[ch]
            if v<0: v=c
            else:
                v+=c*91
                bval |= v<<nbits
                nbits += 13 if (v & 8191)>88 else 14
                while nbits>7:
                    out.append(bval & 255); bval >>= 8; nbits-=8
                v=-1
        if v>=0: out.append((bval | (v<<nbits)) & 255)
        if out: return [Result(bytes(out),"base91")]
    except Exception: pass
    return []

def dec_url(b: bytes)->List[Result]:
    try:
        return [Result(urllib.parse.unquote_to_bytes(b.decode('utf-8',errors='ignore')), "url")]
    except Exception: return []

def dec_html(b: bytes)->List[Result]:
    try:
        s=html.unescape(b.decode('utf-8',errors='ignore'))
        return [Result(s.encode(),"html")]
    except Exception: return []

def dec_zlib(b: bytes)->List[Result]:
    try: return [Result(zlib.decompress(b),"zlib")]
    except Exception: return []

def dec_gzip(b: bytes)->List[Result]:
    try:
        import gzip
        return [Result(gzip.decompress(b),"gzip")]
    except Exception: return []

def dec_bz2(b: bytes)->List[Result]:
    try: return [Result(bz2.decompress(b),"bz2")]
    except Exception: return []

def dec_lzma(b: bytes)->List[Result]:
    try: return [Result(lzma.decompress(b),"lzma")]
    except Exception: return []

# ---------- Tiny transforms ----------
def do_reverse(b: bytes) -> List[Result]:
    return [Result(b[::-1], "reverse")]


# ---------- Classical & simple ciphers ----------
def caesar_shift(b: bytes, k:int)->bytes:
    out=bytearray()
    for ch in b:
        if 65<=ch<=90: out.append(((ch-65+k)%26)+65)
        elif 97<=ch<=122: out.append(((ch-97+k)%26)+97)
        else: out.append(ch)
    return bytes(out)

def caesar_bruteforce(b: bytes, topn:int=6)->List[Result]:
    c=[]
    for k in range(26):
        pt=caesar_shift(b,k)
        c.append(Result(pt, f"caesar(+{k})", english_score(pt)))
    c.sort(key=lambda r:r.score, reverse=True)
    return c[:topn]

def rot47(b: bytes)->List[Result]:
    out=bytearray()
    for ch in b:
        if 33<=ch<=126:
            out.append(33 + ((ch-33+47)%94))
        else:
            out.append(ch)
    return [Result(bytes(out), "rot47")]

def atbash(b: bytes)->List[Result]:
    out=bytearray()
    for ch in b:
        if 65<=ch<=90: out.append(90-(ch-65))
        elif 97<=ch<=122: out.append(122-(ch-97))
        else: out.append(ch)
    return [Result(bytes(out),"atbash")]

_VALID_A = [1,3,5,7,9,11,15,17,19,21,23,25]
def _inv_mod(a:int,m:int)->Optional[int]:
    a=a%m
    for x in range(1,m):
        if (a*x)%m==1: return x
    return None

def affine_bruteforce(b: bytes, topn:int=12)->List[Result]:
    outs=[]
    for a in _VALID_A:
        inv=_inv_mod(a,26)
        if inv is None: continue
        for beta in range(26):
            out=bytearray()
            for ch in b:
                if 65<=ch<=90: out.append(((inv*((ch-65)-beta))%26)+65)
                elif 97<=ch<=122: out.append(((inv*((ch-97)-beta))%26)+97)
                else: out.append(ch)
            out=bytes(out)
            outs.append(Result(out, f"affine(a={a},b={beta})", english_score(out)))
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

def xor_bytes(data: bytes, key: bytes)->bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def xor_single_byte_bruteforce(b: bytes, key_hint: Optional[bytes]=None, topn:int=6)->List[Result]:
    outs=[]
    
    if key_hint and len(key_hint)==1:
        # Direct XOR with the provided key
        pt=xor_bytes(b,key_hint)
        outs.append(Result(pt,f"xor(0x{key_hint[0]:02x})",english_score(pt)))
        
        # Also try hex-decode then XOR if input looks like hex
        try:
            # Check if input might be hex (even length, only hex chars)
            input_str = b.decode('utf-8', errors='ignore')
            if (len(input_str) >= 4 and len(input_str) % 2 == 0 and 
                all(c in '0123456789abcdefABCDEF' for c in input_str)):
                import binascii
                hex_decoded = binascii.unhexlify(input_str)
                pt_hex = xor_bytes(hex_decoded, key_hint)
                outs.append(Result(pt_hex, f"hex->xor(0x{key_hint[0]:02x})", english_score(pt_hex)))
        except Exception:
            pass
        
        # Return results sorted by score
        outs.sort(key=lambda r:r.score, reverse=True)
        return outs
    
    # Bruteforce mode when no specific key is provided
    for k in range(256):
        key=bytes([k]); pt=xor_bytes(b,key)
        outs.append(Result(pt, f"xor(0x{k:02x})", english_score(pt)))
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

def xor_with_user_key(b: bytes, key: bytes) -> List[Result]:
    if not key or len(key) <= 1:
        return []
    pt = xor_bytes(b, key)
    label = f"xor-repeat(key={key.hex()[:16]}{'...' if len(key.hex())>16 else ''})"
    return [Result(pt, label, english_score(pt))]

def xor_repeating_key_guess(b: bytes, max_len:int=6, topn:int=4)->List[Result]:
    outs=[]
    for L in range(2, max_len+1):
        key=bytearray()
        for pos in range(L):
            block=b[pos::L]
            bestk=0; bests=-1e9
            for k in range(256):
                s=english_score(bytes(x^k for x in block))
                if s>bests: bests=s; bestk=k
            key.append(bestk)
        keyb=bytes(key); pt=xor_bytes(b,keyb)
        outs.append(Result(pt, f"xor-repeat(len={L},key={keyb.hex()})", english_score(pt)))
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

def _shift_letter_dec(ch:int,k:int)->int:
    if 65<=ch<=90: return ((ch-65 - k)%26)+65
    if 97<=ch<=122: return ((ch-97 - k)%26)+97
    return ch

def vigenere_decrypt(b: bytes, key: bytes)->bytes:
    if not key: return b
    keyshifts=[(c-65 if 65<=c<=90 else c-97)%26 for c in key if (65<=c<=90 or 97<=c<=122)]
    if not keyshifts: return b
    out=bytearray(); j=0
    for ch in b:
        if 65<=ch<=90 or 97<=ch<=122:
            k=keyshifts[j%len(keyshifts)]; out.append(_shift_letter_dec(ch,k)); j+=1
        else: out.append(ch)
    return bytes(out)

def guess_key_length_ic(b: bytes, max_len:int=12)->List[int]:
    letters=bytes(ch for ch in b if (65<=ch<=90) or (97<=ch<=122))
    if not letters: return [1,2,3]
    def IC(seq:bytes)->float:
        from collections import Counter
        N=len(seq);
        if N<=1: return 0.0
        cnt=Counter(seq)
        return sum(c*(c-1) for c in cnt.values())/(N*(N-1))
    scores=[]
    for L in range(1,max_len+1):
        parts=[letters[i::L] for i in range(L)]
        avg=sum(IC(p) for p in parts)/max(1,L)
        scores.append((avg,L))
    scores.sort(reverse=True)
    return [L for _,L in scores[:5]]

def vigenere_quick(b: bytes, key_hint: Optional[bytes]=None, topn:int=4)->List[Result]:
    outs=[]
    if key_hint:
        key = key_hint.decode('utf-8',errors='ignore')
        kbytes = key.encode().upper()
        pt=vigenere_decrypt(b,kbytes)
        outs.append(Result(pt,f"vigenere(key='{key}')", english_score(pt)))
        return outs[:topn]
    for L in guess_key_length_ic(b):
        key=[]
        for pos in range(L):
            block=bytes(ch for i,ch in enumerate(b) if i%L==pos and (65<=ch<=90 or 97<=ch<=122))
            bestk=0; bests=-1e9
            for k in range(26):
                dec=bytes(_shift_letter_dec(ch,k) for ch in block)
                s=english_score(dec)
                if s>bests: bests=s; bestk=k
            key.append(bestk)
        keytxt="".join(chr(65+k) for k in key)
        pt=vigenere_decrypt(b, keytxt.encode())
        outs.append(Result(pt, f"vigenere(len={L}, key~='{keytxt}')", english_score(pt)))
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

def autokey_decrypt(b:bytes, key_text:str)->bytes:
    key_stream=[(ord(c.upper())-65)%26 for c in key_text if c.isalpha()]
    out=bytearray(); j=0
    for ch in b:
        if 65<=ch<=90 or 97<=ch<=122:
            k = key_stream[j % len(key_stream)] if key_stream else 0
            out.append(_shift_letter_dec(ch, k)); j+=1
        else: out.append(ch)
    return bytes(out)

def beaufort_decrypt(b:bytes, key:str)->bytes:
    ks = [(ord(c.upper())-65)%26 for c in key if c.isalpha()]
    if not ks:
        return b
    out=bytearray(); j=0
    for ch in b:
        if 65<=ch<=90:
            out.append(((ks[j%len(ks)] - (ch-65))%26)+65); j+=1
        elif 97<=ch<=122:
            out.append(((ks[j%len(ks)] - (ch-97))%26)+97); j+=1
        else:
            out.append(ch)
    return bytes(out)

def porta_decrypt(b:bytes, key:str)->bytes:
    def porta_shift(c,k):
        kpair=(ord(k.upper())-65)//2
        alpha="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        left="NOPQRSTUVWXYZABCDEFGHIJKLM"
        right="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if 'A'<=c<='Z':
            i=alpha.index(c)
            return right[(i+kpair)%26] if i<13 else left[(i+kpair)%26]
        if 'a'<=c<='z':
            i=alpha.lower().index(c)
            return right.lower()[(i+kpair)%26] if i<13 else left.lower()[(i+kpair)%26]
        return c
    ks=[k for k in key if k.isalpha()]
    out=[]
    j=0
    for ch in b.decode('utf-8',errors='ignore'):
        if ch.isalpha():
            out.append(porta_shift(ch, ks[j%len(ks)] if ks else 'A')); j+=1
        else:
            out.append(ch)
    return "".join(out).encode()

def gronsfeld_decrypt(b:bytes, key_digits:str)->bytes:
    digs=[int(c) for c in key_digits if c.isdigit()]
    if not digs: return b
    out=bytearray(); j=0
    for ch in b:
        if 65<=ch<=90: out.append(((ch-65 - digs[j%len(digs)])%26)+65); j+=1
        elif 97<=ch<=122: out.append(((ch-97 - digs[j%len(digs)])%26)+97); j+=1
        else: out.append(ch)
    return bytes(out)

def rail_fence_decrypt(ct: str, rails:int)->str:
    if rails <= 1 or rails >= len(ct):
        return ct
    
    # Create the rail pattern to know where characters go
    fence = [[None for _ in range(len(ct))] for _ in range(rails)]
    
    # Mark the positions in the zigzag pattern
    rail = 0
    direction = 1
    for i in range(len(ct)):
        fence[rail][i] = True
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction = -direction
    
    # Fill the marked positions with ciphertext characters
    index = 0
    for r in range(rails):
        for c in range(len(ct)):
            if fence[r][c] is True:
                fence[r][c] = ct[index]
                index += 1
    
    # Read off the characters in zigzag order
    result = []
    rail = 0
    direction = 1
    for i in range(len(ct)):
        result.append(fence[rail][i])
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction = -direction
    
    return "".join(result)

def rail_fence_bruteforce(b: bytes, min_r:int=2, max_r:int=10, topn:int=5)->List[Result]:
    txt=b.decode('utf-8',errors='ignore')
    outs=[]
    for r in range(min_r, min(max_r+1, max(3, len(txt)) )):
        try:
            pt=rail_fence_decrypt(txt,r).encode()
            outs.append(Result(pt, f"railfence(rails={r})", english_score(pt)))
        except Exception: pass
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

def scytale_decrypt(b:bytes, width:int)->bytes:
    txt=b.decode('utf-8',errors='ignore')
    if width<=0: return b
    
    # For scytale cipher: reverse the encryption process
    # Encryption fills grid row-wise and reads column-wise
    # So decryption should fill column-wise and read row-wise
    
    length = len(txt)
    rows = math.ceil(length / width)
    
    # Calculate how many columns will have an extra character
    extra_chars = length % width
    
    # Create the grid
    grid = []
    for r in range(rows):
        grid.append([''] * width)
    
    # Fill the grid column by column
    idx = 0
    for col in range(width):
        # Some columns may have one less character if length % width != 0
        col_height = rows if col < extra_chars else rows - 1 if extra_chars > 0 and rows > 1 else rows
        
        for row in range(col_height):
            if idx < length:
                grid[row][col] = txt[idx]
                idx += 1
    
    # Read row by row to get the plaintext
    result = ''
    for row in range(rows):
        for col in range(width):
            if grid[row][col]:
                result += grid[row][col]
    
    return result.encode()

def scytale_bruteforce(b: bytes, min_w:int=2, max_w:int=12, topn:int=4)->List[Result]:
    outs=[]
    for w in range(min_w, max_w+1):
        try:
            pt=scytale_decrypt(b,w)
            outs.append(Result(pt, f"scytale(width={w})", english_score(pt)))
        except Exception:
            pass
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

def polybius_decrypt(b:bytes, merge_ij:bool=True)->bytes:
    s=re.sub(r'[^1-5]', '', b.decode('utf-8',errors='ignore'))
    if len(s)%2: s=s[:-1]
    alpha="ABCDEFGHIKLMNOPQRSTUVWXYZ" if merge_ij else "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    table=[alpha[i:i+5] for i in range(0,25,5)]
    out=[]
    for i in range(0,len(s),2):
        r=int(s[i])-1; c=int(s[i+1])-1
        if 0<=r<5 and 0<=c<5:
            out.append(table[r][c])
    return "".join(out).encode()

_BACON = { 'AAAAA':'A','AAAAB':'B','AAABA':'C','AAABB':'D','AABAA':'E','AABAB':'F','AABBA':'G','AABBB':'H',
    'ABAAA':'I','ABAAB':'J','ABABA':'K','ABABB':'L','ABBAA':'M','ABBAB':'N','ABBBA':'O','ABBBB':'P',
    'BAAAA':'Q','BAAAB':'R','BAABA':'S','BAABB':'T','BABAA':'U','BABAB':'V','BABBA':'W','BABBB':'X',
    'BBAAA':'Y','BBAAB':'Z' }

def baconian_decrypt(b:bytes)->bytes:
    s=b.decode('utf-8',errors='ignore').upper()
    s=s.replace('0','A').replace('1','B')
    s="".join(ch for ch in s if ch in "AB")
    out=[]
    for i in range(0,len(s)-4,5):
        chunk=s[i:i+5]
        out.append(_BACON.get(chunk,'?'))
    return "".join(out).encode()

_MORSE_TABLE = {
    '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I',
    '.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--':'P','--.-':'Q','.-.':'R',
    '...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
    '-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9'
}
def morse_decrypt(b:bytes)->bytes:
    s=b.decode('utf-8',errors='ignore').strip()
    words = re.split(r'\s{3,}|/', s)
    out_words=[]
    for w in words:
        letters=w.strip().split()
        out_letters=[_MORSE_TABLE.get(L,'?') for L in letters]
        out_words.append("".join(out_letters))
    return " ".join(out_words).encode()

# ---------- Additional lightweight ciphers & bruteforce wrappers ----------

def _normalize_alpha(text: str) -> str:
    return "".join(ch.upper() for ch in text if ch.isalpha())

# -------- Playfair --------
def playfair_build_table(key: str, merge_j: bool = True) -> List[List[str]]:
    key = _normalize_alpha(key)
    seen = []
    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ" if merge_j else "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for ch in key:
        if ch not in seen and ch in alpha:
            seen.append(ch)
    for ch in alpha:
        if ch not in seen:
            seen.append(ch)
    table = [seen[i:i+5] for i in range(0,25,5)]
    return table

def playfair_decrypt(ct: str, key: str, merge_j: bool = True) -> bytes:
    table = playfair_build_table(key, merge_j)
    pos = {}
    for r in range(5):
        for c in range(5):
            pos[table[r][c]] = (r,c)
    s = "".join(ch.upper() for ch in ct if ch.isalpha())
    out=[]
    i=0
    while i < len(s)-1:
        a,b = s[i], s[i+1]
        ra,ca = pos.get(a, (None,None))
        rb,cb = pos.get(b, (None,None))
        if ra is None or rb is None:
            out.append(a); i+=1; continue
        if ra==rb:
            out.append(table[ra][(ca-1)%5]); out.append(table[rb][(cb-1)%5])
        elif ca==cb:
            out.append(table[(ra-1)%5][ca]); out.append(table[(rb-1)%5][cb])
        else:
            out.append(table[ra][cb]); out.append(table[rb][ca])
        i+=2
    if i < len(s):
        out.append(s[i])
    return "".join(out).encode()

def playfair_bruteforce(b: bytes, key_hint: Optional[str]=None, topn:int=4) -> List[Result]:
    txt = b.decode('utf-8', errors='ignore')
    common_keys = []
    if key_hint:
        common_keys.append(key_hint)
    common_keys.extend(["KEY","FLAG","SECRET","PASSWORD","CTF","CRYPTO"])
    outs=[]
    for key in common_keys:
        for merge in (True, False):
            try:
                pt = playfair_decrypt(txt, key, merge_j=merge)
                label = f"playfair(key='{key}',merge_j={merge})"
                outs.append(Result(pt, label, english_score(pt)))
            except Exception:
                pass
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

# -------- Bifid --------
def bifid_decrypt(b: bytes, key: str = "", merge_j: bool = True) -> bytes:
    txt = re.sub(r'[^A-Za-z]', '', b.decode('utf-8', errors='ignore')).upper()
    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ" if merge_j else "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    keyseq = _normalize_alpha(key)
    seen=[]
    for ch in keyseq:
        if ch in alpha and ch not in seen: seen.append(ch)
    for ch in alpha:
        if ch not in seen: seen.append(ch)
    table = [seen[i:i+5] for i in range(0,25,5)]
    pos = {table[r][c]:(r+1,c+1) for r in range(5) for c in range(5)}
    inv = { (r+1,c+1): table[r][c] for r in range(5) for c in range(5) }
    coords=[]
    for ch in txt:
        if ch in pos:
            r,c = pos[ch]; coords.append(r); coords.append(c)
    if not coords:
        return b""
    half = len(coords)//2
    row_coords = coords[:half]
    col_coords = coords[half:]
    plain=[]
    for r,c in zip(row_coords, col_coords):
        plain.append(inv.get((r,c),'?'))
    return "".join(plain).encode()

def bifid_bruteforce(b: bytes, key_hint: Optional[str]=None, topn:int=4) -> List[Result]:
    keys = []
    if key_hint: keys.append(key_hint)
    keys.extend(["KEY","FLAG","SECRET","CTF"])
    outs=[]
    for key in keys:
        for merge in (True, False):
            try:
                pt = bifid_decrypt(b, key=key, merge_j=merge)
                outs.append(Result(pt, f"bifid(key='{key}',merge_j={merge})", english_score(pt)))
            except Exception:
                pass
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

# -------- Columnar Transposition (robust decrypt) --------
def _col_transpose_decrypt(text: str, key: str) -> str:
    if not key:
        return text
    # Build key order with stable sort to handle duplicates
    key_tuples = sorted([(ch, idx) for idx, ch in enumerate(key)], key=lambda x: (x[0], x[1]))
    cols = len(key)
    base = len(text) // cols
    extra = len(text) % cols
    col_lens = [base] * cols
    for i in range(extra):
        orig_idx = key_tuples[i][1]
        col_lens[orig_idx] += 1
    cols_data = {}
    idx = 0
    for ch, orig_idx in key_tuples:
        l = col_lens[orig_idx]
        cols_data[orig_idx] = text[idx:idx+l]; idx += l
    rows = max(len(cols_data.get(k,"")) for k in cols_data) if cols_data else 0
    out=[]
    for r in range(rows):
        for j in range(cols):
            col_text = cols_data.get(j, "")
            if r < len(col_text):
                out.append(col_text[r])
    return "".join(out)

# -------- ADFGX / ADFGVX (lightweight) --------
def _build_polybius_from_key(key: str, size: int = 5) -> Tuple[List[List[str]], Dict[str, Tuple[int,int]]]:
    if size == 5:
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J merged
    else:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    seq = _normalize_alpha(key)
    # allow digits for 6x6
    seq = "".join(ch for ch in (key.upper() if key else "") if (ch.isalnum()))
    seen=[]
    for ch in seq:
        if ch in alphabet and ch not in seen: seen.append(ch)
    for ch in alphabet:
        if ch not in seen: seen.append(ch)
    table = [seen[i:i+size] for i in range(0, size*size, size)]
    pos = { table[r][c]: (r,c) for r in range(size) for c in range(size) }
    return table, pos

def _adfgx_decode_pairs(code: str, setchars: str, table: List[List[str]]) -> str:
    idxmap = {ch:i for i,ch in enumerate(setchars)}
    size = len(setchars)
    out=[]
    for i in range(0, len(code), 2):
        pair = code[i:i+2]
        if len(pair) < 2 or pair[0] not in idxmap or pair[1] not in idxmap:
            continue
        r = idxmap[pair[0]]
        c = idxmap[pair[1]]
        if 0 <= r < len(table) and 0 <= c < len(table):
            out.append(table[r][c])
    return "".join(out)

def adfgx_adfgvx_bruteforce(b: bytes, key_hint: Optional[str]=None, topn:int=3) -> List[Result]:
    s = b.decode('utf-8', errors='ignore').upper()
    outs=[]
    for setchars, size in (("ADFGX",5), ("ADFGVX",6)):
        code = re.sub(f"[^{setchars}]", "", s)
        if len(code) < 4:  # too short to be meaningful
            continue
        # square keys and column keys to try
        sq_keys = []
        col_keys = []
        if key_hint:
            kh = "".join(ch for ch in key_hint.upper() if ch.isalnum())
            if kh: 
                sq_keys.append(kh)
                col_keys.append(kh)
        sq_keys.extend(["KEY","SECRET"])
        col_keys.extend(["KEY","PASSWORD","SECRET"])
        # try (1) columnar decrypt then pair decode, and (2) direct pair decode
        for sk in sq_keys:
            table, _ = _build_polybius_from_key(sk, size=size)
            # (2) direct decode
            pt = _adfgx_decode_pairs(code, setchars, table)
            outs.append(Result(pt.encode(), f"adf{setchars.lower()}(square='{sk}')", english_score(pt.encode())))
            # (1) with columnar key
            for ck in col_keys:
                try:
                    decol = _col_transpose_decrypt(code, ck)
                    pt2 = _adfgx_decode_pairs(decol, setchars, table)
                    outs.append(Result(pt2.encode(), f"adf{setchars.lower()}(square='{sk}',col='{ck}')", english_score(pt2.encode())))
                except Exception:
                    pass
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

# -------- Hill 2x2 (proper) --------
def _mod_inv(a: int, m: int) -> Optional[int]:
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def _hill_decrypt_2x2(b: bytes, mat: Tuple[int,int,int,int]) -> bytes:
    txt = re.sub(r'[^A-Za-z]', '', b.decode('utf-8',errors='ignore')).upper()
    if not txt: return b""
    a, b2, c, d = mat
    det = (a * d - b2 * c) % 26
    inv_det = _mod_inv(det, 26)
    if inv_det is None:
        return txt.encode()
    inv_mat = [
        ( inv_det * d) % 26,
        (-inv_det * b2) % 26,
        (-inv_det * c) % 26,
        ( inv_det * a) % 26
    ]
    nums = [ord(ch) - 65 for ch in txt]
    out_chars = []
    for i in range(0, len(nums), 2):
        x = nums[i]
        y = nums[i+1] if i+1 < len(nums) else ord('X') - 65
        p0 = (inv_mat[0]*x + inv_mat[1]*y) % 26
        p1 = (inv_mat[2]*x + inv_mat[3]*y) % 26
        out_chars.append(chr(p0 + 65))
        out_chars.append(chr(p1 + 65))
    return "".join(out_chars).encode()

def hill_bruteforce(b: bytes, topn:int=4) -> List[Result]:
    candidates = [
        (3,3,2,5), (9,2,7,3), (11,8,3,7), (5,17,8,3), (7,8,11,11)
    ]
    outs=[]
    for m in candidates:
        try:
            pt = _hill_decrypt_2x2(b, m)
            outs.append(Result(pt, f"hill2x2(mat={m})", english_score(pt)))
        except Exception:
            pass
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

# -------- Four-square (simple) --------
def four_square_decrypt(b: bytes, key1: str="", key2: str="", merge_j: bool=True) -> bytes:
    txt = re.sub(r'[^A-Za-z]', '', b.decode('utf-8',errors='ignore')).upper()
    if not txt: return b""
    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ" if merge_j else "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    def build_grid(k):
        seq=_normalize_alpha(k)
        seen=[]
        for ch in seq:
            if ch in alpha and ch not in seen: seen.append(ch)
        for ch in alpha:
            if ch not in seen: seen.append(ch)
        return [seen[i:i+5] for i in range(0,25,5)]
    g0 = build_grid("")       # top-left (plain)
    g1 = build_grid(key1)     # top-right
    g2 = build_grid(key2)     # bottom-left
    g3 = build_grid("")       # bottom-right
    pos0 = {g0[r][c]:(r,c) for r in range(5) for c in range(5)}
    pos3 = {g3[r][c]:(r,c) for r in range(5) for c in range(5)}
    out=[]
    for i in range(0,len(txt),2):
        a=txt[i]; bch = txt[i+1] if i+1 < len(txt) else 'X'
        ra,ca = pos3.get(a,(None,None))
        rb,cb = pos0.get(bch,(None,None))
        if ra is None or rb is None:
            out.append(a); continue
        out.append(g2[ra][cb]); out.append(g1[rb][ca])
    return "".join(out).encode()

def four_square_bruteforce(b: bytes, key_hint: Optional[str]=None, topn:int=4) -> List[Result]:
    keys = []
    if key_hint: keys.append(key_hint)
    keys.extend(["KEY","SECRET","CTF"])
    outs=[]
    for k1 in keys:
        for k2 in keys:
            try:
                pt=four_square_decrypt(b,k1,k2,merge_j=True)
                outs.append(Result(pt, f"foursquare(k1='{k1}',k2='{k2}')", english_score(pt)))
            except Exception:
                pass
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

# -------- Nihilist (very light) --------
def nihilist_decrypt(b: bytes, key: str="") -> bytes:
    s = re.sub(r'[^0-9A-Za-z]', '', b.decode('utf-8',errors='ignore')).upper()
    if not s: return b""
    alpha="ABCDEFGHIKLMNOPQRSTUVWXYZ"
    table=[alpha[i:i+5] for i in range(0,25,5)]
    pos = {table[r][c]:(r+1,c+1) for r in range(5) for c in range(5)}
    digits = re.findall(r'\d+', s)
    if digits:
        letters=[]
        for chunk in digits:
            for i in range(0,len(chunk),2):
                p=chunk[i:i+2]
                if len(p)<2: continue
                r=int(p[0])-1; c=int(p[1])-1
                if 0<=r<5 and 0<=c<5:
                    letters.append(table[r][c])
        return "".join(letters).encode()
    # fallback: return filtered letters
    letters = "".join(ch for ch in s if ch.isalpha())
    return letters.encode()

def nihilist_bruteforce(b: bytes, key_hint: Optional[str]=None, topn:int=3) -> List[Result]:
    keys = []
    if key_hint: keys.append(key_hint)
    keys.extend(["KEY","SECRET","CTF"])
    outs=[]
    for k in keys:
        try:
            pt = nihilist_decrypt(b, key=k)
            outs.append(Result(pt, f"nihilist(key='{k}')", english_score(pt)))
        except Exception:
            pass
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

# -------- Trifid (very light) --------
def trifid_decrypt(b: bytes, period: int = 5) -> bytes:
    s = re.sub(r'[^A-Za-z]', '', b.decode('utf-8',errors='ignore')).upper()
    if not s: return b""
    out=[]
    for i in range(0,len(s),period):
        block = s[i:i+period]
        out.append(block[::-1] if len(block)==period else block)
    return "".join(out).encode()

def trifid_bruteforce(b: bytes, topn:int=3) -> List[Result]:
    outs=[]
    for p in (3,5,7):
        try:
            pt = trifid_decrypt(b, period=p)
            outs.append(Result(pt, f"trifid(period={p})", english_score(pt)))
        except Exception:
            pass
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

# -------- Tiny Substitution helper (cheap) --------
def substitution_simple_swaps(b: bytes, topn:int=4) -> List[Result]:
    """
    Cheap heuristic substitution attempts:
    - Find the top up-to-4 most frequent letters in the ciphertext.
    - Map them to the top target letters ('E','T','A','O',...) in a few shifted ways.
    - Return best scoring results.
    This avoids ValueError by ensuring source and dest strings have equal length.
    """
    txt = b.decode('utf-8',errors='ignore')
    letters = [ch for ch in txt.upper() if 'A'<=ch<='Z']
    if not letters:
        return []
    from collections import Counter
    freq = [x for x,_ in Counter(letters).most_common(8)]
    # limit to at most 4 source letters (as the old logic attempted)
    src_letters = freq[:4]
    if not src_letters:
        return []

    # Choose target letters (length must match src_letters)
    base_targets = ['E','T','A','O','I','N','S','R']
    max_map = len(src_letters)
    targets = base_targets[:max_map]

    outs: List[Result] = []
    # Try a few shifted mappings of targets to avoid combinatorial explosion
    for shift in range(max_map):
        src = ''.join(src_letters[:max_map])
        dst = ''.join(targets[(i+shift) % max_map] for i in range(max_map))
        try:
            trans = str.maketrans(src, dst)
            cand = txt.upper().translate(trans)
            outs.append(Result(cand.encode(), f"subst_map(shift={shift},{src}->{dst})", english_score(cand.encode())))
        except Exception:
            continue

    # If we didn't create any mapping (unlikely), return empty
    if not outs:
        return []

    outs.sort(key=lambda r: r.score, reverse=True)
    return outs[:topn]


# -------- Fibonacci cipher --------
def fibonacci_generate_sequence(n: int) -> List[int]:
    """Generate first n Fibonacci numbers."""
    if n <= 0: return []
    if n == 1: return [1]
    if n == 2: return [1, 1]
    fib = [1, 1]
    for i in range(2, n):
        fib.append(fib[i-1] + fib[i-2])
    return fib

def fibonacci_encrypt_text(text: str, start_pos: int = 0) -> bytes:
    """Encrypt text using Fibonacci sequence as shift values."""
    if not text: return b""
    letters = [ch for ch in text.upper() if 'A' <= ch <= 'Z']
    if not letters: return text.encode()
    
    # Generate enough Fibonacci numbers
    fib_seq = fibonacci_generate_sequence(len(letters) + start_pos)
    if len(fib_seq) < len(letters): 
        return text.encode()  # fallback
    
    result = []
    for i, ch in enumerate(letters):
        shift = fib_seq[i + start_pos] % 26
        new_ch = chr(((ord(ch) - ord('A') + shift) % 26) + ord('A'))
        result.append(new_ch)
    
    return ''.join(result).encode()

def fibonacci_decrypt_text(text: str, start_pos: int = 0) -> bytes:
    """Decrypt text using Fibonacci sequence as shift values."""
    if not text: return b""
    letters = [ch for ch in text.upper() if 'A' <= ch <= 'Z']
    if not letters: return text.encode()
    
    # Generate enough Fibonacci numbers
    fib_seq = fibonacci_generate_sequence(len(letters) + start_pos)
    if len(fib_seq) < len(letters): 
        return text.encode()  # fallback
    
    result = []
    for i, ch in enumerate(letters):
        shift = fib_seq[i + start_pos] % 26
        new_ch = chr(((ord(ch) - ord('A') - shift) % 26) + ord('A'))
        result.append(new_ch)
    
    return ''.join(result).encode()

def fibonacci_bruteforce(b: bytes, topn: int = 8) -> List[Result]:
    """Try Fibonacci cipher with different starting positions."""
    try:
        text = b.decode('utf-8', errors='ignore')
    except Exception:
        text = b.decode('latin1', errors='ignore')
    
    if not text or not any('A' <= ch <= 'Z' or 'a' <= ch <= 'z' for ch in text):
        return []
    
    outs = []
    # Try different starting positions in Fibonacci sequence
    for start in range(min(10, len(text))):
        try:
            pt = fibonacci_decrypt_text(text, start_pos=start)
            if pt:
                score = english_score(pt)
                outs.append(Result(pt, f"fibonacci(start={start})", score))
        except Exception:
            continue
    
    outs.sort(key=lambda r: r.score, reverse=True)
    return outs[:topn]

# -------- Homophonic substitution (CTF-friendly) --------
def homophonic_decode_bytes(b: bytes) -> bytes:
    """
    Decode a homophonic substitution that encodes letters as 2-digit codes.
    Accepts bytes, tolerates separators, returns bytes plaintext (uppercase).
    Unknown codes become '?'
    """
    # mapping derived from your table (string keys '00'..'99' -> letters)
    M = {
        '21': 'A', '27': 'A', '31': 'A', '40': 'A',
        '15': 'B',
        '01': 'C', '33': 'C',
        '20': 'D', '34': 'D',
        '22': 'E', '28': 'E', '32': 'E', '36': 'E', '37': 'E',
        '05': 'F',
        '17': 'G',
        '14': 'H',
        '02': 'I', '29': 'I', '38': 'I', '41': 'I',
        '19': 'J',
        '03': 'K',
        '07': 'L', '39': 'L', '42': 'L',
        '09': 'M', '43': 'M',
        '12': 'N', '48': 'N', '97': 'N',
        '18': 'O', '60': 'O', '85': 'O',
        '26': 'P', '44': 'P',
        '25': 'Q',
        '24': 'R', '49': 'R',
        '10': 'S', '30': 'S', '45': 'S', '99': 'S',
        '06': 'T', '96': 'T', '55': 'T',
        '16': 'U', '94': 'U',
        '23': 'V',
        '13': 'W',
        '11': 'X',
        '08': 'Y',
        '04': 'Z'
    }

    # Decode: Remove non-digit characters, then chunk into 2-digit groups.
    try:
        s = b.decode('utf-8', errors='ignore')
    except Exception:
        s = b.decode('latin1', errors='ignore')

    digits = "".join(ch for ch in s if ch.isdigit())
    if not digits:
        # maybe ciphertext contains letters that are actually digit pairs separated by spaces,
        # try splitting by whitespace and taking tokens that look like 2-digit.
        tokens = re.findall(r'\b\d{2}\b', s)
        if tokens:
            decoded = "".join(M.get(tok, '?') for tok in tokens)
            return decoded.encode()
        return b""

    # if odd length, drop trailing char (could also try prefixing 0, but safer to drop)
    if len(digits) % 2 == 1:
        digits = digits[:-1]

    out_chars = []
    for i in range(0, len(digits), 2):
        chunk = digits[i:i+2]
        out_chars.append(M.get(chunk, '?'))
    return "".join(out_chars).encode()

def homophonic_bruteforce(b: bytes, topn: int = 3) -> List[Result]:
    """
    Wrapper to fit pipeline: returns a small list of Result objects.
    Currently we only try the single known mapping (cheap). If you add
    alternate mappings or key-based variants, extend here.
    """
    try:
        pt = homophonic_decode_bytes(b)
        return [Result(pt, "homophonic", english_score(pt))]
    except Exception:
        return []




# -------- Caesar Box / Columnar Box (Rectangle Transposition) --------
def box_cipher_bruteforce(b: bytes, max_width: int = 20, topn: int = 5) -> List[Result]:
    """
    Try multiple rectangle widths for 'Caesar Box' style transposition.
    Returns a list of Result objects ranked by english_score.
    """

    try:
        s = b.decode('utf-8', errors='ignore')
    except Exception:
        s = b.decode('latin1', errors='ignore')

    L = len(s)
    if L < 4:
        return []

    outs = []

    # generate candidate widths
    sizes = set()
    for w in range(2, min(max_width, L) + 1):
        sizes.add(w)
    for w in range(2, int(math.sqrt(L)) + 1):
        if L % w == 0:
            sizes.add(w)
            sizes.add(L // w)

    for width in sorted(sizes):
        height = math.ceil(L / width)
        num_long = L - (height - 1) * width
        cols = []
        idx = 0
        for col in range(width):
            col_len = height if col < num_long else height - 1
            cols.append(s[idx:idx + col_len])
            idx += col_len

        # reconstruct plaintext reading row-wise
        grid = []
        for r in range(height):
            row_chars = []
            for c in range(width):
                if r < len(cols[c]):
                    ch = cols[c][r]
                else:
                    ch = '_'
                row_chars.append(ch)
            grid.append(row_chars)

        plaintext = "".join(ch for row in grid for ch in row)
        clean = plaintext.rstrip('_')
        score = english_score(clean.encode('utf-8', errors='ignore'))
        outs.append(Result(clean.encode(), f"box(width={width},height={height})", score))

    outs.sort(key=lambda r: r.score, reverse=True)
    return outs[:topn]



# ---------- ECV (reverse reduce) decoder ----------
import ast

def _decrypt_ecv_single_int(encrypted_value: int) -> str:
    """
    Reverse the reduce-like obfuscation that was described:
      for s in reversed([16,32,64,128]):
          value = value ^ s
          value = value >> s
      root = isqrt(value); return chr(root)

    This function implements that and returns a single-character string.
    If any step fails or root is out-of-range, returns '?'.
    """
    try:
        # sequence used in your snippet
        n = [16, 32, 64, 128]
        value = int(encrypted_value)
        for s in reversed(n):
            # undo the XOR and the left shift
            value = value ^ s
            value = value >> s
        # integer sqrt
        root = math.isqrt(value)
        if 0 <= root <= 0x10FFFF:
            return chr(root)
        return '?'
    except Exception:
        return '?'

def _parse_big_ints_from_text(s: str) -> List[int]:
    """
    Try several heuristics to pull out big integers from the text:
      - Python-style list literal: [1234, 5678, ...]
      - Comma/space/dash-separated numbers
      - Multi-line numbers
      - Fallback: any long integer tokens (10+ digits) found by regex
    Returns a list of ints (may be empty).
    """
    nums = []
    s = s.strip()
    # 1) try to parse a python list literal
    if s.startswith('[') and s.endswith(']'):
        try:
            lst = ast.literal_eval(s)
            if isinstance(lst, (list, tuple)) and all(isinstance(x, int) for x in lst):
                return list(lst)
        except Exception:
            pass

    # 2) find all integer tokens (allow very large)
    token_matches = re.findall(r'\d{6,}', s)  # tokens of length >=6 digits (tunable)
    if token_matches:
        try:
            return [int(t) for t in token_matches]
        except Exception:
            pass

    # 3) split on common separators and parse
    sep_tokens = re.split(r'[,\s\]\[\(\)\-;:]+', s)
    for tok in sep_tokens:
        if not tok: continue
        if re.fullmatch(r'\d{1,}', tok):
            try:
                nums.append(int(tok))
            except Exception:
                pass
    return nums

def dec_ecv(b: bytes) -> List[Result]:
    """
    Decoder wrapper to detect and attempt ECV-style big-integer list decoding.
    If the input contains large integers, attempts to decode each into a character
    using the reversal algorithm. Returns a Result with plaintext when found,
    otherwise returns [].
    """
    try:
        s = b.decode('utf-8', errors='ignore').strip()
    except Exception:
        s = b.decode('latin1', errors='ignore').strip()

    ints = _parse_big_ints_from_text(s)
    if not ints:
        return []

    # Cap how many we decode to prevent huge loops
    MAX_DECODE = 4096
    if len(ints) > MAX_DECODE:
        ints = ints[:MAX_DECODE]

    chars = []
    for val in ints:
        ch = _decrypt_ecv_single_int(val)
        chars.append(ch)
    plain = "".join(chars)

    # Filter out degenerate results (too many ? or non-printable)
    printable = "".join(ch for ch in plain if 32 <= ord(ch) < 127)
    ratio = len(printable) / max(1, len(plain))
    if len(plain) == 0 or ratio < 0.25:
        # not a promising decode
        return []
    return [Result(plain.encode('utf-8', errors='ignore'), "ecv", english_score(plain.encode('utf-8', errors='ignore')))]


# -------- Twin Hex (trigrams base36 -> ASCII bigrams) --------
ASCII_MIN = 32
ASCII_MAX = 127
ALPHABET_SIZE = ASCII_MAX - ASCII_MIN + 1  # 96
MAX_TWIN_INDEX = ALPHABET_SIZE * ALPHABET_SIZE - 1  # 9215

def _base36_to_int_token(s: str) -> int:
    """Convert base36 token (0-9,a-z) to integer (case-insensitive)."""
    s = s.lower()
    # allow tokens up to length 3 (base36) — int(s,36) will raise if invalid
    return int(s, 36)

def _index_to_bigram(idx: int) -> str:
    """Map integer 0..9215 into two ASCII chars (range 32..127 inclusive)."""
    if not (0 <= idx <= MAX_TWIN_INDEX):
        raise ValueError(f"Index {idx} out of TwinHex range (0..{MAX_TWIN_INDEX})")
    a = idx // ALPHABET_SIZE
    b = idx % ALPHABET_SIZE
    return chr(ASCII_MIN + a) + chr(ASCII_MIN + b)

def _tokenize_twinhex_text(s: str):
    """
    Split input into base36 tokens of length up to 3.
    Accepts whitespace-separated tokens; if a token has longer length,
    it is chunked into 3-char pieces. E.g. "52b5wk540" -> ["52b","5wk","540"].
    """
    parts = []
    for tok in s.split():
        if not tok:
            continue
        i = 0
        while i < len(tok):
            parts.append(tok[i:i+3])
            i += 3
    # fallback: if user provided a continuous string without spaces, and split() yields single token,
    # the loop above already chunked it. So parts will be non-empty.
    return parts

def decode_twinhex_text(ciphertext: str, verbose: bool = False) -> str:
    """
    Decode a Twin Hex textual ciphertext into plaintext string.
    Tokenizes into base36 1..3 char tokens, converts each token -> index -> two ASCII chars.
    """
    if not ciphertext:
        return ""
    tokens = _tokenize_twinhex_text(ciphertext.strip())
    if verbose:
        # debug printing if needed
        print(f"[twinhex] tokens: {tokens}")
    out = []
    for t in tokens:
        if not t:
            continue
        try:
            idx = _base36_to_int_token(t)
        except Exception as e:
            raise ValueError(f"Invalid TwinHex token {t!r}: {e}") from e
        if idx > MAX_TWIN_INDEX:
            raise ValueError(f"TwinHex token {t!r} decoded to {idx}, > {MAX_TWIN_INDEX}")
        out.append(_index_to_bigram(idx))
    return "".join(out)

def dec_twinhex(b: bytes) -> List[Result]:
    """
    Bytes -> List[Result] wrapper so TwinHex fits into your decoder pipeline.
    Accepts any bytes, decodes to str (latin1/utf-8 tolerant), extracts tokens and returns result.
    """
    try:
        s = b.decode('utf-8', errors='ignore').strip()
    except Exception:
        s = b.decode('latin1', errors='ignore').strip()
    if not s:
        return []
    try:
        pt = decode_twinhex_text(s, verbose=False)
        return [Result(pt.encode('utf-8', errors='ignore'), "twinhex")]
    except Exception:
        # if decoding fails, return empty list (so it doesn't spam errors)
        return []




































# ---------- Registries ----------
PHASE1_DECODERS: List[Callable[[bytes], List[Result]]] = [
    dec_hex, dec_binary, dec_ascii_numbers, dec_octal_numbers,dec_ecv,
    dec_base64, dec_base32, dec_base36, dec_base62, dec_base58, dec_base85, dec_base45, dec_base91, dec_base92,
    dec_url, dec_html,
    dec_zlib, dec_gzip, dec_bz2, dec_lzma,
    lambda b: atbash(b),
    lambda b: rot47(b),
    rot5_numbers,
    do_reverse,
    dec_twinhex,
]

BASE_NAMES = {"base64","base32","base36","base62","base58","base85","ascii85","base45","base91","base92","hex","binary","url","html","zlib","gzip","bz2","lzma","atbash","rot47","rot5","reverse","ascii(dec)","ascii(oct)","ascii_shift","ecv","twinhex"}

def phase1_solvers(b: bytes, key_map: Dict[str, Optional[bytes]]) -> List[Result]:
    outs: List[Result] = []
    # Caesar / Affine
    outs.extend(caesar_bruteforce(b, topn=6))
    outs.extend(affine_bruteforce(b, topn=8))
    # XOR single-byte + guessed repeating
    outs.extend(xor_single_byte_bruteforce(b, key_hint=key_map.get('raw') if key_map else None, topn=8))
    outs.extend(xor_repeating_key_guess(b, max_len=6, topn=3))
    # XOR with user multi-byte key if given
    if key_map and key_map.get('raw') and len(key_map['raw']) > 1:
        outs.extend(xor_with_user_key(b, key_map['raw']))
    # Vigenere
    if key_map:
        if key_map.get('vigenere'):
            outs.append(Result(vigenere_decrypt(b, key_map['vigenere']), f"vigenere(key='{key_map['vigenere'].decode()}')", english_score(vigenere_decrypt(b, key_map['vigenere']))))
        elif key_map.get('vigenere_from_digits'):
            outs.append(Result(vigenere_decrypt(b, key_map['vigenere_from_digits']), f"vigenere_from_digits(key='{key_map['vigenere_from_digits'].decode()}')", english_score(vigenere_decrypt(b, key_map['vigenere_from_digits']))))
        else:
            outs.extend(vigenere_quick(b, key_hint=None, topn=3))
    else:
        outs.extend(vigenere_quick(b, key_hint=None, topn=3))
    outs.extend(rail_fence_bruteforce(b, min_r=2, max_r=10, topn=6))
    outs.extend(scytale_bruteforce(b, min_w=2, max_w=12, topn=4))
    outs.extend(box_cipher_bruteforce(b, max_width=15, topn=4))
    # Always-on light decoders
    outs.append(Result(baconian_decrypt(b), "baconian", english_score(baconian_decrypt(b))))
    outs.append(Result(morse_decrypt(b), "morse", english_score(morse_decrypt(b))))
    # Lightweight additions (now key-aware)
    key_hint_text = key_map.get('text').decode(errors='ignore') if key_map and key_map.get('text') else None
    outs.extend(playfair_bruteforce(b, key_hint=key_hint_text, topn=3))
    outs.extend(bifid_bruteforce(b, key_hint=key_hint_text, topn=3))
    outs.extend(adfgx_adfgvx_bruteforce(b, key_hint=key_hint_text, topn=3))
    outs.extend(hill_bruteforce(b, topn=3))
    outs.extend(four_square_bruteforce(b, key_hint=key_hint_text, topn=3))
    outs.extend(nihilist_bruteforce(b, key_hint=key_hint_text, topn=2))
    outs.extend(trifid_bruteforce(b, topn=2))
    outs.extend(substitution_simple_swaps(b, topn=3))
    outs.extend(homophonic_bruteforce(b, topn=2))
    outs.extend(fibonacci_bruteforce(b, topn=4))
    outs.extend(ascii_shift_bruteforce(b, topn=6, span=32))
    # Key-based variants
    if key_map:
        key_txt = key_hint_text
        if key_txt:
            outs.append(Result(autokey_decrypt(b, key_txt), f"autokey(key='{key_txt}')", english_score(autokey_decrypt(b, key_txt))))
            if any(ch.isalpha() for ch in key_txt):
                outs.append(Result(beaufort_decrypt(b, key_txt), f"beaufort(key='{key_txt}')", english_score(beaufort_decrypt(b, key_txt))))
            outs.append(Result(porta_decrypt(b, key_txt), f"porta(key='{key_txt}')", english_score(porta_decrypt(b, key_txt))))
        if key_map.get('digits'):
            digs = key_map['digits'].decode()
            outs.append(Result(gronsfeld_decrypt(b, digs), f"gronsfeld(key='{digs}')", english_score(gronsfeld_decrypt(b, digs))))
    return outs

def should_expand(res: Result) -> bool:
    pr = printable_ratio(res.data)
    ent = entropy(res.data)
    if res.method in BASE_NAMES:
        return True
    return pr > 0.25 and ent > 3.0

# ---------- Phase runners ----------
@dataclass
class PhaseStats:
    ops:int=0
    yellow:int=0
    exact:int=0

def try_specific_decoder_by_name(data: bytes, method_name: str, key_map: Dict[str, Optional[bytes]], main_re, extra_re, flag_format: str) -> Optional[Tuple[bytes, str]]:
    """Try a specific decoder by name. Returns (decoded_data, method) if successful flag found, None otherwise."""
    
    # Map method names to decoder functions
    decoder_map = {
        "base64": dec_base64,
        "hex": dec_hex, 
        "binary": dec_binary,
        "ascii_numbers": dec_ascii_numbers,
        "morse": lambda b: [Result(morse_decrypt(b), "morse", english_score(morse_decrypt(b)))],
        "caesar": lambda b: caesar_bruteforce(b, topn=3),  # Try top 3 Caesar shifts
    }
    
    decoder_func = decoder_map.get(method_name)
    if not decoder_func:
        return None
    
    try:
        results = decoder_func(data)
        if not results:
            return None
        
        # Try each result to see if it contains a flag
        for result in results:
            save_report_entry(result.method, result.data)
            hits = find_flags(result.data, main_re, extra_re, flag_format)
            if hits:
                exact = [h for h in hits if h.case == "exact"]
                if exact:
                    for h in exact:
                        print_flag((result.method,), h)
                    return result.data, result.method
        
    except Exception:
        pass  # Failed, continue to next method
    
    return None

def run_phase1(b: bytes, main_re, extra_re, key_map: Dict[str, Optional[bytes]], debug_on: bool, flag_format: str) -> Tuple[Optional[bytes], Optional[Tuple[str,...]], PhaseStats]:
    st = PhaseStats()
    
    # NEW: Smart detection and prioritized execution
    try:
        predictions = analyze_and_prioritize(b)
        if predictions:
            top_pred = predictions[0]
            print(f"💡 {cCYN('Smart suggestion:')} {top_pred[0]} ({top_pred[1]*100:.0f}% confidence) - trying first...")
            if len(predictions) > 1:
                others = ", ".join(f"{p[0]} ({p[1]*100:.0f}%)" for p in predictions[1:3])
                print(f"   {cBLU('Also trying:')} {others}")
            
            # Try high-confidence predictions first (>70% confidence)
            high_confidence = [p for p in predictions if p[1] > 0.7]
            for method_name, confidence in high_confidence:
                if debug_on:
                    eprint(cCYN(f"[PRIORITY] Trying: {method_name}"))
                
                result = try_specific_decoder_by_name(b, method_name, key_map, main_re, extra_re, flag_format)
                if result:
                    st.exact += 1
                    st.ops += 1
                    return result[0], (result[1],), st
                st.ops += 1
        else:
            print(f"💡 {cCYN('No clear pattern detected - using comprehensive scan')}")
            
    except Exception as e:
        if debug_on:
            eprint(f"Detection error: {e}")
    
    # FALLBACK: If high-confidence methods didn't work, use comprehensive scan
    print(f"🔄 {cCYN('Comprehensive scan - trying all methods...')}")
    
    try:
        save_report_entry("orig", b)
    except Exception:
        pass

    hits = find_flags(b, main_re, extra_re, flag_format)
    if hits:
        st.yellow += sum(1 for h in hits if h.case!="exact")
        if any(h.case=="exact" for h in hits):
            st.exact += 1
            for h in hits:
                if h.case=="exact":
                    print_flag(("orig",), h)
            st.ops += 1
            return b, ("orig",), st

    for dec in PHASE1_DECODERS:
        try:
            reslist = dec(b)
        except Exception:
            continue
        for res in reslist:
            st.ops += 1
            if debug_on:
                eprint(cCYN(f"Trying: [{res.method}]"))
            try:
                save_report_entry(res.method, res.data)
            except Exception:
                pass

            hits = find_flags(res.data, main_re, extra_re, flag_format)
            if hits:
                st.yellow += sum(1 for h in hits if h.case!="exact")
                exact = [h for h in hits if h.case=="exact"]
                if exact:
                    st.exact += 1
                    for h in exact: print_flag((res.method,), h)
                    return res.data, (res.method,), st
                else:
                    for h in hits: print_partial((res.method,), h, res.data)

    for res in phase1_solvers(b, key_map):
        st.ops += 1
        if debug_on:
            eprint(cCYN(f"Trying: [{res.method}]"))
        try:
            save_report_entry(res.method, res.data)
        except Exception:
            pass

        hits = find_flags(res.data, main_re, extra_re, flag_format)
        if hits:
            st.yellow += sum(1 for h in hits if h.case!="exact")
            exact = [h for h in hits if h.case=="exact"]
            if exact:
                st.exact += 1
                for h in exact: print_flag((res.method,), h)
                return res.data, (res.method,), st
            else:
                for h in hits: print_partial((res.method,), h, res.data)

    return None, None, st

def run_combo_layers(b: bytes, main_re, extra_re, key_map: Dict[str, Optional[bytes]], max_depth: int, debug_on: bool, phase_name:str, flag_format: str) -> Tuple[Optional[bytes], Optional[Tuple[str,...]], PhaseStats]:
    st = PhaseStats()

    def apply_all_transforms(data: bytes) -> List[Result]:
        out: List[Result] = []
        # decoders + cheap transforms
        for dec in PHASE1_DECODERS:
            try: out.extend(dec(data))
            except Exception: pass
        # bruteforces & ciphers
        out.extend(caesar_bruteforce(data, topn=6))
        out.extend(affine_bruteforce(data, topn=8))
        out.extend(xor_single_byte_bruteforce(data, key_hint=key_map.get('raw') if key_map else None, topn=8))
        out.extend(ascii_shift_bruteforce(data, topn=4, span=24))
        out.extend(xor_repeating_key_guess(data, max_len=6, topn=3))
        out.extend(xor_repeating_key_guess(data, max_len=6, topn=3))
        if key_map and key_map.get('raw') and len(key_map['raw'])>1:
            out.extend(xor_with_user_key(data, key_map['raw']))
        if key_map:
            if key_map.get('vigenere'):
                out.append(Result(vigenere_decrypt(data, key_map['vigenere']), f"vigenere(key='{key_map['vigenere'].decode()}')", english_score(vigenere_decrypt(data, key_map['vigenere']))))
            elif key_map.get('vigenere_from_digits'):
                out.append(Result(vigenere_decrypt(data, key_map['vigenere_from_digits']), f"vigenere_from_digits(key='{key_map['vigenere_from_digits'].decode()}')", english_score(vigenere_decrypt(data, key_map['vigenere_from_digits']))))
            else:
                out.extend(vigenere_quick(data, key_hint=None, topn=3))
        else:
            out.extend(vigenere_quick(data, key_hint=None, topn=3))
        # lightweight additions (ALWAYS run; bug fixed)
        key_hint_text = key_map.get('text').decode(errors='ignore') if key_map and key_map.get('text') else None
        out.extend(playfair_bruteforce(data, key_hint=key_hint_text, topn=2))
        out.extend(bifid_bruteforce(data, key_hint=key_hint_text, topn=2))
        out.extend(adfgx_adfgvx_bruteforce(data, key_hint=key_hint_text, topn=2))
        out.extend(hill_bruteforce(data, topn=2))
        out.extend(four_square_bruteforce(data, key_hint=key_hint_text, topn=2))
        out.extend(nihilist_bruteforce(data, key_hint=key_hint_text, topn=1))
        out.extend(trifid_bruteforce(data, topn=1))
        out.extend(substitution_simple_swaps(data, topn=2))
        out.extend(fibonacci_bruteforce(data, topn=2))
        # rail fence / scytale
        out.extend(rail_fence_bruteforce(data, min_r=2, max_r=10, topn=6))
        out.extend(scytale_bruteforce(data, min_w=2, max_w=12, topn=4))
        out.extend(homophonic_bruteforce(data, topn=1))
        out.extend(box_cipher_bruteforce(data, max_width=15, topn=2))
        # light decoders
        out.append(Result(baconian_decrypt(data), "baconian", english_score(baconian_decrypt(data))))
        out.append(Result(morse_decrypt(data), "morse", english_score(morse_decrypt(data))))
        return out

    start = Candidate(b, ("orig",), 0, english_score(b))
    Q: List[Candidate] = [start]
    visited=set()
    shown_yellow=set()

    while Q:
        node = Q.pop(0)
        if node.depth >= max_depth:
            continue

        next_res = apply_all_transforms(node.data)
        next_res.sort(key=lambda r: (r.method in BASE_NAMES, getattr(r,"score",0)), reverse=True)

        for res in next_res:
            chain = node.chain + (res.method,)
            st.ops += 1
            if debug_on:
                eprint(cCYN(f"Trying: [{' -> '.join(chain[1:])}]"))

            try:
                op_name = " -> ".join(chain[1:]) if len(chain) > 1 else res.method
                save_report_entry(op_name, res.data)
            except Exception:
                pass

            hits = find_flags(res.data, main_re, extra_re, flag_format)
            if hits:
                st.yellow += sum(1 for h in hits if h.case!="exact")
                exact = [h for h in hits if h.case=="exact"]
                if exact:
                    st.exact += 1
                    for h in exact: print_flag(chain[1:], h)
                    return res.data, chain[1:], st
                else:
                    key=(res.method, res.data[:64])
                    if key not in shown_yellow:
                        shown_yellow.add(key)
                        for h in hits: print_partial(chain[1:], h, res.data)

            pr = printable_ratio(res.data); ent=entropy(res.data)
            if not should_expand(res):
                continue
            if pr < 0.12 and ent < 3.0:
                continue

            hsh=(hash(res.data), chain[-1])
            if hsh in visited: continue
            visited.add(hsh)

            Q.append(Candidate(res.data, chain, node.depth+1, getattr(res,"score",0.0)))

    return None, None, st

# ---------- Interactive ----------
def interactive_flow(flag_format_cli: Optional[str], key_cli: Optional[bytes]) -> Tuple[str, bytes, Dict[str, Optional[bytes]]]:
    flag_format = flag_format_cli or input("Enter flag format (e.g., picoctf): ").strip()
    ct_in = input("Ciphertext (text or path to file): ").strip()
    if is_file(ct_in):
        with open(ct_in, "rb") as f: ctext=f.read()
    else:
        ctext = ct_in.encode()
    if key_cli is not None:
        key_map = normalize_key_map(key_cli)
    else:
        k = input("Key/passphrase (optional; text or path): ").strip()
        key_bytes = read_value_or_file(k) if k else None
        key_map = normalize_key_map(key_bytes) if key_bytes else {'raw': None, 'text': None, 'digits': None, 'vigenere': None, 'vigenere_from_digits': None}
    return flag_format, ctext, key_map

# ---------- Small phase report (plain) ----------
def phase_report_plain(name: str, st: PhaseStats):
    print(f"[{name}] ops={st.ops} yellow={st.yellow} exact={st.exact}")

# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser(
        description="cipherxploit: minimal, modular cipher solver for CTFs",
        add_help=False
    )
    ap.add_argument("flag_format", nargs="?", help="Flag format (e.g., picoctf) -> builds regex TOKEN\\{.*?\\}")
    ap.add_argument("-c","--ciphertext", help="Ciphertext (raw string or path to file)")
    ap.add_argument("-k","--key", help="Key/passphrase (raw string or path to file)")
    ap.add_argument("-r","--extra-regex", help="Additional regex to highlight (yellow)")
    ap.add_argument("-d","--debug", action="store_true", help="Small debug: show operations being checked")
    ap.add_argument("-b","--batch", action="store_true", help="Batch mode: skip interactive prompts and run only single-layer analysis")
    ap.add_argument("-h","--help", action="help", help="Show this help and exit")
    args = ap.parse_args()

    _report_all.clear(); _report_might.clear()
    try:
        open(REPORT_PATH, "w", encoding="utf-8").close()
    except Exception:
        pass

    key_cli = read_value_or_file(args.key) if args.key else None
    key_map = normalize_key_map(key_cli) if key_cli else {'raw': None, 'text': None, 'digits': None, 'vigenere': None, 'vigenere_from_digits': None}

    if args.ciphertext is None:
        flag_format, ctext, key_map = interactive_flow(args.flag_format, key_cli)
    else:
        flag_format = args.flag_format or input("Enter flag format (e.g., picoctf): ").strip()
        ctext = read_value_or_file(args.ciphertext)
        if ctext is None:
            print(cYEL("Could not read ciphertext.")); sys.exit(2)

    if not flag_format:
        print(cYEL("Missing flag format (e.g., picoctf).")); sys.exit(2)

    main_re = build_main_regex(flag_format)
    extra_re = compile_extra_regex(args.extra_regex)
    debug_on = args.debug
    batch_mode = args.batch

    print(cCYN("=== Phase 1: single-layer ==="))
    win, chain, st1 = run_phase1(ctext, main_re, extra_re, key_map, debug_on, flag_format)
    phase_report_plain("Phase 1", st1)
    if win is not None:
        write_report_file()
        sys.exit(0)

    # Skip multi-layer phases in batch mode
    if batch_mode:
        print(cYEL("Batch mode: Skipping multi-layer analysis. No exact-case flag found in Phase 1."))
        write_report_file()
        print(cBLU(f"Report written to {REPORT_PATH}"))
        sys.exit(1)

    print(cCYN("=== Phase 2: dual-layer combinations ==="))
    win, chain, st2 = run_combo_layers(ctext, main_re, extra_re, key_map, max_depth=2, debug_on=debug_on, phase_name="Phase 2", flag_format=flag_format)
    phase_report_plain("Phase 2", st2)
    if win is not None:
        write_report_file()
        sys.exit(0)

    allow_triple = input("Try triple-layer combos (can be slow)? (y/N): ").strip().lower().startswith('y')
    if allow_triple:
        print(cCYN("=== Phase 3: triple-layer combinations ==="))
        win, chain, st3 = run_combo_layers(ctext, main_re, extra_re, key_map, max_depth=3, debug_on=debug_on, phase_name="Phase 3", flag_format=flag_format)
        phase_report_plain("Phase 3", st3)
        if win is not None:
            write_report_file()
            sys.exit(0)
        allow_quad = input("Still nothing. Try quad-layer combos? (y/N): ").strip().lower().startswith('y')
        if allow_quad:
            print(cCYN("=== Phase 4: quad-layer combinations ==="))
            win, chain, st4 = run_combo_layers(ctext, main_re, extra_re, key_map, max_depth=4, debug_on=debug_on, phase_name="Phase 4", flag_format=flag_format)
            phase_report_plain("Phase 4", st4)
            if win is not None:
                write_report_file()
                sys.exit(0)

    print(cYEL("No exact-case flag found. Review partial matches, adjust (-k/-r), or enable deeper layers."))
    write_report_file()
    print(cBLU(f"Report written to {REPORT_PATH}"))
    sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted."); sys.exit(130)
