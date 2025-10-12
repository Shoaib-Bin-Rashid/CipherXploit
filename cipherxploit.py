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
from typing import Callable, List, Optional, Sequence, Tuple

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
    # exact-case regex (e.g., picoctf\{.*?\})
    pat = rf"{re.escape(flag_format)}\{{.*?\}}"
    return re.compile(pat)

def compile_extra_regex(rx: Optional[str]) -> Optional[re.Pattern]:
    if not rx: return None
    try: return re.compile(rx, re.IGNORECASE)
    except re.error: return None

def find_flags(blob: bytes, main_re: re.Pattern, extra_re: Optional[re.Pattern], flag_format: str) -> List[Hit]:
    """
    Return list of hits. Priority:
      1) exact-case main_re matches -> case="exact"
      2) case-insensitive whole-token matches -> case="partial"
      3) if flag_format (prefix) appears anywhere (loose) -> attempt to find surrounding token {...}, else return matched substring -> case="partial"
      4) extra_re matches -> case="extra"
    """
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

    # 3) loose prefix search (e.g., searching "RCS" and token is "RCSC{...}")
    loose = re.compile(re.escape(flag_format), re.IGNORECASE)
    m = loose.search(txt)
    if m:
        # try to find enclosing token with braces near the match
        start_search = max(0, m.start()-32)
        end_search = min(len(txt), m.end()+256)
        window = txt[start_search:end_search]
        tok_match = re.search(r"[A-Za-z0-9_]+\{.*?\}", window)
        if tok_match:
            full = tok_match.group()
            # compute absolute span
            abs_start = start_search + tok_match.start()
            abs_end = start_search + tok_match.end()
            hits.append(Hit(full, (abs_start, abs_end), "partial"))
        else:
            # fallback: show the matched substring
            hits.append(Hit(m.group(), (m.start(), m.end()), "partial"))
        return hits

    # 4) extra regex
    if extra_re:
        for m in extra_re.finditer(txt):
            hits.append(Hit(m.group(), (m.start(), m.end()), "extra"))
    return hits

def print_partial(chain: Sequence[str], hit: Hit):
    print("---------------------------------------------")
    print(f"Partial match :  [{ ' -> '.join(chain) }]  {cYEL(hit.match)}")
    print("---------------------------------------------")

def print_flag(chain: Sequence[str], hit: Hit):
    print("\n==============")
    print(f"Flag Found : {cGRN(hit.match)}")
    print(f"Operation :  [{ ' -> '.join(chain) }]")
    print("==============\n")

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
            cand=fn(b.strip(), validate=False)
            if cand: outs.append(Result(cand,name))
        except Exception: pass
    return outs

def dec_base92(b: bytes) -> List[Result]:
    """
    Decode Base92 as used by GCHQ CyberChef (different from Horne's Base92).
    Reference: CyberChef source code (b92.js)
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
    v = -1
    bits = 0
    n = 0
    out = bytearray()
    s = b.decode('utf-8', errors='ignore').strip()
    for c in s:
        if c not in alphabet:
            continue
        val = alphabet.index(c)
        if v < 0:
            v = val
        else:
            v += val * 91
            n |= v << bits
            bits += 13 if (v & 8191) > 88 else 14
            while bits >= 8:
                out.append(n & 0xFF)
                n >>= 8
                bits -= 8
            v = -1
    if v >= 0:
        out.append((n | (v << bits)) & 0xFF)
    return [Result(bytes(out), "base92(cyberchef)")]



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

# ---------- Classical & simple ciphers ----------
def caesar_shift(b: bytes, k:int)->bytes:
    out=bytearray()
    for ch in b:
        if 65<=ch<=90: out.append(((ch-65+k)%26)+65)
        elif 97<=ch<=122: out.append(((ch-97+k)%26)+97)
        else: out.append(ch)
    return bytes(out)

def caesar_bruteforce(b: bytes, topn:int=3)->List[Result]:
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
def affine_bruteforce(b: bytes, topn:int=6)->List[Result]:
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

def xor_single_byte_bruteforce(b: bytes, key_hint: Optional[bytes]=None, topn:int=5)->List[Result]:
    if key_hint and len(key_hint)==1:
        pt=xor_bytes(b,key_hint)
        return [Result(pt,f"xor(0x{key_hint[0]:02x})", english_score(pt))]
    outs=[]
    for k in range(256):
        key=bytes([k]); pt=xor_bytes(b,key)
        outs.append(Result(pt, f"xor(0x{k:02x})", english_score(pt)))
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

def xor_repeating_key_guess(b: bytes, max_len:int=6, topn:int=3)->List[Result]:
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

def vigenere_quick(b: bytes, key_hint: Optional[bytes]=None, topn:int=3)->List[Result]:
    if key_hint:
        key = key_hint.decode('utf-8',errors='ignore')
        kbytes = key.encode().upper()
        pt=vigenere_decrypt(b,kbytes)
        return [Result(pt,f"vigenere(key='{key}')", english_score(pt))]
    outs=[]
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
    ks=[(ord(c.upper())-65)%26 for c in key if c.isalpha()]
    out=bytearray(); j=0
    for ch in b:
        if 65<=ch<=90: out.append(((ks[j%len(ks)] - (ch-65))%26)+65); j+=1
        elif 97<=ch<=122: out.append(((ks[j%len(ks)] - (ch-97))%26)+97); j+=1
        else: out.append(ch)
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
    L=len(ct)
    rail=[['\n']*L for _ in range(rails)]
    dir_down=None; row,col=0,0
    for _ in range(L):
        if row==0: dir_down=True
        if row==rails-1: dir_down=False
        rail[row][col]='*'; col+=1
        row = row+1 if dir_down else row-1
    idx=0
    for i in range(rails):
        for j in range(L):
            if rail[i][j]=='*' and idx<L:
                rail[i][j]=ct[idx]; idx+=1
    res=[]; row,col=0,0
    for _ in range(L):
        if row==0: dir_down=True
        if row==rails-1: dir_down=False
        if rail[row][col]!='\n': res.append(rail[row][col]); col+=1
        row = row+1 if dir_down else row-1
    return "".join(res)

def rail_fence_bruteforce(b: bytes, topn:int=3)->List[Result]:
    txt=b.decode('utf-8',errors='ignore')
    outs=[]
    for r in range(2,9):
        try:
            pt=rail_fence_decrypt(txt,r).encode()
            outs.append(Result(pt, f"railfence(rails={r})", english_score(pt)))
        except Exception: pass
    outs.sort(key=lambda r:r.score, reverse=True)
    return outs[:topn]

def scytale_decrypt(b:bytes, width:int)->bytes:
    txt=b.decode('utf-8',errors='ignore')
    if width<=0: return b
    rows = math.ceil(len(txt)/width)
    grid=['']*rows; idx=0
    for c in txt:
        grid[idx%rows]+=c; idx+=1
    return "".join(grid).encode()

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

_BACON = {
    'AAAAA':'A','AAAAB':'B','AAABA':'C','AAABB':'D','AABAA':'E','AABAB':'F','AABBA':'G','AABBB':'H',
    'ABAAA':'I','ABAAB':'J','ABABA':'K','ABABB':'L','ABBAA':'M','ABBAB':'N','ABBBA':'O','ABBBB':'P',
    'BAAAA':'Q','BAAAB':'R','BAABA':'S','BAABB':'T','BABAA':'U','BABAB':'V','BABBA':'W','BABBB':'X',
    'BBAAA':'Y','BBAAB':'Z'
}
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
    '.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
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

# ---------- Registries ----------
PHASE1_DECODERS: List[Callable[[bytes], List[Result]]] = [
    dec_hex, dec_binary,
    dec_base64, dec_base32, dec_base58, dec_base85, dec_base45, dec_base91,dec_base92,
    dec_url, dec_html,
    dec_zlib, dec_gzip, dec_bz2, dec_lzma,
    lambda b: atbash(b),
    lambda b: rot47(b),
]

def phase1_solvers(b: bytes, key_hint: Optional[bytes]) -> List[Result]:
    outs: List[Result] = []
    outs.extend(caesar_bruteforce(b, topn=4))
    outs.extend(affine_bruteforce(b, topn=6))
    outs.extend(xor_single_byte_bruteforce(b, key_hint=key_hint, topn=6))
    outs.extend(xor_repeating_key_guess(b, max_len=4, topn=3))
    outs.extend(vigenere_quick(b, key_hint=key_hint, topn=3))
    outs.extend(rail_fence_bruteforce(b, topn=3))
    # Always-on light decoders
    outs.append(Result(baconian_decrypt(b), "baconian", 0.0))
    outs.append(Result(morse_decrypt(b), "morse", 0.0))
    # Key-based variants auto-using main key if present
    if key_hint:
        key_txt = key_hint.decode('utf-8', errors='ignore')
        outs.append(Result(autokey_decrypt(b, key_txt), f"autokey(key='{key_txt}')", 0.0))
        outs.append(Result(beaufort_decrypt(b, key_txt), f"beaufort(key='{key_txt}')", 0.0))
        outs.append(Result(porta_decrypt(b, key_txt), f"porta(key='{key_txt}')", 0.0))
        digs="".join(ch for ch in key_txt if ch.isdigit())
        if digs:
            outs.append(Result(gronsfeld_decrypt(b, digs), f"gronsfeld(key='{digs}')", 0.0))
    return outs

BASE_NAMES = {"base64","base32","base58","base85","ascii85","base45","base91","base92","hex","binary","url","html","zlib","gzip","bz2","lzma","atbash","rot47"}

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

def run_phase1(b: bytes, main_re, extra_re, key_hint: Optional[bytes], debug_on: bool, flag_format: str) -> Tuple[Optional[bytes], Optional[Tuple[str,...]], PhaseStats]:
    st = PhaseStats()
    # check original blob
    hits = find_flags(b, main_re, extra_re, flag_format)
    if hits:
        st.yellow += sum(1 for h in hits if h.case!="exact")
        if any(h.case=="exact" for h in hits):
            st.exact += 1
            # print flag found for original
            for h in hits:
                if h.case=="exact":
                    print_flag(("orig",), h)
            st.ops += 1
            return b, ("orig",), st

    # run decoders
    for dec in PHASE1_DECODERS:
        try:
            reslist = dec(b)
        except Exception:
            continue
        for res in reslist:
            st.ops += 1
            if debug_on:
                eprint(cCYN(f"Trying: [{res.method}]"))
            hits = find_flags(res.data, main_re, extra_re, flag_format)
            if hits:
                st.yellow += sum(1 for h in hits if h.case!="exact")
                exact = [h for h in hits if h.case=="exact"]
                if exact:
                    st.exact += 1
                    for h in exact: print_flag((res.method,), h)
                    return res.data, (res.method,), st
                else:
                    for h in hits: print_partial((res.method,), h)

    # run classic solvers
    for res in phase1_solvers(b, key_hint):
        st.ops += 1
        if debug_on:
            eprint(cCYN(f"Trying: [{res.method}]"))
        hits = find_flags(res.data, main_re, extra_re, flag_format)
        if hits:
            st.yellow += sum(1 for h in hits if h.case!="exact")
            exact = [h for h in hits if h.case=="exact"]
            if exact:
                st.exact += 1
                for h in exact: print_flag((res.method,), h)
                return res.data, (res.method,), st
            else:
                for h in hits: print_partial((res.method,), h)

    return None, None, st

def run_combo_layers(b: bytes, main_re, extra_re, key_hint: Optional[bytes], max_depth: int, debug_on: bool, phase_name:str, flag_format: str) -> Tuple[Optional[bytes], Optional[Tuple[str,...]], PhaseStats]:
    st = PhaseStats()

    def apply_all_transforms(data: bytes) -> List[Result]:
        out: List[Result] = []
        for dec in PHASE1_DECODERS:
            try: out.extend(dec(data))
            except Exception: pass
        out.extend(caesar_bruteforce(data, topn=4))
        out.extend(affine_bruteforce(data, topn=6))
        out.extend(xor_single_byte_bruteforce(data, key_hint=key_hint, topn=6))
        out.extend(vigenere_quick(data, key_hint=key_hint, topn=2))
        out.extend(xor_repeating_key_guess(data, max_len=3, topn=2))
        out.extend(rail_fence_bruteforce(data, topn=2))
        out.append(Result(baconian_decrypt(data), "baconian", 0.0))
        out.append(Result(morse_decrypt(data), "morse", 0.0))
        if key_hint:
            key_txt = key_hint.decode('utf-8', errors='ignore')
            out.append(Result(autokey_decrypt(data, key_txt), f"autokey(key='{key_txt}')", 0.0))
            out.append(Result(beaufort_decrypt(data, key_txt), f"beaufort(key='{key_txt}')", 0.0))
            out.append(Result(porta_decrypt(data, key_txt), f"porta(key='{key_txt}')", 0.0))
            digs="".join(ch for ch in key_txt if ch.isdigit())
            if digs:
                out.append(Result(gronsfeld_decrypt(data, digs), f"gronsfeld(key='{digs}')", 0.0))
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
                        for h in hits: print_partial(chain[1:], h)

            pr = printable_ratio(res.data); ent=entropy(res.data)
            if not should_expand(res):
                continue
            if pr < 0.15 and ent < 3.0:
                continue

            hsh=(hash(res.data), chain[-1])
            if hsh in visited: continue
            visited.add(hsh)

            Q.append(Candidate(res.data, chain, node.depth+1, getattr(res,"score",0.0)))

    return None, None, st

# ---------- Interactive ----------
def interactive_flow(flag_format_cli: Optional[str], key_cli: Optional[bytes]) -> Tuple[str, bytes, Optional[bytes]]:
    flag_format = flag_format_cli or input("Enter flag format (e.g., picoctf): ").strip()
    ct_in = input("Ciphertext (text or path to file): ").strip()
    if is_file(ct_in):
        with open(ct_in, "rb") as f: ctext=f.read()
    else:
        ctext = ct_in.encode()
    # If key given via CLI, never ask again
    if key_cli is not None:
        key = key_cli
    else:
        k = input("Key/passphrase (optional; text or path): ").strip()
        key = read_value_or_file(k) if k else None
    return flag_format, ctext, key

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
    ap.add_argument("-h","--help", action="help", help="Show this help and exit")
    args = ap.parse_args()

    key_cli = read_value_or_file(args.key) if args.key else None

    if args.ciphertext is None:
        flag_format, ctext, key = interactive_flow(args.flag_format, key_cli)
    else:
        flag_format = args.flag_format or input("Enter flag format (e.g., picoctf): ").strip()
        ctext = read_value_or_file(args.ciphertext)
        if ctext is None:
            print(cYEL("Could not read ciphertext.")); sys.exit(2)
        key = key_cli  # use CLI key as-is (no prompt)

    if not flag_format:
        print(cYEL("Missing flag format (e.g., picoctf).")); sys.exit(2)

    main_re = build_main_regex(flag_format)
    extra_re = compile_extra_regex(args.extra_regex)
    debug_on = args.debug

    # ==== Phase 1 ====
    print(cCYN("=== Phase 1: single-layer ==="))
    win, chain, st1 = run_phase1(ctext, main_re, extra_re, key, debug_on, flag_format)
    phase_report_plain("Phase 1", st1)
    if win is not None:
        sys.exit(0)

    # ==== Phase 2 ====
    print(cCYN("=== Phase 2: dual-layer combinations ==="))
    win, chain, st2 = run_combo_layers(ctext, main_re, extra_re, key, max_depth=2, debug_on=debug_on, phase_name="Phase 2", flag_format=flag_format)
    phase_report_plain("Phase 2", st2)
    if win is not None:
        sys.exit(0)

    # Ask about deeper layers ONLY NOW
    allow_triple = input("Try triple-layer combos (can be slow)? (y/N): ").strip().lower().startswith('y')
    if allow_triple:
        print(cCYN("=== Phase 3: triple-layer combinations ==="))
        win, chain, st3 = run_combo_layers(ctext, main_re, extra_re, key, max_depth=3, debug_on=debug_on, phase_name="Phase 3", flag_format=flag_format)
        phase_report_plain("Phase 3", st3)
        if win is not None:
            sys.exit(0)
        allow_quad = input("Still nothing. Try quad-layer combos? (y/N): ").strip().lower().startswith('y')
        if allow_quad:
            print(cCYN("=== Phase 4: quad-layer combinations ==="))
            win, chain, st4 = run_combo_layers(ctext, main_re, extra_re, key, max_depth=4, debug_on=debug_on, phase_name="Phase 4", flag_format=flag_format)
            phase_report_plain("Phase 4", st4)
            if win is not None:
                sys.exit(0)

    print(cYEL("No exact-case flag found. Review partial matches, adjust (-k/-r), or enable deeper layers."))

    print(cCYN("\n💡 Tip:"))
    print(cYEL("If your encoded text looks like Base85 or Base92 and nothing worked here,"))
    print(cYEL("try decoding it manually in CyberChef — their implementations sometimes differ"))

    sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted."); sys.exit(130)
