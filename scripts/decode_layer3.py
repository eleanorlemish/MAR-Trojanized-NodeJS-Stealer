#!/usr/bin/env python3
"""
Decode the third obfuscation layer in decrypted_config.txt.

Layer 3 is the payload unpacked by AES-256-CBC. It has its own string pool
(Iw2swF) and lookup table (GyGgqCn = SFKgy2()) with a two-piece rotation:

  QMHVrQo(n) = GyGgqCn[n > 0x44 ? n-0x45 : n+0x4d]

Four base91 alphabets found by static analysis:
  vlFfqcH  — primary decoder (used by default in N1hjBA)
  UGb1iHg  — alternate decoder (passed explicitly in some calls)
  eUrNEyk1 — first variant found in eUrNEyk() function
  eUrNEyk2 — second variant found in eUrNEyk() function

Strategy: extract ALL single-quoted strings from the file, try all known
alphabets, keep anything that decodes to >45% printable ASCII, then
scan for IOC patterns.

Usage:
  python3 decode_layer3.py [path_to_decrypted_config.txt]
"""

import sys
import re
import os

#Alphabets from static analysis
ALPHA_V  = 'x1.?^"rW;Qqfk`2aj*=bZ4!D_G<w+MPtT5d$OKXV}HE:68C|~&RiI9/z7,]YSUB%yJcvA#hNupn>F{Le()@o0ls3[gm'
ALPHA_U  = 'Aot`upN{vVrJ5Plwg4_LsBbCDZx%Y"?6=ne]c/,yzK&i^$>EX:OF<0I@}#81d~|Q7[WGm+qUH.(!9*)23;TkfjahMSR'
# eUrNEyk function — two alphabet variants found in decrypted_config.txt
ALPHA_E1 = '<x3}lDe&C%SvmfV8F:o*;4+2rz6~XMw0^B,=5Z$H/9p`Wy{uAk)GjRnKJcgYQtsU]7i@?E|hbd(_T![a>I"N1#LP.Oq'
ALPHA_E2 = '<!=*w{)LD?%>YlWGfd64#p9$u(|AX+OUBQyCN}IHcir2J_3E,81ez.Rn@o]t0qS&V~ax:vK7"FPT;^hmZsM5bg/`[kj'

# Outer layer alphabets (reuse from decode_strings.py in case SFKgy2 strings
# use the same encoding)
OUTER_ALPHABETS = {
    "WglYdj":  'XBANWEYIiRCoHjLOktfFGaTceKhSJnUdqgmblQPrp]%D~uZVs[0xz6v54$/<`#2+};{!&9")y?31.w*(:,_|8=@>^M7',
    "lbfOUuE": ':5!.`@1)}6xNCXj%BTw(|KLnF8QM^vyVSPOJ0a2"k7*<s&~u/qUr=m[Ee+GHoWfZhA,d>RD_9#g$I{Y3p4zb;i]t?cl',
    "VUKvgOC": 'l32#4yKQ!0i9"WvDCu<>Fe{`dz8jJ|,(@V.5?YwgqZGB=kaxT&^U1/L6sMtIcSbomr$~)[7%;}]*_:+HEAnPhRpfNX',
    "XZZwu9D": 'A~GBO$b4^qZM(6>z?Pm@UICt1Dp:5T,kE!c=H%vhoF7us}Qg[0`]_).KeVN9<yx/SX+"&3rnY|{J8w#RjldWLi;af2*',
    "dTUpmk":  'dYOWAB!u]Q?l[m,Thv^/a5Hti|p+zJ_e2C1V(;70nsD3xM"8P#%L{Zg&b6`*.r<j):9XNwUfKI>R}4SykEq=~$oFGc@',
    "KCDHytJ": 'bVpjfgFAlDQsJcYLdeZPrmo!xv_&")9+4=?z*w(7u:R;2`5>y,GMX[in631O$HECUS^q0aBKT}@{|W#%~]N<h/Itk.8',
    "TZNFUP5": '.k<XFL&u*:S^`mCvtTb#+dA,n~7W;[Mzhgjy>Yol2}@4Ui/6f]HD35aB1(89GsZ%IKR=NqE$0!|OwJ"p_)x{PcrV?eQ',
    "eD2buMs": ',9`:qFhUV63<rEMK^iC$ldX.jzJm=5g4#bRL}p8NoT(x+?~eB[IDfW*Q2G0s|{wAcS;>&)tv1!kaY@uHnO/_Z7%]"Py',
}

ALL_ALPHABETS = [ALPHA_V, ALPHA_U, ALPHA_E1, ALPHA_E2] + list(OUTER_ALPHABETS.values())


#Base91 decoder (same algorithm as outer layers)
def base91_decode(encoded: str, alphabet: str) -> bytes:
    s = str(encoded) if encoded else ""
    out = []
    v = 0
    b = 0
    first = -1
    for ch in s:
        pos = alphabet.find(ch)
        if pos == -1:
            continue
        if first < 0:
            first = pos
        else:
            val = first + pos * 91
            v |= val << b
            b += 13 if (val & 8191) > 88 else 14
            while b > 7:
                out.append(v & 255)
                v >>= 8
                b -= 8
            first = -1
    if first > -1:
        out.append((v | first << b) & 255)
    return bytes(out)


ALPHA_NAMES = ['vlFfqcH', 'UGb1iHg', 'eUrNEyk1', 'eUrNEyk2'] + list(OUTER_ALPHABETS.keys())


def best_decode(encoded: str) -> tuple:
    """Try all alphabets, return (decoded_str, score, alphabet_name)."""
    best_str = encoded
    best_score = -1.0
    best_alpha = 'none'
    for name, alpha in zip(ALPHA_NAMES, ALL_ALPHABETS):
        raw = base91_decode(encoded, alpha)
        if not raw:
            continue
        printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
        score = printable / len(raw)
        if score > best_score:
            best_score = score
            best_alpha = name
            # Try UTF-8, fall back to Latin-1 (every byte is valid Latin-1)
            decoded = raw.decode('utf-8', errors='replace')
            if '\ufffd' in decoded:
                decoded = raw.decode('latin-1')
            best_str = decoded
    return best_str, best_score, best_alpha


#Extract all single-quoted strings from the file
def extract_quoted_strings(text: str) -> list:
    """Pull all 'string literals' from minified JS, handling escapes."""
    results = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "'":
            j = i + 1
            buf = []
            while j < n:
                c = text[j]
                if c == '\\' and j + 1 < n:
                    nc = text[j + 1]
                    esc = {'n': '\n', 'r': '\r', 't': '\t', "'": "'",
                           '\\': '\\', '/': '/', 'b': '\b', 'f': '\f',
                           '"': '"'}
                    buf.append(esc.get(nc, nc))
                    j += 2
                elif c == "'":
                    break
                else:
                    buf.append(c)
                    j += 1
            s = ''.join(buf)
            if len(s) >= 3:   # skip very short strings
                results.append(s)
            i = j + 1
        else:
            i += 1
    return results


# IOC scanner
IOC_PATTERNS = [
    (re.compile(r'wss?://[^\s\'"]{4,}', re.I), 'WebSocket URL'),
    (re.compile(r'https?://[^\s\'"]{4,}', re.I), 'HTTP URL'),
    (re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?'), 'IP:port'),
    (re.compile(r'[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.(?:onion|io|com|net|org|xyz|ru|cc|to|tk|pw)(?::\d{2,5})?', re.I), 'domain'),
    (re.compile(r'/socket\.io', re.I), 'socket.io path'),
    (re.compile(r'ngrok|localhost|127\.0\.0|0\.0\.0\.0', re.I), 'local/tunnel'),
    (re.compile(r'discord(?:app)?\.com|telegram', re.I), 'exfil service'),
]


def scan_iocs(text: str) -> list:
    found = []
    for pat, label in IOC_PATTERNS:
        for m in pat.finditer(text):
            found.append((label, m.group()))
    return found


#Main
def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'decrypted_config.txt'
    print(f"[*] Reading {path} ...")
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    print(f"[*] File size: {len(content):,} chars, reading strings ...")

    strings = extract_quoted_strings(content)
    print(f"[*] Extracted {len(strings):,} quoted strings (len>=3)")
    unique = list(dict.fromkeys(strings))  # deduplicate, preserving order
    print(f"[*] Unique strings: {len(unique):,}")

    # Decode and filter
    SCORE_THRESHOLD = 0.45   # require 45% printable (extended ASCII common in obfuscated JS)
    MIN_LEN = 3              # minimum decoded length

    decoded_results = []
    ioc_hits = []

    print(f"[*] Decoding with {len(ALL_ALPHABETS)} alphabets (threshold={SCORE_THRESHOLD:.0%}) ...")
    print(f"[*] Alphabets: {', '.join(ALPHA_NAMES)}")
    for raw in unique:
        decoded, score, alpha = best_decode(raw)
        if score >= SCORE_THRESHOLD and len(decoded) >= MIN_LEN:
            decoded_results.append((raw, decoded, score, alpha))
            iocs = scan_iocs(decoded)
            if iocs:
                ioc_hits.append((raw, decoded, score, alpha, iocs))

    print(f"[*] Decoded {len(decoded_results):,} strings above threshold")

    # Write all decoded strings
    out_all = path.replace('.txt', '_layer3_decoded.txt')
    with open(out_all, 'w', encoding='utf-8') as f:
        f.write(f"# Layer 3 decoded strings — {len(decoded_results)} results\n")
        f.write(f"# Format: [score] [alpha] encoded → decoded\n\n")
        for raw, dec, score, alpha in sorted(decoded_results, key=lambda x: -x[2]):
            f.write(f"[{score:.2f}][{alpha}] {repr(raw)}\n  → {repr(dec)}\n\n")
    print(f"[+] All decoded strings written to: {out_all}")

    # Print IOC hits
    if ioc_hits:
        print(f"\n{'='*65}")
        print(f"!!! {len(ioc_hits)} IOC MATCHES FOUND !!!")
        print('='*65)
        for raw, dec, score, alpha, iocs in ioc_hits:
            print(f"\n  Encoded: {raw[:80]}")
            print(f"  Decoded: {dec}")
            print(f"  Score:   {score:.2f} ({alpha})")
            print(f"  IOCs:    {iocs}")
    else:
        print("\n[!] No IOC patterns found in decoded strings.")
        print("[!] The C2 URL may be:")
        print("    1. Assembled from multiple decoded pieces at runtime")
        print("    2. Encoded with an additional unknown alphabet")
        print("    3. Hidden in the GyGgqCn constant array (plain values)")

    # Also dump strings just below threshold for manual review
    print(f"\n[*] Strings decoding to 30-45% printable (manual review):")
    below = []
    for raw in unique:
        decoded, score, alpha = best_decode(raw)
        if 0.30 <= score < SCORE_THRESHOLD and len(decoded) > 8:
            below.append((score, alpha, decoded))
    for score, alpha, decoded in sorted(below, key=lambda x: -x[0])[:50]:
        print(f"  [{score:.2f}][{alpha}] {decoded[:120]}")

    # Scan the raw content itself for any plaintext IOCs (sanity check)
    raw_iocs = scan_iocs(content)
    if raw_iocs:
        print(f"\n[!] Plaintext IOCs in raw file (not base91-encoded):")
        for label, val in set(raw_iocs):
            print(f"  [{label}] {val}")

    print("\n[*] Done.")


if __name__ == '__main__':
    main()
