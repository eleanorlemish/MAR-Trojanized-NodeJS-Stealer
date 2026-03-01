#!/usr/bin/env python3
"""
Standalone decoder for crypted.js string array found in packaged genesis malware
Implements all 6 base91 cipher variants extracted statically from deobfuscated.txt.
This is 100% original Python code — no malware code is included or executed.

Usage:  python3 decode_strings.py [path_to_deobfuscated.txt]
Output: decoded_strings.txt  (all decoded strings, best-alphabet wins)
        iocs.txt             (filtered IOC candidates)
"""

import sys
import re

# All 6 cipher alphabets found in deobfuscated.txt
# Each is a 90-char shuffled ASCII set used as the base91 decode alphabet.
# Sources: WglYdj(L1460), lbfOUuE(L241), VUKvgOC(L494), XZZwu9D(L524),
#          dTUpmk(L551), KCDHytJ(L1202)
ALPHABETS = {
    "WglYdj":   'XBANWEYIiRCoHjLOktfFGaTceKhSJnUdqgmblQPrp]%D~uZVs[0xz6v54$/<`#2+};{!&9")y?31.w*(:,_|8=@>^M7',
    "lbfOUuE":  ':5!.`@1)}6xNCXj%BTw(|KLnF8QM^vyVSPOJ0a2"k7*<s&~u/qUr=m[Ee+GHoWfZhA,d>RD_9#g$I{Y3p4zb;i]t?cl',
    "VUKvgOC":  'l32#4yKQ!0i9"WvDCu<>Fe{`dz8jJ|,(@V.5?YwgqZGB=kaxT&^U1/L6sMtIcSbomr$~)[7%;}]*_:+HEAnPhRpfNX',
    "XZZwu9D":  'A~GBO$b4^qZM(6>z?Pm@UICt1Dp:5T,kE!c=H%vhoF7us}Qg[0`]_).KeVN9<yx/SX+"&3rnY|{J8w#RjldWLi;af2*',
    "dTUpmk":   'dYOWAB!u]Q?l[m,Thv^/a5Hti|p+zJ_e2C1V(;70nsD3xM"8P#%L{Zg&b6`*.r<j):9XNwUfKI>R}4SykEq=~$oFGc@',
    "KCDHytJ":  'bVpjfgFAlDQsJcYLdeZPrmo!xv_&")9+4=?z*w(7u:R;2`5>y,GMX[in631O$HECUS^q0aBKT}@{|W#%~]N<h/Itk.8',
    "TZNFUP5":  '.k<XFL&u*:S^`mCvtTb#+dA,n~7W;[Mzhgjy>Yol2}@4Ui/6f]HD35aB1(89GsZ%IKR=NqE$0!|OwJ"p_)x{PcrV?eQ',
    "eD2buMs":  ',9`:qFhUV63<rEMK^iC$ldX.jzJm=5g4#bRL}p8NoT(x+?~eB[IDfW*Q2G0s|{wAcS;>&)tv1!kaY@uHnO/_Z7%]"Py',
}


def base91_decode(encoded: str, alphabet: str) -> bytes:
    """
    Pure Python implementation of the WglYdj/lbfOUuE base91 decode algorithm.
    Identical logic across all 6 cipher functions — only the alphabet differs.
    """
    s = str(encoded) if encoded else ""
    out = []
    v = 0        # bit accumulator
    b = 0        # bits in accumulator
    first = -1   # first-half accumulator (-1 = waiting for first char)

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


def readability_score(data: bytes) -> float:
    """
    Score 0.0-1.0 based on what fraction of bytes are printable ASCII.
    Higher = more likely to be a real string.
    """
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data)


def try_all_alphabets(encoded: str) -> tuple:
    """
    Try all 6 alphabets. Return (best_decoded_str, best_alphabet_name, score).
    """
    best_str = ""
    best_name = "?"
    best_score = -1.0

    for name, alpha in ALPHABETS.items():
        raw = base91_decode(encoded, alpha)
        score = readability_score(raw)
        if score > best_score:
            best_score = score
            best_name = name
            try:
                best_str = raw.decode('utf-8', errors='replace')
            except Exception:
                best_str = repr(raw)

    return best_str, best_name, best_score


def extract_encoded_strings(path: str) -> list:
    """
    Reads line 57 of deobfuscated.txt and parses all quoted strings.
    Line format:  }, 1)(["enc0", "enc1", ...], 47)
    """
    print(f"[*] Opening {path} ...")
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for i, line in enumerate(f, 1):
            if i == 57:
                target = line
                break
        else:
            sys.exit("[!] Line 57 not found. Is this the right file?")

    print(f"[*] Line 57 length: {len(target):,} chars")

    # Parse all JSON-style quoted strings
    entries = []
    i = 0
    n = len(target)
    while i < n:
        if target[i] == '"':
            j = i + 1
            buf = []
            while j < n:
                c = target[j]
                if c == '\\' and j + 1 < n:
                    nc = target[j + 1]
                    esc = {'n': '\n', 'r': '\r', 't': '\t', '"': '"',
                           '\\': '\\', '/': '/', 'b': '\b', 'f': '\f'}
                    buf.append(esc.get(nc, nc))
                    j += 2
                elif c == '"':
                    break
                else:
                    buf.append(c)
                    j += 1
            entries.append(''.join(buf))
            i = j + 1
        else:
            i += 1

    print(f"[*] Parsed {len(entries)} encoded strings")
    return entries


#IOC keyword filter
IOC_PATTERNS = [
    r'https?://',
    r'wss?://',
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',   # IPv4
    r'\.onion',
    r'ngrok',
    r'AppData',
    r'\\Chrome\\',
    r'\\Firefox\\',
    r'\\Edge\\',
    r'\\Opera\\',
    r'\\Brave\\',
    r'\\Chromium\\',
    r'\\Vivaldi\\',
    r'Login Data',
    r'Cookies',
    r'Web Data',
    r'Local State',
    r'wallet',
    r'keystore',
    r'\.ldb',
    r'SELECT\s',
    r'password',
    r'secret',
    r'HKEY_',
    r'HKLM\\',
    r'HKCU\\',
    r'MachineGuid',
    r'telegram',
    r'discord',
    r'webhook',
    r'metamask',
    r'exodus',
    r'electrum',
    r'atomic',
    r'screenshot',
    r'clipboard',
    r'socket\.io',
    r'require\(',
]
IOC_RE = re.compile('|'.join(IOC_PATTERNS), re.IGNORECASE)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'deobfuscated.txt'
    entries = extract_encoded_strings(path)

    print(f"[*] Decoding with {len(ALPHABETS)} cipher alphabets, best-match wins ...")

    all_results = []
    iocs = []

    for idx, enc in enumerate(entries):
        decoded, alpha_name, score = try_all_alphabets(enc)
        all_results.append((idx, enc, decoded, alpha_name, score))
        if score >= 0.85 and IOC_RE.search(decoded):
            iocs.append((idx, enc, decoded, alpha_name, score))

        if (idx + 1) % 100 == 0:
            print(f"  ... decoded {idx + 1}/{len(entries)}")

    print(f"[+] Done. {len(iocs)} IOC candidates found.")

    # Write full results
    out_all = 'decoded_strings.txt'
    with open(out_all, 'w', encoding='utf-8') as f:
        f.write(f"# crypted.js decoded strings — {len(all_results)} total\n")
        f.write(f"# FORMAT: [INDEX] score=N.NN (alphabet)  decoded_value\n\n")
        for idx, enc, dec, aname, score in all_results:
            if score >= 0.80:   # only write plausibly decoded strings
                f.write(f"[{idx:04d}] score={score:.2f} ({aname})\n")
                f.write(f"  decoded: {dec!r}\n")
                f.write(f"  encoded: {enc[:80]}\n\n")
    print(f"[+] All readable strings → {out_all}")

    # Write IOC report
    out_ioc = 'iocs.txt'
    with open(out_ioc, 'w', encoding='utf-8') as f:
        f.write(f"# IOC candidates from crypted.js — {len(iocs)} found\n\n")
        for idx, enc, dec, aname, score in iocs:
            f.write(f"[{idx:04d}] (score={score:.2f}, cipher={aname})\n")
            f.write(f"  {dec}\n\n")
    print(f"[+] IOC report → {out_ioc}")

    # Stdout summary — IOCs
    print("\n" + "=" * 65)
    print(f"IOC CANDIDATES ({len(iocs)}):")
    print("=" * 65)
    for idx, enc, dec, aname, score in iocs:
        print(f"  [{idx:04d}] {dec}")

    # Print ALL 314 decoded strings
    print(f"\n{'=' * 65}")
    print(f"ALL {len(all_results)} DECODED STRINGS:")
    print("=" * 65)
    for idx, enc, dec, aname, score in all_results:
        print(f"  [{idx:04d}] score={score:.2f} ({aname}) {dec!r}")

    # Try to find URL by concatenating adjacent strings at key indices
    print(f"\n{'=' * 65}")
    print("URL ASSEMBLY ATTEMPT (indices 85-95, 119-125):")
    print("=" * 65)
    url_indices = list(range(85, 96)) + list(range(119, 126))
    for i in url_indices:
        if i < len(all_results):
            idx, enc, dec, aname, score = all_results[i]
            print(f"  [{idx:04d}] {dec!r}")
    concat_85_95 = ''.join(all_results[i][2] for i in range(85, min(96, len(all_results))))
    print(f"\n  Concat [85-95]: {concat_85_95!r}")

    # PBKDF2 params
    print(f"\n{'=' * 65}")
    print("PBKDF2 PARAMS (indices 40-55):")
    print("=" * 65)
    for i in range(40, min(56, len(all_results))):
        idx, enc, dec, aname, score = all_results[i]
        print(f"  [{idx:04d}] score={score:.2f}  {dec!r}")

    # Module names area
    print(f"\n{'=' * 65}")
    print("MODULE NAME AREA (indices 120-170):")
    print("=" * 65)
    for i in range(120, min(171, len(all_results))):
        idx, enc, dec, aname, score = all_results[i]
        print(f"  [{idx:04d}] score={score:.2f}  {dec!r}")


if __name__ == '__main__':
    main()
