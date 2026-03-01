#!/usr/bin/env python3
"""
Decrypt the AES-256-CBC config blob from cold.exe / crypted.js.

All parameters reverse-engineered via static analysis of deobfuscated.txt.
This is 100% original Python code — no malware code is included or executed.

The malware stores its C2 URL and sensitive config as an AES-256-CBC
ciphertext encrypted in the string pool (dZV0zIO), split across 4 entries.

Decryption chain (lines 1069-1082 of deobfuscated.txt):
  key  = PBKDF2-HMAC-SHA512(password, salt_b64, 100000, 32)
  data = AES-256-CBC-decrypt(ciphertext_b64, key, iv_b64)

Array rotation: Q8Uzc0p(n) = dZV0zIO[(n+267) % 314]

Confirmed string mappings (rotation R=267):
  Q8Uzc0p(59) = 'pbkdf2Sync'  [decoded idx 12]
  Q8Uzc0p(60) = 'from'        [decoded idx 13]
  Q8Uzc0p(61) = 'base64'      [decoded idx 14]
  Q8Uzc0p(62) = 'sha512'      [decoded idx 15]
  Q8Uzc0p(77) = 'createDecipheriv'  [decoded idx 30]
  Q8Uzc0p(78) + Q8Uzc0p(79) = 'aes-256-cbc'  [decoded idx 31+32]
  Q8Uzc0p(28) = 'log'         [decoded idx 295]  console.log override

Usage:
  python3 decrypt_config.py [path_to_deobfuscated.txt]
  python3 decrypt_config.py  (defaults to deobfuscated.txt in cwd)
"""

import sys
import re
import hashlib
import base64

#Cipher alphabets (same 8 as decode_strings.py)
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

ROTATION = 267   # Q8Uzc0p(n) = decoded_array[(n + ROTATION) % len(array)]

#Known decryption parameters (all confirmed statically)
# XZZwu9D = [ciphertext, password, salt, iv]
# Indices in Q8Uzc0p-space → actual decoded array indices via (n+267)%314

# Password: Q8Uzc0p(45)+Q8Uzc0p(46)+Q8Uzc0p(47)+Q8Uzc0p(48)
#   = decoded[312]+decoded[313]+decoded[0]+decoded[1]
PBKDF2_PASSWORD = 'qqkM5HynUl3Cqc3nmafzuKi+eg1PVDS4'

# Salt: Q8Uzc0p(49) = decoded[2]
PBKDF2_SALT_B64 = 'UHTaXURgNzVMwKn8jkSgiw=='

# IV: Q8Uzc0p(50)+Q8Uzc0p(51)+Q8Uzc0p(52)+Q8Uzc0p(53)
#   = decoded[3]+decoded[4]+decoded[5]+decoded[6]
AES_IV_B64 = '5lS8fyfaLAgt60BTDCM6KQ=='

# Ciphertext: Q8Uzc0p(41)+Q8Uzc0p(42)+Q8Uzc0p(43)+Q8Uzc0p(44)
#   = decoded[308]+decoded[309]+decoded[310]+decoded[311]
CIPHERTEXT_INDICES = [308, 309, 310, 311]   # in decoded array space


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


def best_decode(encoded: str) -> str:
    best_str = ""
    best_score = -1.0
    for alpha in ALPHABETS.values():
        raw = base91_decode(encoded, alpha)
        if not raw:
            continue
        printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
        score = printable / len(raw)
        if score > best_score:
            best_score = score
            try:
                best_str = raw.decode('utf-8', errors='replace')
            except Exception:
                best_str = repr(raw)
    return best_str


def parse_line57(path: str) -> list:
    print(f"[*] Opening {path} ...")
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for i, line in enumerate(f, 1):
            if i == 57:
                target = line
                break
        else:
            sys.exit("[!] Line 57 not found.")
    print(f"[*] Line 57 length: {len(target):,} chars")
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


def aes256cbc_decrypt(ciphertext_bytes: bytes, key: bytes, iv: bytes) -> bytes:
    """Pure-Python AES-256-CBC decrypt (no external deps)."""
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext_bytes)
        # PKCS#7 unpad
        pad = plaintext[-1]
        if 1 <= pad <= 16:
            plaintext = plaintext[:-pad]
        return plaintext
    except ImportError:
        pass

    # Fallback: try cryptography library
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        raw = dec.update(ciphertext_bytes) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(raw) + unpadder.finalize()
    except ImportError:
        pass

    sys.exit("[!] No AES library found. Install pycryptodome or cryptography:\n"
             "    pip install pycryptodome\n"
             "    pip install cryptography")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'deobfuscated.txt'
    entries = parse_line57(path)
    total = len(entries)
    print(f"[*] Decoding {len(CIPHERTEXT_INDICES)} ciphertext chunks ...")

    # Decode the ciphertext pieces (in decoded array space, not Q8Uzc0p space)
    ciphertext_b64 = ""
    for idx in CIPHERTEXT_INDICES:
        if idx >= total:
            sys.exit(f"[!] Index {idx} out of range (only {total} strings)")
        dec = best_decode(entries[idx])
        print(f"  [decoded[{idx:03d}]] {len(dec)} chars")
        ciphertext_b64 += dec

    print(f"[*] Total ciphertext (base64): {len(ciphertext_b64)} chars")

    # Derive AES key via PBKDF2-HMAC-SHA512
    print("[*] Deriving AES-256 key via PBKDF2-HMAC-SHA512 (100,000 iterations) ...")
    salt_bytes = base64.b64decode(PBKDF2_SALT_B64)
    iv_bytes   = base64.b64decode(AES_IV_B64)
    password_bytes = PBKDF2_PASSWORD.encode('utf-8')

    key = hashlib.pbkdf2_hmac('sha512', password_bytes, salt_bytes, 100000, dklen=32)
    print(f"[*] Derived key (hex): {key.hex()}")
    print(f"[*] IV (hex):          {iv_bytes.hex()}")

    # Decode ciphertext from base64
    try:
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
    except Exception as e:
        # Try with padding fix
        padded = ciphertext_b64 + '=' * (4 - len(ciphertext_b64) % 4)
        ciphertext_bytes = base64.b64decode(padded, validate=False)
    print(f"[*] Ciphertext bytes:  {len(ciphertext_bytes)}")

    # Decrypt
    print("[*] Decrypting with AES-256-CBC ...")
    try:
        plaintext = aes256cbc_decrypt(ciphertext_bytes, key, iv_bytes)
        print(f"\n{'=' * 65}")
        print("DECRYPTED CONFIG:")
        print("=" * 65)
        try:
            text = plaintext.decode('utf-8')
        except UnicodeDecodeError:
            text = plaintext.decode('latin-1')
        print(text)

        # Write output
        with open('decrypted_config.txt', 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"\n[+] Written to decrypted_config.txt")

        # Quick IOC scan
        ioc_patterns = [
            r'wss?://', r'https?://', r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'\.onion', r'ngrok', r'socket', r':\d{4,5}',
        ]
        import re as _re
        combined = _re.compile('|'.join(ioc_patterns), _re.IGNORECASE)
        matches = combined.findall(text)
        if matches:
            print(f"\n[+] IOC patterns found in plaintext: {set(matches)}")

    except Exception as e:
        print(f"[!] Decryption failed: {e}")
        print("[!] Possible causes:")
        print("    - Wrong password/salt/IV (double-check rotation R=267)")
        print("    - Ciphertext indices are wrong")
        print("    - Additional encoding layer")
        print(f"\n[*] Raw hex first 64 bytes of ciphertext: {ciphertext_bytes[:64].hex()}")


if __name__ == '__main__':
    main()
