# Analysis Scripts — Genesis Project Stealer

Three standalone Python scripts for static analysis of the trojanized Node.js stealer
(`f946f54953187eea89d4a1d0d5999be386bd9af0c3be0270dd42d9d28372ec27`).
No malware code is executed — all scripts perform offline decoding/decryption of
statically recovered parameters.

**Requires:** Python 3.8+, Windows or Linux. Run with `py` on Windows.

## Dependencies

| Script | stdlib modules | External package | Install |
|--------|---------------|-----------------|---------|
| `decode_strings.py` | `sys`, `re` | none | — |
| `decrypt_config.py` | `sys`, `re`, `hashlib`, `base64` | `pycryptodome` **or** `cryptography` | see below |
| `decode_layer3.py` | `sys`, `re`, `os` | none | — |

`decrypt_config.py` tries both AES libraries at runtime and falls back gracefully.
Install whichever you have available:

```
pip install pycryptodome
```
```
pip install cryptography
```

`pycryptodome` is preferred (smaller, no Rust toolchain required). If neither is
installed the script exits with an install hint rather than crashing silently.

---

## Pipeline Overview

```
cold.exe (PE binary)
  └─ pkg overlay → deobfuscated.txt      (Layer 1 output — JS with base91 string pool)
       └─ decode_strings.py              → decoded_strings.txt, iocs.txt
       └─ decrypt_config.py              → decrypted_config.txt
            └─ decode_layer3.py          → decrypted_config_layer3_decoded.txt
```

---

## decode_strings.py

**Decodes Layer 1** — the base91-encoded string pool embedded in `deobfuscated.txt`.

The Layer 1 payload is a minified JS file containing a 314-entry string array
(`dZV0zIO`) on line 57. Each entry is base91-encoded with one of 8 custom alphabets
(`WglYdj`, `lbfOUuE`, `VUKvgOC`, `XZZwu9D`, `dTUpmk`, `KCDHytJ`, `TZNFUP5`,
`eD2buMs`). The script tries all alphabets for each entry and keeps the one that
produces the highest fraction of printable ASCII.

**Usage:**
```
py decode_strings.py [path_to_deobfuscated.txt]
py decode_strings.py                              # defaults to deobfuscated.txt
```

**Output:**
- `decoded_strings.txt` — all 314 decoded strings (score ≥ 0.80), with index,
  score, and winning alphabet
- `iocs.txt` — subset matching IOC patterns (URLs, file paths, registry keys,
  browser profile paths, crypto wallet names, etc.)

**Notes:**
- All 314 strings decoded at score = 1.00 (unambiguous)
- Recovered PBKDF2 parameters (password, salt, IV) are at decoded indices 308–313
  and 2–6; these feed directly into `decrypt_config.py`
- The rotation function `Q8Uzc0p(n) = dZV0zIO[(n + 267) % 314]` maps obfuscated
  call-site indices to decoded array positions

---

## decrypt_config.py

**Decrypts Layer 2** — the AES-256-CBC encrypted inner payload recovered from
the Layer 1 string pool.

The malware concatenates four base91-decoded strings (decoded indices 308–311)
to form a base64 ciphertext, then decrypts it using a PBKDF2-HMAC-SHA512 derived
key. All parameters were statically recovered — no dynamic execution required.

**Usage:**
```
py decrypt_config.py [path_to_deobfuscated.txt]
py decrypt_config.py                              # defaults to deobfuscated.txt
```

**Output:**
- `decrypted_config.txt` — the decrypted Layer 3 JS payload (~1.2 MB, 64 lines)
- Console: derived key (hex), IV (hex), IOC pattern hits in plaintext

**Decryption parameters (statically recovered):**

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-256-CBC |
| KDF | PBKDF2-HMAC-SHA512, 100,000 iterations, dklen=32 |
| Password | `qqkM5HynUl3Cqc3nmafzuKi+eg1PVDS4` |
| Salt (b64) | `UHTaXURgNzVMwKn8jkSgiw==` |
| IV (b64) | `5lS8fyfaLAgt60BTDCM6KQ==` |
| Ciphertext | decoded indices 308–311 concatenated |

**AES library fallback order:** `pycryptodome` → `cryptography` → exit with install hint.

---

## decode_layer3.py

**Decodes Layer 3** — the second base91-encoded string pool inside `decrypted_config.txt`.

The decrypted payload contains its own obfuscation layer: a 2702-entry string pool
(`Iw2swF`) and a 1066-entry lookup table (`GyGgqCn = SFKgy2()`). Strings are decoded
at runtime by `N1hjBA(n)` which calls `vlFfqcH(Iw2swF[n])`. The file contains 60
unique 91-character alphabets; the primary is `GzASKf` (index 0), with `ALPHA_U`
used for a subset of strings.

**Usage:**
```
py decode_layer3.py [path_to_decrypted_config.txt]
py decode_layer3.py                               # defaults to decrypted_config.txt
```

**Input:** `decrypted_config.txt` (Layer 2 output) — **not** `deobfuscated.txt`.

**Output:**
- `decrypted_config_layer3_decoded.txt` — all strings decoded above 45% printable
  threshold, sorted by score, with winning alphabet name
- Console: IOC pattern hits with encoded/decoded values and provenance

**Key findings from Layer 3 decode:**

| Variable | Resolved Value | Method |
|----------|---------------|--------|
| `nqRYG4` | `genesishaha.fun` | Iw2swF[54–57] fragment assembly |
| `eIcSIM` | `https://genesishaha.fun` | 4-part n6Fj8T + wn_MBP4 assembly |
| Iw2swF[65–66] | `GENESIScrazy` | Operator handle |

C2 domain assembly (Iw2swF indices 54–57):
```
[54] 'https:'   (GzASKf alphabet)
[55] '//gene'   (ALPHA_U alphabet)
[56] 'sishah'   (GzASKf alphabet)
[57] 'a.fun'    (GzASKf alphabet)
```

**Note:** The function `eUrNEyk` in this payload is `function eUrNEyk(){return global}`
(global scope detection) — it is **not** a string decoder despite the name appearing in
the outer layer decoder script. Name collision between layers.

---

## Output Files Reference

| File | Produced by | Contents |
|------|-------------|----------|
| `decoded_strings.txt` | `decode_strings.py` | Layer 1: all 314 decoded strings |
| `iocs.txt` | `decode_strings.py` / manual | IOC candidates from all layers |
| `decrypted_config.txt` | `decrypt_config.py` | Layer 2 decrypted JS payload |
| `decrypted_config_layer3_decoded.txt` | `decode_layer3.py` | Layer 3 decoded strings |
| `deobfuscated.txt` | external (js-beautify / manual) | Layer 1 beautified JS |
