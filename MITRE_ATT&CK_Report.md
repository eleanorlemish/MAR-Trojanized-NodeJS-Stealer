# MITRE ATT&CK Report — cold.exe (crypted.js)

**Sample:** `cold.exe` — Node.js infostealer packaged with `pkg`
**Inner payload:** `crypted.js` → AES-256-CBC encrypted `decrypted_config.txt` (three-layer obfuscation)
**Analysis date:** 2026-02-28
**Status:** Layer 1 + 2 + 3 statically analyzed. Primary C2 domain (`nqRYG4`) pending decode by `decode_layer3.py` on airgapped Linux.

---

## Sample Overview

`cold.exe` is a **Node.js infostealer** bundled using the `pkg` tool. It is branded/attributed to the **Genesis Project** (Telegram: `t.me/genesisproject`).

The virtual filesystem is embedded at `C:\snapshot\builder\` inside the PE, with `crypted.js` as the primary payload.

**Packaging artifacts (OPSEC leaks):**
- CI build path: `C:\Users\runneradmin\AppData\Local\Temp\pkg.24e0b2b2d51e47b9dba34c30\` (GitHub Actions runner)
- Developer artifact: username `devetry` in screenshot-desktop example path

**Three obfuscation layers confirmed:**
1. **Layer 1** — Custom 8-table base91 cipher (`dZV0zIO`, 314 strings) with rotation R=267 (`Q8Uzc0p`)
2. **Layer 2** — AES-256-CBC encrypted config blob (PBKDF2-HMAC-SHA512, 100k iterations). Parameters statically recovered. Decrypted by `decrypt_config.py`.
3. **Layer 3** — Another obfuscated JS module (`Iw2swF` string pool, `GyGgqCn`/`SFKgy2()` constant array, `QMHVrQo` lookup). Layer-3 decoder script: `decode_layer3.py`.

---

## MITRE ATT&CK Techniques

### Initial Access
| Technique | ID | Evidence |
|-----------|-----|---------|
| Phishing / Malvertising | T1566 | Executable delivered as a fake application |

---

### Execution
| Technique | ID | Evidence |
|-----------|-----|---------|
| User Execution: Malicious File | T1204.002 | Victim executes cold.exe directly |
| Command and Scripting Interpreter: JavaScript | T1059.007 | Entire payload is Node.js/V8 JavaScript inside pkg binary |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | `child_process` module used for shell commands; `REG.exe QUERY` for registry reads |
| System Binary Proxy Execution | T1218 | `screenCapture_1.3.2.bat` helper with `app.manifest` for screen capture on Win32 |

---

### Persistence
| Technique | ID | Evidence |
|-----------|-----|---------|
| (Pending C2 decode) | T1547 | Likely startup persistence — method TBD after IOC recovery |

---

### Defense Evasion
| Technique | ID | Evidence |
|-----------|-----|---------|
| Obfuscated Files or Information | T1027 | Triple-layer obfuscation: 8 custom base91 cipher tables + string rotation + AES-256-CBC encrypted payload + third base91 layer |
| Obfuscated Files or Information: Software Packing | T1027.002 | `pkg` bundles Node.js runtime + modules into single PE |
| Obfuscated Files or Information: Indicator Removal from Tools | T1027.005 | All module names, URLs, file paths encoded in string pool across all 3 layers |
| Indicator Removal: Disable or Modify Tools | T1562 | `console.log`, `console.warn`, `console.error` all overridden to `() => undefined` (deobfuscated.txt line 838+) |
| Virtualization/Sandbox Evasion | T1497 | `PBVNru1.hdcTjF()` / `PBVNru1.CP3vO2` guard conditions on most branches — anti-debug/anti-analysis checks |
| Masquerading | T1036 | Electron/Node.js app with legitimate-looking UI |
| Hide Artifacts | T1564 | Console output suppressed; no visible windows from background stealer thread |
| Control Flow Flattening | T1027 | `while(state_sum != target) { switch(state_sum) { ... } }` pattern throughout crypted.js |
| Encrypted Payload | T1027.002 | Layer 2 payload (decrypted_config.txt) encrypted with AES-256-CBC + PBKDF2-HMAC-SHA512 key derivation |

---

### Credential Access
| Technique | ID | Evidence |
|-----------|-----|---------|
| Credentials from Web Browsers | T1555.003 | `sqlite3` reads browser Login Data / Cookies / Local Storage; `@primno/dpapi` for Windows DPAPI master key decryption; targets Chrome, Firefox, Opera, Chromium |
| OS Credential Dumping: DPAPI | T1003.005 | `@primno/dpapi` native module — decrypts Windows DPAPI-protected browser master key |
| Steal Web Session Cookie | T1539 | SQLite queries against Cookies database; `Local Storage` directory traversal confirmed in plaintext |
| Unsecured Credentials: Credentials In Files | T1552.001 | File system traversal (`fast-glob`/`readdir-glob`) targeting credential-adjacent files |

---

### Discovery
| Technique | ID | Evidence |
|-----------|-----|---------|
| System Information Discovery | T1082 | `REG.exe QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid`; `require('os')` (Yw7Qns5) for system info; `LOCALAPPDATA` env var accessed |
| Hardware Fingerprinting | T1082 | `node-machine-id` (`FdzLvb`) for unique machine ID |
| File and Directory Discovery | T1083 | `fast-glob` + `readdir-glob` recursive filesystem traversal; `fs-extra` (Uq2qZ2p) |
| Process Discovery | T1057 | `OpenProcessToken` — process token enumeration |
| Software Discovery: Browser Extensions | T1518.001 | Chromium, Firefox, Opera targeted for credential and session data |
| Query Registry | T1012 | `REG.exe QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography` |
| Account Discovery | T1087 | Discord API calls (v8/v9/v10) — `GET /users/@me/profile`, guild enumeration |

---

### Collection
| Technique | ID | Evidence |
|-----------|-----|---------|
| Screen Capture | T1113 | `screenshot-desktop` (`AumgXm`) + Win32 helper `screenCapture_1.3.2.bat` + `app.manifest`; `jimp` image processing (`ZRC2ren`); smart diffing with `pixelmatch` |
| Clipboard Data | T1115 | `copyToClipboard` function referenced |
| Data from Local System | T1005 | `fast-glob`/`readdir-glob` recursive glob traversal; `fs-extra` file read operations |
| Data from Information Repositories: Browser | T1213 | SQLite queries against Chrome/Firefox/Edge/Opera Login Data, Cookies, Web Data, Local Storage |
| Archive Collected Data: Archive via Library | T1560.002 | `adm-zip` + `archiver` — creates ZIP archives of stolen data; `brotli`/`zlib` (QVqTkIh/pDNvXZ) for compression |
| Email Collection | T1114 | `exif-parser` + `file-type` for media/document exfiltration scanning |
| Data Staged | T1074 | Staging using `temp` module; `path.join` paths under temp directory (iiE8Fn = require('path')) |
| Input Capture | T1056 | Clipboard monitoring confirmed |

---

### Command and Control
| Technique | ID | Evidence |
|-----------|-----|---------|
| Application Layer Protocol: Web Protocols | T1071.001 | `socket.io-client` (`LUnohV2`) — persistent WebSocket C2 with HTTP fallback; `axios` (`air3U0`) for HTTP API calls |
| Application Layer Protocol: File Transfer Protocols | T1071.002 | `gofile.io` used for file exfiltration (public upload service) |
| Encrypted Channel | T1573 | WebSocket over WSS (TLS); `ws` module |
| Protocol Tunneling / Fallback Channels | T1572 | engine.io transport chain: WebSocket → HTTP long-polling → HTTP3 |
| Dynamic Resolution | T1568 | Primary C2 domain (`nqRYG4`) assembled at runtime from 3+ concatenated encoded string fragments — prevents static extraction. `eIcSIM` (socket.io URL) assembled from 4 encoded fragments |
| Data Encoding: Standard Encoding | T1132.001 | MsgPack binary serialization for C2 traffic (`socket.io.msgpack.min.js`) |
| Web Service: Dead Drop Resolver | T1102.001 | `code-api.xyz` used to host stolen Discord tokens as retrievable links; `t.me/genesisproject` for operator alerting |

---

### Exfiltration
| Technique | ID | Evidence |
|-----------|-----|---------|
| Exfiltration Over C2 Channel | T1041 | Data exfiltrated via socket.io C2 (`stream-meter` for transfer metering); `POST https://api.${nqRYG4}/send-embed` and `/send-embed-viewer` endpoints |
| Exfiltration to Cloud Storage | T1567.002 | `gofile.io/uploadFile` — public file exfil; Discord embed data via `api.${nqRYG4}/send-embed` (webhook-like mechanism) |
| Automated Exfiltration | T1020 | `pixelmatch`-based smart screenshot diffing — only changed frames exfiltrated |
| Data Transfer Size Limits | T1030 | `stream-meter` module measures and limits transfer sizes |

---

## Confirmed IOCs (Layer 3 Static Analysis)

### Threat Actor Infrastructure
| IOC | Type | Confirmed Method |
|-----|------|-----------------|
| `code-api.xyz` | C2 domain (token exfil) | **Plaintext in decrypted_config.txt** |
| `t.me/genesisproject` | Telegram channel (Genesis Project) | **Plaintext in decrypted_config.txt** |
| `gofile.io` | File exfil service | **Plaintext in decrypted_config.txt** |
| `https://code-api.xyz/?p=${TOKEN}` | Token exfil URL pattern | **Plaintext in decrypted_config.txt** |
| `nqRYG4` | Primary C2 domain (obfuscated) | Assembled from encoded fragments — **decode_layer3.py required** |
| `eIcSIM` | Socket.io C2 URL (obfuscated) | Assembled from encoded fragments — **decode_layer3.py required** |

### C2 API Paths (Confirmed Plaintext)
- `https://${nqRYG4}/paths` — configuration/tasking endpoint
- `https://api.${nqRYG4}/send-embed` — data exfiltration endpoint
- `https://api.${nqRYG4}/send-embed-viewer` — rich-data exfiltration endpoint

### Target Services Accessed
- `discord.com/api/v10/users/${id}/profile` — Discord user profiling
- `discord.com/api/v8/guilds/${id}/invites` — Discord guild enumeration
- `discord.com/api/v9/users/${id}/profile` — Discord user profiling (v9)
- `cdn.discordapp.com/avatars/` — Discord avatar fetching
- `discord.gg/` — Discord invite link enumeration

### Build Artifacts
- CI build path: `C:\Users\runneradmin\AppData\Local\Temp\pkg.24e0b2b2d51e47b9dba34c30\`
- Developer username: `devetry`
- Payload filename: `crypted.js`
- Virtual FS root: `C:\snapshot\builder\`

---

## Layer 2 Decryption Parameters (Statically Recovered)

**Located at deobfuscated.txt lines 1069–1082. Decrypted by `decrypt_config.py`.**

| Parameter | Value | Source |
|-----------|-------|--------|
| Algorithm | AES-256-CBC | `Q8Uzc0p(78)+Q8Uzc0p(79)` → `aes-256-cbc` |
| PBKDF2 hash | SHA-512 | `Q8Uzc0p(62)` → `sha512` |
| PBKDF2 iterations | 100,000 | Hardcoded |
| PBKDF2 key length | 32 bytes | Hardcoded |
| **Password** | `qqkM5HynUl3Cqc3nmafzuKi+eg1PVDS4` | `decoded[312]+[313]+[0]+[1]` |
| **Salt (b64)** | `UHTaXURgNzVMwKn8jkSgiw==` | `decoded[2]` |
| **IV (b64)** | `5lS8fyfaLAgt60BTDCM6KQ==` | `decoded[3]+[4]+[5]+[6]` |
| Ciphertext | `decoded[308]+[309]+[310]+[311]` | 4 long b64 strings |

*Note: This decrypts the inner JS payload (Layer 3), NOT browser credentials. Browser credential decryption uses DPAPI + `@primno/dpapi`.*

---

## Module Inventory (from Layer 3 plaintext require() calls)

| Variable | Module | Purpose | MITRE |
|----------|--------|---------|-------|
| `LUnohV2` | `socket.io-client` | WebSocket C2 persistent connection | T1071.001 |
| `air3U0` | `axios` | HTTP API exfiltration | T1041 |
| `pDNvXZ` | `brotli` | Data compression | T1560 |
| `Uq2qZ2p` | `fs` | File system access | T1005 |
| `QVqTkIh` | `zlib` | Data compression | T1560 |
| `vWPeYM2` | `form-data` | HTTP multipart exfil | T1041 |
| `z1gUogW` | `@primno/dpapi` | Windows DPAPI decryption | T1003.005 |
| `iiE8Fn` | `path` | File path manipulation | T1005 |
| `JeCwPU` | `crypto` | AES credential decryption | T1555.003 |
| `FdzLvb` | `node-machine-id` | Hardware fingerprinting | T1082 |
| `AumgXm` | `screenshot-desktop` | Screen capture | T1113 |
| `ZRC2ren` | `jimp` | Image processing | T1113 |
| `Yw7Qns5` | `os` | System info | T1082 |
| — | `sqlite3` | Browser DB access | T1555.003 |
| — | `adm-zip` | Archive creation | T1560.002 |
| — | `archiver` | Archive creation | T1560.002 |
| — | `child_process` | Shell command execution | T1059.003 |
| — | `fs-extra` | Extended file system ops | T1005 |
| — | `@primno/dpapi` | Windows credential DPAPI | T1003.005 |
| — | `@redacted/enterprise-plugin` | Supply chain masquerade? | T1195 |

---

## Anti-Analysis Techniques (Confirmed)

1. **Console suppression** — `console.log/warn/error = () => undefined` on load
2. **Control flow flattening** — arithmetic state machine pattern throughout
3. **Layer 1: 8-table base91 cipher** — 314 strings in `dZV0zIO`, rotation R=267 (`Q8Uzc0p`)
   - Alphabets: WglYdj, lbfOUuE, VUKvgOC, XZZwu9D, dTUpmk, KCDHytJ, TZNFUP5, eD2buMs
4. **Layer 2: AES-256-CBC payload encryption** — PBKDF2-HMAC-SHA512, 100k iterations
5. **Layer 3: Second base91 cipher** — `Iw2swF` string pool, two alphabets (`vlFfqcH`, `UGb1iHg`)
   - `QMHVrQo(n) = GyGgqCn[n > 68 ? n-69 : n+77]` two-piece rotation
6. **All require() calls encoded** — module names only appear after decode
7. **C2 URL split across multiple decoded string fragments** — `eIcSIM` and `nqRYG4` assembled at runtime
8. **Anti-debug guards** — `PBVNru1.hdcTjF()` / `PBVNru1.CP3vO2 > -89` conditions

---

## Analysis Scripts

| Script | Purpose | Status |
|--------|---------|--------|
| `decode_strings.py` | Layer 1: Decode 8-table base91 string pool | Done — run on Linux |
| `decrypt_config.py` | Layer 2: AES-256-CBC decrypt of config blob | Done — decrypted_config.txt produced |
| `decode_layer3.py` | Layer 3: Decode Iw2swF string pool, extract C2 domain | **Ready — run on Linux** |

---

## Next Steps

1. **Run `decode_layer3.py` on airgapped Linux** against `decrypted_config.txt`:
   - Should recover `nqRYG4` (primary C2 domain) and `eIcSIM` (socket.io URL)
   - Will dump all decoded strings for IOC review
2. **Submit confirmed IOCs to threat intel:**
   - `code-api.xyz` → VirusTotal, URLscan.io, Shodan
   - `t.me/genesisproject` → check Genesis Project threat actor profiles
   - Primary C2 domain (once decoded) → Shodan lookup for exposed services
3. **Check VirusTotal** for `cold.exe` hash → cross-reference with Genesis Stealer family
4. **Yara rule targets:**
   - PBKDF2 password string: `qqkM5HynUl3Cqc3nmafzuKi+eg1PVDS4`
   - Salt: `UHTaXURgNzVMwKn8jkSgiw==`
   - Domain: `code-api.xyz`
   - Telegram: `t.me/genesisproject`
