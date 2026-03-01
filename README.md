# Malware Analysis Report: Trojanized Node.js Stealer (pokemoncraft.com)

**Author:** Eleanor R. Lemish — Independent Security Researcher  
**Date:** February 28, 2026  
**TLP:** GREEN — May be shared within the cybersecurity community  
**Attribution:** Genesis Project / GENESIScrazy (`t.me/genesisproject`)

---

## Overview

This repository contains a detailed malware analysis report for a trojanized Node.js information stealer attributed to the **Genesis Project** threat actor group (operator handle: **GENESIScrazy**), distributed via **pokemoncraft.com** — a fake game mod website promoted through Discord social engineering.

The sample is a **76.68 MB Windows PE (x64)** binary built using the `pkg` npm module. At the time of analysis, only **2 of 69** VirusTotal vendors flagged it as malicious.

**All three obfuscation layers were statically defeated**, revealing the confirmed C2 domain (`genesishaha.fun`), exfiltration endpoints, operator handle (`GENESIScrazy`), and the complete module inventory with deobfuscated variable mappings.

📄 **[Read the full report (PDF)](MAR_Trojanized_NodeJS_Stealer.pdf)**

---

## Key Findings

- **Threat Actor:** Genesis Project / GENESIScrazy (`t.me/genesisproject`) — commercial stealer/RAT service
- **Delivery:** Discord social engineering → pokemoncraft.com → trojanized game mod installer
- **Packing:** `pkg` npm module bundles Node.js v18.5.0 runtime + payload into single PE; 42 MB overlay
- **Obfuscation:** Three-layer architecture:
  - **Layer 1:** 8-table base91 cipher (314 strings, rotation R=267)
  - **Layer 2:** AES-256-CBC encrypted payload (PBKDF2-HMAC-SHA512, 100k iterations) — parameters statically recovered
  - **Layer 3:** Second base91 cipher (2 tables, two-piece rotation) — C2 domain assembled from encoded fragments
- **C2:** `genesishaha.fun` — socket.io over WSS with MsgPack binary serialization; three-layer transport fallback (WebSocket → HTTP long-polling → WebTransport/HTTP/3); C2 URL assembled from 3-4 encoded fragments at runtime (T1568)
- **Credential Theft:** DPAPI decryption (`@primno/dpapi`) + SQLite3 access to Chrome/Firefox/Opera/Edge databases
- **Discord Theft:** Token theft + API v8/v9/v10 user profiling and guild enumeration
- **Screen Capture:** `screenshot-desktop` with `pixelmatch` change detection — only exfiltrates changed frames
- **Exfiltration:** Multi-channel: socket.io C2, `gofile.io` (file upload), `code-api.xyz` (token storage), Discord embeds
- **Anti-Forensics:** Self-deleting installer; console output suppressed; anti-debug guards; control flow flattening; `rundll32.exe` + `user32.dll` proxy execution

---

## Sample Identification

| Property | Value |
|----------|-------|
| **SHA-256** | `f946f54953187eea89d4a1d0d5999be386bd9af0c3be0270dd42d9d28372ec27` |
| **MD5** | `d1f00db7c12af85563c19765def85e1b` |
| **SHA-1** | `b033c0ed7a98c43f365ed924e465f3732913c8d6` |
| **Imphash** | `4d0fb8dc9ee470058274f448bebbb85f` |
| **File Size** | 76.68 MB (80,402,188 bytes) |
| **Signature** | Unsigned |
| **VT Detection** | 2/69 (2026-02-26) |
| **Attribution** | Genesis Project / GENESIScrazy |
| **VirusTotal** | [View on VirusTotal](https://www.virustotal.com/gui/file/f946f54953187eea89d4a1d0d5999be386bd9af0c3be0270dd42d9d28372ec27) |

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|------------|
| **Initial Access** | T1566 (Phishing/Malvertising) |
| **Execution** | T1204.002 (User Execution), T1059.007 (JavaScript), T1059.003 (Windows Cmd), T1106 (Native API), T1218 (System Binary Proxy), T1218.011 (Rundll32) |
| **Defense Evasion** | T1027 (Obfuscation), T1027.002 (Packing), T1027.005 (Indicator Removal from Tools), T1027.013 (Encrypted/Encoded File), T1140 (Runtime Deobfuscation), T1070.004 (File Deletion), T1562 (Disable Tools), T1497 (Sandbox Evasion), T1036 (Masquerading), T1564 (Hide Artifacts) |
| **Credential Access** | T1555.003 (Browser Credentials), T1003.005 (DPAPI), T1539 (Session Cookies), T1552.001 (Credentials in Files) |
| **Discovery** | T1082 (System Info), T1016 (Network Config Discovery), T1083 (File/Dir Discovery), T1057 (Process Discovery), T1518.001 (Browser Extensions), T1012 (Query Registry), T1087 (Account Discovery) |
| **Collection** | T1113 (Screen Capture), T1115 (Clipboard), T1005 (Local System), T1213 (Info Repositories), T1560.002 (Archive via Library), T1074 (Data Staged), T1056 (Input Capture) |
| **C2** | T1071.001 (Web Protocols), T1071.002 (File Transfer), T1008 (Fallback Channels), T1573 (Encrypted Channel), T1568 (Dynamic Resolution), T1132.001 (Data Encoding), T1102.001 (Dead Drop Resolver) |
| **Exfiltration** | T1041 (Over C2), T1567.002 (Cloud Storage), T1020 (Automated), T1030 (Size Limits) |

---

## Confirmed IOCs

### Threat Actor Infrastructure
| IOC | Type | Status |
|-----|------|--------|
| `genesishaha.fun` | Primary C2 domain | **Confirmed — Layer 3 decoded** |
| `https://genesishaha.fun` | Socket.io C2 base URL | **Confirmed — Layer 3 decoded** |
| `code-api.xyz` | C2 domain (token exfil) | **Confirmed plaintext** |
| `https://code-api.xyz/?p=${TOKEN}` | Token exfil URL pattern | **Confirmed plaintext** |
| `t.me/genesisproject` | Telegram (operator alerts) | **Confirmed plaintext** |
| `GENESIScrazy` | Operator handle | **Confirmed — Layer 3 decoded** |
| `gofile.io` / `gofile.io/uploadFile` | File exfil service | **Confirmed plaintext** |

### C2 API Paths
| Endpoint | Function |
|----------|----------|
| `https://genesishaha.fun/paths` | Configuration/tasking |
| `https://api.genesishaha.fun/send-embed` | Data exfiltration |
| `https://api.genesishaha.fun/send-embed-viewer` | Rich-data exfiltration |
| `https://genesishaha.fun/victims/*/dashboard` | Victim control web panel |

### External Services Accessed
- `api.ipify.org` — External IP address lookup (victim fingerprinting)
- `discord.com/api/v10/users/${id}/profile` — User profiling
- `discord.com/api/v8/guilds/${id}/invites` — Guild enumeration
- `cdn.discordapp.com/avatars/` — Avatar fetching

### YARA Rule Targets
| String | Context |
|--------|---------|
| `genesishaha.fun` | Primary C2 domain |
| `GENESIScrazy` | Operator handle |
| `qqkM5HynUl3Cqc3nmafzuKi+eg1PVDS4` | PBKDF2 password (Layer 2) |
| `UHTaXURgNzVMwKn8jkSgiw==` | PBKDF2 salt (base64) |
| `code-api.xyz` | Token exfiltration domain |
| `t.me/genesisproject` | Operator Telegram channel |

---

## Layer 2 Decryption Parameters (Statically Recovered)

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-256-CBC |
| KDF | PBKDF2-HMAC-SHA512 (100,000 iterations) |
| Password | `qqkM5HynUl3Cqc3nmafzuKi+eg1PVDS4` |
| Salt (b64) | `UHTaXURgNzVMwKn8jkSgiw==` |
| IV (b64) | `5lS8fyfaLAgt60BTDCM6KQ==` |

> **Note:** These decrypt the inner JS payload (Layer 3), NOT browser credentials.

---

## Attribution Leads

- **Genesis Project / GENESIScrazy** — `t.me/genesisproject` (confirmed in decrypted config)
- **`genesishaha.fun`** — C2 domain with victim management panel
- **`runneradmin`** in build paths — GitHub Actions CI/CD runner
- **`devetry`** username in screenshot-desktop module path — developer machine leak
- **Hardcoded crypto material** — PBKDF2 password/salt/IV statically recoverable (OPSEC failure)

---

## Repository Contents

```
├── README.md                            # This file
├── MAR_Trojanized_NodeJS_Stealer.pdf    # Full analysis report
├── scripts/
│   ├── decode_strings.py                # Layer 1: 8-table base91 decoder
│   ├── decrypt_config.py                # Layer 2: AES-256-CBC decryption
│   └── decode_layer3.py                 # Layer 3: Second base91 decoder
```

---

## References

- [Fortinet — Stealit Campaign Abuses Node.js SEA](https://www.fortinet.com/blog/threat-research/stealit-campaign-abuses-nodejs-single-executable-application)
- [Zscaler — NodeLoader: Node.js Malware Evading Detection](https://www.zscaler.com/blogs/security-research/nodeloader-exposed-node-js-malware-evading-detection)
- [Microsoft — Threat Actors Misuse Node.js to Deliver Malware](https://www.microsoft.com/en-us/security/blog/2025/04/15/threat-actors-misuse-node-js-to-deliver-malware-and-other-malicious-payloads/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [VirusTotal — Sample Analysis](https://www.virustotal.com/gui/file/f946f54953187eea89d4a1d0d5999be386bd9af0c3be0270dd42d9d28372ec27)

---

## Disclaimer

This report was produced for informational and defensive purposes only. All analysis was conducted on isolated infrastructure. The distribution website was reported to the appropriate authorities prior to publication. IOCs are shared under **TLP:GREEN** to support community defense.

---

## License

This work is shared under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — you are free to share and adapt with attribution.
