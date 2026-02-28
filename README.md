# Malware Analysis Report: Trojanized Node.js Stealer (pokemoncraft.com)

**Author:** Eleanor R. Lemish — Independent Security Researcher  
**Date:** February 28, 2026  
**TLP:** GREEN — May be shared within the cybersecurity community

---

## Overview

This repository contains a detailed malware analysis report for a trojanized Node.js information stealer distributed via **pokemoncraft.com**, a fake game mod website promoted through Discord social engineering.

The sample is a **76.68 MB Windows PE (x64)** binary built using the `pkg` npm module, which bundles a complete Node.js v18.5.0 runtime, V8 engine, and all malicious dependencies into a single self-contained executable. At the time of analysis, only **2 of 69** VirusTotal vendors flagged it as malicious.

📄 **[Read the full report (PDF)](MAR_Trojanized_NodeJS_Stealer.pdf)**

---

## Key Findings

- **Delivery:** Discord social engineering → fake game mod site (pokemoncraft.com) → trojanized installer
- **Packing:** `pkg` npm module bundles Node.js runtime + obfuscated JS payload into single PE; 42 MB overlay
- **Payload:** `crypted.js` — obfuscator.io-style obfuscation with string rotation array, hex indices, randomized names
- **C2:** socket.io over WSS with MsgPack binary serialization; three-layer transport fallback (WebSocket → HTTP long-polling → WebTransport/HTTP/3)
- **Credential Theft:** DPAPI decryption (`@primno/dpapi`) + SQLite3 direct access to Chrome/Edge Login Data, Cookies, and Web Data
- **Screen Capture:** `screenshot-desktop` with `pixelmatch` change detection — only exfiltrates when screen content changes
- **Exfiltration:** Encrypted ZIP archives via multipart/form-data upload over C2 channel
- **Anti-Forensics:** Installer self-deletes after payload deployment

---

## Sample Identification

| Property | Value |
|----------|-------|
| **SHA-256** | `f946f54953187eea89d4a1d0d5999be386bd9af0c3be0270dd42d9d28372ec27` |
| **MD5** | `d1f00db7c12af85563c19765def85e1b` |
| **SHA-1** | `b033c0ed7a98c43f365ed924e465f3732913c8d6` |
| **Imphash** | `4d0fb8dc9ee470058274f448bebbb85f` |
| **File Size** | 76.68 MB (80,402,188 bytes) |
| **File Type** | PE32+ executable (console) x86-64 |
| **Signature** | Unsigned |
| **VT Detection** | 2/69 (as of 2026-02-26) |
| **First Seen** | 2026-02-26 |

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|------------|
| **Execution** | T1059.007 (JavaScript), T1106 (Native API) |
| **Defense Evasion** | T1027 (Obfuscation), T1027.002 (Software Packing), T1140 (Runtime Deobfuscation), T1070.004 (File Deletion) |
| **Credential Access** | T1555.003 (Browser Credentials), T1539 (Session Cookies) |
| **Discovery** | T1082 (System Info), T1083 (File/Directory Discovery), T1057 (Process Discovery) |
| **Collection** | T1113 (Screen Capture), T1115 (Clipboard), T1005 (Local System Data), T1560.001 (Archive via Library) |
| **Exfiltration** | T1041 (Over C2 Channel), T1567 (Cloud Account) |
| **Command & Control** | T1071.001 (Web Protocols/WebSockets), T1008 (Fallback Channels), T1573.001 (Encrypted Channel) |

---

## IOC Summary

### Network
| Indicator | Type |
|-----------|------|
| `pokemoncraft.com` | Distribution domain (reported; now offline) |
| socket.io over WSS (MsgPack) | C2 protocol |
| C2 URL embedded in `crypted.js` | Not yet deobfuscated |

### Host
| Indicator | Type |
|-----------|------|
| `C:\snapshot\builder\crypted.js` | Payload path (pkg virtual FS) |
| `REG QUERY HKLM\...\Cryptography /v MachineGuid` | Fingerprinting |
| `screenCapture_1.3.2.bat` | Screen capture helper |
| `Lxlxtp()` | Obfuscation string array function |

---

## Attribution Leads

- **`runneradmin`** in build paths — GitHub Actions CI/CD runner (OPSEC failure)
- **`devetry`** username embedded in screenshot-desktop module path (developer machine leak)
- TTP overlap with **Stealit** (Fortinet, Oct 2025) and **NodeLoader** (Zscaler, Apr 2025) campaigns

---

## Repository Contents

```
├── README.md                            # This file
├── MAR_Trojanized_NodeJS_Stealer.pdf    # Full analysis report
```

---

## References

- [Fortinet — Stealit Campaign Abuses Node.js SEA](https://www.fortinet.com/blog/threat-research/stealit-campaign-abuses-nodejs-single-executable-application)
- [Zscaler — NodeLoader: Node.js Malware Evading Detection](https://www.zscaler.com/blogs/security-research/nodeloader-exposed-node-js-malware-evading-detection)
- [Microsoft — Threat Actors Misuse Node.js to Deliver Malware](https://www.microsoft.com/en-us/security/blog/2025/04/15/threat-actors-misuse-node-js-to-deliver-malware-and-other-malicious-payloads/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## Disclaimer

This report was produced for informational and defensive purposes only. All analysis was conducted on isolated infrastructure. The distribution website was reported to the appropriate authorities prior to publication. IOCs are shared under **TLP:GREEN** to support community defense.

---

## License

This work is shared under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — you are free to share and adapt with attribution.
