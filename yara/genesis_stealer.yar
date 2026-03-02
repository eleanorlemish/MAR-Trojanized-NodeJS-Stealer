/*
    YARA Rule: GenesisProject_NodeJS_Stealer
    Author:    Eleanor R. Lemish — Independent Security Researcher
    Date:      2026-02-28
    TLP:       GREEN — May be shared within the cybersecurity community
    SHA-256:   f946f54953187eea89d4a1d0d5999be386bd9af0c3be0270dd42d9d28372ec27
    Reference: https://github.com/eleanorlemish/MAR-Trojanized-NodeJS-Stealer

    Detects the Genesis Project trojanized Node.js credential stealer
    originally distributed via pokemoncraft.com / Discord social engineering.

    Three-layer obfuscation: base91 -> AES-256-CBC -> base91.
    Strings below are confirmed plaintext in the binary — not encoded.

    Notes:
    - $pbkdf2_pass and $pbkdf2_salt are hardcoded crypto material (OPSEC failure
      by the operator) used to decrypt the inner payload. High confidence, low
      false-positive risk.
    - $pkg_marker targets the Node.js pkg bundler SEA header present in all
      pkg-built binaries, combined with other strings narrows to this family.
    - Condition requires PE + at least 2 strings to reduce false positives.
*/

rule GenesisProject_NodeJS_Stealer
{
    meta:
        description     = "Genesis Project trojanized Node.js stealer — pokemoncraft.com campaign"
        author          = "Eleanor R. Lemish"
        date            = "2026-02-28"
        tlp             = "GREEN"
        sha256          = "f946f54953187eea89d4a1d0d5999be386bd9af0c3be0270dd42d9d28372ec27"
        md5             = "d1f00db7c12af85563c19765def85e1b"
        threat_actor    = "Genesis Project"
        c2              = "genesishaha.fun"
        mitre_attack    = "T1027, T1027.002, T1555.003, T1003.005, T1113, T1568, T1008"

    strings:
        // Layer 2 crypto material — hardcoded PBKDF2 parameters (high confidence)
        $pbkdf2_pass    = "qqkM5HynUl3Cqc3nmafzuKi+eg1PVDS4" ascii
        $pbkdf2_salt    = "UHTaXURgNzVMwKn8jkSgiw==" ascii
        $aes_iv         = "5lS8fyfaLAgt60BTDCM6KQ==" ascii

        // Confirmed C2 / exfiltration infrastructure (plaintext in binary)
        $c2_domain      = "genesishaha.fun" ascii
        $token_exfil    = "code-api.xyz" ascii
        $operator_tg    = "t.me/genesisproject" ascii
        $file_exfil     = "gofile.io/uploadFile" ascii

        // Operator handle (confirmed via Layer 3 decode)
        $op_handle      = "GENESIScrazy" ascii

        // pkg bundler SEA marker present in all pkg-built Node.js binaries
        $pkg_marker     = "PKG_DEFAULT_ENTRYPOINT" ascii

        // DPAPI credential theft module
        $dpapi_mod      = "@primno/dpapi" ascii

        // Screenshot change-detection module
        $screenshot_mod = "screenshot-desktop" ascii
        $pixelmatch     = "pixelmatch" ascii

    condition:
        uint16(0) == 0x5A4D       // PE file (MZ header)
        and filesize > 50MB       // pkg binaries are large; avoids small imposters
        and (
            // High-confidence: crypto material present = almost certainly this sample
            ($pbkdf2_pass and $pbkdf2_salt)
            or
            // Medium-confidence: C2 + operator infrastructure
            (2 of ($c2_domain, $token_exfil, $operator_tg, $op_handle, $file_exfil))
            or
            // Behavioral: pkg + stealer modules combination
            ($pkg_marker and 2 of ($dpapi_mod, $screenshot_mod, $pixelmatch, $token_exfil))
        )
}
