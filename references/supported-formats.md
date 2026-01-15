# Supported Formats

**Deep Decoder** supports a wide range of encodings, ciphers, and obfuscation techniques.

## Encodings (Binary <-> Text)

| Format | Output | Notes |
| :--- | :--- | :--- |
| **Base64** | Binary | Standard & URL-Safe supported. Ignores padding errors. |
| **Base32** | Binary | Standard Base32. |
| **Ascii85** | Binary | Adobe style `<~ ... ~>`. |
| **Hex** | Binary | Detects space, colon, or continuous hex strings. |
| **Quoted-Printable** | Binary | Email encoding (`=0A=0D`). |
| **URL Encoding** | Text | Decodes `%20` and `+`. Parses query strings to JSON. |
| **HTML Entities** | Text | Decodes `&amp;`, `&#97;`, `&#x41;`. |

## Ciphers (Text <-> Text)

| Cipher | Strategy | Notes |
| :--- | :--- | :--- |
| **Rot13** | Deterministic | Standard A-Z rotation. |
| **Rot47** | Deterministic | Rotates ASCII chars 33-126. |
| **Atbash** | Deterministic | Reverses alphabet (A <-> Z). |
| **Caesar** | Brute Force | Tries all 25 shifts. Selects best English score. |
| **Rail Fence** | Brute Force | Tries 2-5 rails. Selects best English score. |
| **XOR** | Brute Force | Tries all 256 single-byte keys. |

## Structured Formats

| Format | Action |
| :--- | :--- |
| **JWT** | Decodes Header & Payload to JSON. Does not verify signature. |
| **Gzip / Zlib** | Auto-detected and decompressed. |

## Heuristics

The tool uses **Shannon Entropy** and **Content Scoring** to guide decision making:

- **English Text**: High text score, low entropy.
- **Source Code**: High text score, presence of keywords (`var`, `function`, `class`).
- **Compressed/Encrypted**: High entropy (> 6 bits/byte).
