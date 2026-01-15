---
name: deep-decoder
description: Recursively decode and identify complex encodings (Base64/32/85, URL, JWT, Hex, Rot13, XOR, Caesar) and extract binary files (images, archives).
---

# Deep Decoder

Use this skill when you encounter:
1. **Ambiguous Strings**: Random-looking alphanumeric blobs, huge blocks of text, or strings ending in `==`.
2. **Obfuscated Code/Traffic**: Payloads that look like they are wrapped in multiple layers (e.g., `Base64(Gzip(Hex(...)))`).
3. **Hidden Files**: Binary dumps that might contain images, PDFs, or executables.
4. **CTF Challenges**: Cryptography and forensic tasks involving classical ciphers or unknown encodings.

## Capabilities

- **Recursive Decoding**: Automatically peels back layers of encoding (e.g., `Hex -> Base64 -> Gzip -> JSON`).
- **Brute-Force**: built-in solvers for single-byte XOR and Caesar ciphers.
- **File Extraction**: identifies and saves embedded files (PNG, JPEG, ZIP, ELF, etc.) to disk.
- **Format Support**:
  - **Text**: JWT, URL, HTML Entities, Rot13, Caesar, Quoted-Printable.
  - **Binary-to-Text**: Base64, Base32, Ascii85, Hex.
  - **Compression**: Gzip, Zlib, Deflate.

## Usage

### CLI Interface

**Script Location**: `scripts/deep_decode.py`

#### 1. Analyze a String
```bash
python scripts/deep_decode.py --input "SGVsbG8gV29ybGQ=" --pretty
```

#### 2. Analyze a File
```bash
python scripts/deep_decode.py --file path/to/dump.txt --pretty
```

#### 3. Extract Hidden Files
**Crucial**: If the output suggests a binary file (e.g., "Magic: PNG"), you **MUST** run this to save it.
```bash
python scripts/deep_decode.py --input "..." --extract-dir ./extracted_files
```

### Response Interpretation

The tool returns JSON. Look for the `attempts` array.
- `status: success`: The layer was successfully decoded.
- `text`: The readable text result.
- `magic`: The detected file type (e.g., `PNG`, `ELF`).
- `extracted_path`: WHERE the file was saved. **Always tell the User this path.**

## Heuristics for Agents

1. **If output contains "GZIP" / "ZLIB"**: The data was compressed. The tool has likely already decompressed it for you in the next step.
2. **If output is JSON (JWT)**: The tool automatically splits header/payload.
3. **If "magic" detected**: The data is a file. Stop trying to read it as text. Tell the user you found a file.
4. **If "failed"**: The tool couldn't find a standard encoding. Consider manual analysis or other crypto tools.
