<div align="center">

# Deep Decoder

[![Agent Ready](https://img.shields.io/badge/Agent-Ready-blue?style=flat-square)](SKILL.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3](https://img.shields.io/badge/Python-3.10+-green?style=flat-square)](scripts/deep_decode.py)

[English](README.md) | [中文文档](README_CN.md)

</div>

[English](README.md) | [中文文档](README_CN.md)

</div>

---

## 🚀 Quick Install (Claude Code)

```bash
# 1. Add the Marketplace
/plugin marketplace add github:bx33661/Deep-Decoder

# 2. Install the Skill
/plugin install deep-decoder@deep-decoder-market
```

---

##  What is this?

**Deep Decoder** is a specialized skill designed for **Security Researchers**, **CTF Players**, and **AI Agents**. It autonomously peels back layers of obfuscation, turning binary garbage into readable text or extracting hidden files.

Instead of guessing "Is this Base64?", simply pass the string to Deep Decoder. It recursively attempts 15+ formats until it finds the truth.

## Capabilities

| Feature | Description |
| :--- | :--- |
| **Recursive Decoding** | Automatically solves chains like `Base64` → `Gzip` → `URL` → `JSON`. |
| **Forensics** | Detects and extracts **Images**, **Archives**, **Databases**, and **Executables**. |
| **Crypto Solving** | Brute-force solvers for **XOR**, **Caesar**, **Rail Fence**, **Atbash**, and **Rot47**. |
| **Content ID** | Intelligently distinguishes **Source Code**, **English Text**, and **Binary Data**. |

## Agent Usage

### 1. Analyze ambiguous strings
When you see a random blob of text, run this:

```bash
python scripts/deep_decode.py --input "SGVsbG8gV29ybGQ=" --pretty
```

### 2. Extract potential files
When you suspect a file is hidden in a hex dump or response:

```bash
python scripts/deep_decode.py --file traffic.dump --extract-dir ./workspace
```

### 3. Understanding the Output
The tool returns structured JSON. Look at the `attempts` array.
- If `magic` is present -> **It's a file.** (e.g., `magic: PNG`)
- If `text` is present -> **It's readable data.** (e.g., `text: "password123"`)

## Supported Formats

- **Encodings**: Base64, Base32, Ascii85, Hex, URL, Quoted-Printable, HTML.
- **Compression**: Gzip, Zlib, Deflate.
- **Ciphers**: XOR, Caesar, Atbash, Rot13/47, Rail Fence.
- **Files**: PNG, JPG, GIF, WEBP, ZIP, RAR, 7Z, PDF, ELF, PE, Class, SQLite, Office.

---
<div align="center">
  <sub>Powered by bx</sub>
</div>
