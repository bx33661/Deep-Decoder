<div align="center">

# Deep Decoder

[![Agent Ready](https://img.shields.io/badge/Agent-Ready-blue?style=flat-square)](SKILL.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3](https://img.shields.io/badge/Python-3.10+-green?style=flat-square)](scripts/deep_decode.py)

[English](README.md) | [中文文档](README_CN.md)

</div>

---

## 这个SKILL是干什么的？

**Deep Decoder** 是一个专为 **Claude** 及其他 AI Agent 设计的 Skill。它能自动剥离多层混淆，将乱码还原为可读文本，或从流量中提取隐藏文件。

无需猜测 “这是 Base64 吗？”，只需将字符串扔给 Deep Decoder。它会递归尝试 15+ 种格式，直到找到真相。

## 核心能力

| 功能 | 描述 |
| :--- | :--- |
| **递归处理** | 自动处理嵌套编码链，例如 `Base64` → `Gzip` → `URL` → `JSON`。 |
| **文件取证** | 自动检测并提取 **图片**、**压缩包**、**数据库**、**可执行文件**等。 |
| **密码破解** | 内置暴力破解器，支持 **XOR**、**凯撒密码**、**栅栏密码**、**Atbash** 等。 |
| **内容识别** | 智能区分 **源代码**、**自然语言** 和 **二进制数据**，减少 Agent 幻觉。 |

## Agent 使用指南

### 1. 分析不明字符串
当你看到一串乱码时，直接运行：

```bash
python scripts/deep_decode.py --input "SGVsbG8gV29ybGQ=" --pretty
```

### 2. 提取隐藏文件
当你怀疑文本或 Hex 中包含文件时：

```bash
python scripts/deep_decode.py --file traffic.dump --extract-dir ./workspace
```

### 3. 如何理解输出
工具返回结构化的 JSON。请关注 `attempts` 列表：
- 如果出现 `magic` -> **这是一个文件** (例如 `magic: PNG`)，请告诉用户你提取了文件。
- 如果出现 `text` -> **这是可读文本** (例如 `text: "password123"`)。

## 支持格式

- **编码**: Base64, Base32, Ascii85, Hex, URL, Quoted-Printable, HTML.
- **压缩**: Gzip, Zlib, Deflate.
- **加密**: XOR, Caesar, Atbash, Rot13/47, Rail Fence.
- **文件**: PNG, JPG, GIF, WEBP, ZIP, RAR, 7Z, PDF, ELF, PE, Class, SQLite, Office.

---
<div align="center">
  <sub>Powered by bx</sub>
</div>
