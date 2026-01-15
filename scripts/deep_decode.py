#!/usr/bin/env python3
import argparse
import base64
import binascii
import html
import json
import re
import urllib.parse
import zlib
import gzip
import quopri
import codecs
import hashlib
import os
import string
import math
from collections import Counter

# Label, Signature, Extension
MAGIC_SIGNATURES = [
    ("JPEG", bytes.fromhex("FFD8FF"), ".jpg"),
    ("PNG", bytes.fromhex("89504E470D0A1A0A"), ".png"),
    ("GIF", b"GIF87a", ".gif"),
    ("GIF", b"GIF89a", ".gif"),
    ("PDF", b"%PDF-", ".pdf"),
    ("ZIP", b"PK\x03\x04", ".zip"),
    ("ZIP", b"PK\x05\x06", ".zip"),
    ("ZIP", b"PK\x07\x08", ".zip"),
    ("GZIP", b"\x1F\x8B\x08", ".gz"),
    ("ELF", b"\x7FELF", ".bin"),
    ("BMP", b"BM", ".bmp"),
    ("RAR", b"Rar!\x1A\x07\x00", ".rar"),
    ("7Z", b"7z\xBC\xAF'\x1C", ".7z"),
    ("ZLIB", bytes.fromhex("7801"), ".zlib"),
    ("ZLIB", bytes.fromhex("789C"), ".zlib"),
    ("ZLIB", bytes.fromhex("78DA"), ".zlib"),
    ("SQLITE", b"SQLite format 3\x00", ".db"),
    ("JAVA_CLASS", bytes.fromhex("CAFEBABE"), ".class"),
    ("MS_OLE", bytes.fromhex("D0CF11E0A1B11AE1"), ".doc"), # Old Office / MSI
    ("DEB", b"!.arch<debian>", ".deb"),
    ("WEBP", b"RIFF", ".webp"), # Partial, needs 'WEBP' check
]

# Regex Patterns
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
BASE32_RE = re.compile(r"^[A-Z2-7=]+$")
URL_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")
QUERYSTRING_RE = re.compile(r"^[^=&]+=[^&]*(&[^=&]+=[^&]*)+$")
HTML_ENTITY_RE = re.compile(r"&(?:[a-zA-Z]+|#\d+|#x[0-9a-fA-F]+);")
QUOTED_PRINTABLE_RE = re.compile(r"=[0-9A-Fa-f]{2}")

# Detection Patterns
JS_OBF_RE = re.compile(r"(eval\s*\(|function\s*\(p,a,c,k,e,d|var\s+_0x)")

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())

def normalize_input(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] in ("'", '"', "`") and text[-1] == text[0]:
        return text[1:-1]
    return text

def add_padding(value: str) -> str:
    return value + "=" * ((4 - len(value) % 4) % 4)

def b64_decode(value: str, urlsafe: bool) -> bytes | None:
    try:
        padded = add_padding(value)
        if urlsafe:
            return base64.urlsafe_b64decode(padded.encode("ascii"))
        return base64.b64decode(padded.encode("ascii"), validate=False)
    except (binascii.Error, ValueError):
        return None

def is_mostly_printable(data: bytes) -> bool:
    if not data:
        return True
    printable = sum((32 <= b <= 126) or b in (9, 10, 13) for b in data)
    return printable / len(data) >= 0.85

def score_text(text: str) -> float:
    if not text:
        return 0.0
    
    # Text Analysis
    common_english = "etaoin shrdlu"
    score_eng = sum(1 for c in text.lower() if c in common_english) / len(text) if text else 0
    
    # Code Analysis (Python/JS/C)
    code_keywords = ["function", "var", "const", "let", "import", "class", "def", "return", "if", "for", "while", "logger", "System", "public", "void"]
    score_code = 0.0
    if any(k in text for k in code_keywords):
        score_code = 0.6
        if "{" in text and "}" in text:
            score_code += 0.2
            
    # Structure Analysis
    score_struct = 0.0
    if text.startswith("{") and text.endswith("}"): # JSON-like
        score_struct = 0.5
    
    # High entropy implies randomness, not text.
    # We want to return high score for readable things.
    # Combine scores
    return max(score_eng, score_code, score_struct)

def detect_magic(data: bytes) -> tuple[str, str]:
    # Returns (Label, Extension)
    for label, sig, ext in MAGIC_SIGNATURES:
        if data.startswith(sig):
            # Special handling for RIFF/WEBP
            if label == "WEBP":
                if len(data) > 12 and data[8:12] == b"WEBP":
                    return "WEBP", ".webp"
                continue
            return label, ext
            
    if len(data) >= 8 and data[4:8] == b"ftyp":
        return "MP4", ".mp4"
    if data.startswith(b"ID3"):
        return "MP3", ".mp3"
    # MP3 Sync Frame: FFFB or FFF3 etc. Very prone to false positives.
    # Require at least 2 frames or reasonable length?
    if len(data) > 100 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0:
        return "MP3", ".mp3"
        
    if data.startswith(b"MZ"):
        # PE heuristic: check for PE header offset? 
        # For now, just simplistic.
        if len(data) > 64 and b"This program" in data[:512]:
           return "PE_EXE", ".exe"
            
    return "unknown", ".bin"

def looks_like_jwt(text: str) -> bool:
    parts = text.split(".")
    if len(parts) not in (2, 3):
        return False
    if not all(BASE64URL_RE.fullmatch(part or "x") for part in parts):
        return False
    header = b64_decode(parts[0], True)
    if not header: return False
    try:
        json.loads(header.decode("utf-8"))
    except:
        return False
    return True

def looks_like_base64(text: str) -> bool:
    if "." in text or len(text) < 8: return False
    # Filter out pure Hex (can look like B64) to prefer Hex decoder
    if re.fullmatch(r"[0-9A-Fa-f]+", text) and len(text) % 2 == 0:
        return False
    if BASE64_RE.fullmatch(text): return True
    if BASE64URL_RE.fullmatch(text) and ("-" in text or "_" in text): return True
    return False

def looks_like_base32(text: str) -> bool:
    if len(text) < 16 or "=" not in text: return False
    return bool(BASE32_RE.fullmatch(text))

def looks_like_ascii85(text: str) -> bool:
    return text.startswith("<~") and text.endswith("~>")

def looks_like_urlencoded(text: str) -> bool:
    return bool(URL_ENCODED_RE.search(text) or QUERYSTRING_RE.fullmatch(text))

def looks_like_hex(text: str) -> bool:
    if not text: return False
    text_clean = text.replace(" ", "").replace(":", "").replace("0x", "")
    if len(text_clean) % 2 != 0: return False
    return bool(re.fullmatch(r"[0-9A-Fa-f]+", text_clean))

def looks_like_html_entities(text: str) -> bool:
    return bool(HTML_ENTITY_RE.search(text))

def looks_like_quoted_printable(text: str) -> bool:
    return bool(QUOTED_PRINTABLE_RE.search(text))

def detect_candidates(text: str) -> list[str]:
    candidates = []
    if looks_like_jwt(text): candidates.append("jwt")
    if looks_like_base64(text): candidates.append("base64")
    if looks_like_base32(text): candidates.append("base32")
    if looks_like_ascii85(text): candidates.append("ascii85")
    if looks_like_urlencoded(text): candidates.append("url")
    if looks_like_hex(text): candidates.append("hex")
    if looks_like_html_entities(text): candidates.append("html")
    if looks_like_quoted_printable(text): candidates.append("quoted-printable")
    
    # Text Transformations
    if any(c.isalpha() for c in text):
        candidates.append("rot13")
        candidates.append("rot47")
        candidates.append("atbash")
        candidates.append("caesar")
        candidates.append("rail_fence")
    
    # Always allow XOR if input is somewhat valid
    if len(text) > 0:
        candidates.append("xor") 
        
    # JS Obfuscation?
    if JS_OBF_RE.search(text):
        candidates.append("js_obfuscation") # Just a tag for now

    return candidates

# --- Decoders ---

def decode_jwt(text: str) -> tuple[dict, str | None]:
    parts = text.split(".")
    try:
        header = b64_decode(parts[0], True)
        payload = b64_decode(parts[1], True)
        if not header or not payload: return {}, "decode failed"
        return {"header": json.loads(header), "payload": json.loads(payload)}, None
    except:
        return {}, "invalid json"

def decode_base64(text: str) -> tuple[bytes | None, str | None]:
    urlsafe = "-" in text or "_" in text
    decoded = b64_decode(text, urlsafe)
    return (decoded, None) if decoded else (None, "failed")

def decode_base32(text: str) -> tuple[bytes | None, str | None]:
    try:
        padding = "=" * ((8 - len(text) % 8) % 8)
        return base64.b32decode((text + padding).encode("ascii")), None
    except: return None, "failed"

def decode_ascii85(text: str) -> tuple[bytes | None, str | None]:
    try: return base64.a85decode(text.encode("ascii")), None
    except: return None, "failed"

def decode_urlencoded(text: str) -> tuple[dict, str | None]:
    try:
        if QUERYSTRING_RE.fullmatch(text):
            return {"pairs": urllib.parse.parse_qs(text)}, None
        return {"text": urllib.parse.unquote(text)}, None
    except: return None, "failed"

def decode_hex(text: str) -> tuple[bytes | None, str | None]:
    cleaned = re.sub(r"(0x|\\x|[\s,:-])", "", text)
    try: return bytes.fromhex(cleaned), None
    except: return None, "failed"

def decode_quoted_printable(text: str) -> tuple[bytes | None, str | None]:
    try: return quopri.decodestring(text.encode("utf-8")), None
    except: return None, "failed"

# --- Classical Ciphers ---

def decode_rot13(text: str) -> tuple[str, str | None]:
    return codecs.decode(text, "rot_13"), None

def decode_rot47(text: str) -> tuple[str, str | None]:
    # Rot47 rotates ASCII 33-126
    res = []
    for c in text:
        val = ord(c)
        if 33 <= val <= 126:
            res.append(chr(33 + ((val - 33 + 47) % 94)))
        else:
            res.append(c)
    return "".join(res), None

def decode_atbash(text: str) -> tuple[str, str | None]:
    # Atbash: A<->Z, a<->z
    def _map(c):
        if 'a' <= c <= 'z': return chr(ord('z') - (ord(c) - ord('a')))
        if 'A' <= c <= 'Z': return chr(ord('Z') - (ord(c) - ord('A')))
        return c
    return "".join(_map(c) for c in text), None

def try_rail_fence(text: str) -> tuple[dict | None, str | None]:
    # Brute force rails 2 to 5
    best_score = 0.0
    best_res = None
    
    # Helper to decrypt rail fence
    def _decrypt_rail(cipher, num_rails):
        rng = range(len(cipher))
        fence = [[None] * len(cipher) for _ in range(num_rails)]
        rails = list(range(num_rails - 1)) + list(range(num_rails - 1, 0, -1))
        for n, x in enumerate(rng):
            fence[rails[n % len(rails)]][x] = '*'
        
        itr = iter(cipher)
        for r in fence:
            for i in range(len(r)):
                if r[i] == '*': r[i] = next(itr)
        
        result = []
        for n, x in enumerate(rng):
            result.append(fence[rails[n % len(rails)]][x])
        return "".join(result)

    for rails in range(2, 6):
        try:
            pt = _decrypt_rail(text, rails)
            s = score_text(pt)
            if s > best_score:
                best_score = s
                best_res = {"rails": rails, "plaintext": pt}
        except: pass
    
    if best_score > 0.45:
        return best_res, None
    return None, "no plain text found"

def try_caesar(text: str) -> tuple[dict | None, str | None]:
    best_score = 0.0
    best_res = None
    
    for shift in range(1, 26):
        try:
            shifted = ""
            for char in text:
                if char.isalpha():
                    base = ord('a') if char.islower() else ord('A')
                    shifted += chr((ord(char) - base + shift) % 26 + base)
                else: shifted += char
            
            s = score_text(shifted)
            if s > best_score:
                best_score = s
                best_res = {"shift": shift, "plaintext": shifted}
        except: pass
            
    if best_score > 0.45:
        return best_res, None
    return None, "no english text"

def try_xor(text: str) -> tuple[dict | None, str | None]:
    # XOR logic with bytes conversion
    data = None
    if looks_like_hex(text):
        data, _ = decode_hex(text)
    if not data: data = text.encode("utf-8")
        
    best_score = 0.0
    best_res = None
    
    for key in range(1, 256):
        xored = bytes([b ^ key for b in data])
        # Text Check
        if is_mostly_printable(xored):
             try:
                 txt = xored.decode("utf-8")
                 s = score_text(txt)
                 if s > best_score:
                     best_score = s
                     best_res = {"key": key, "plaintext": txt}
             except: pass
        else:
            # Magic Check
            label, _ = detect_magic(xored)
            if label != "unknown":
                return {"key": key, "magic": label, "binary_hex": xored[:16].hex().upper()}, None

    if best_score > 0.45:
        return best_res, None
    return None, "no likely result"

def try_decompress(data: bytes) -> tuple[bytes | None, str]:
    if not data: return None, ""
    try: return gzip.decompress(data), "gzip"
    except: pass
    try: return zlib.decompress(data), "zlib"
    except: pass
    try: return zlib.decompress(data, -15), "deflate"
    except: pass
    return None, ""

# --- Main Solver Logic ---

def attempt_decode(text: str, fmt: str, extract_dir: str | None = None) -> dict:
    attempt = {"format": fmt, "status": "failed"}
    
    # Text-to-Text Solvers
    if fmt == "caesar":
        res, err = try_caesar(text)
        if not err: attempt.update({"status": "success", "text": res["plaintext"], **res})
        return attempt
        
    if fmt == "atbash":
        res, err = decode_atbash(text)
        s = score_text(res)
        if s > 0.4: attempt.update({"status": "success", "text": res, "score": s})
        return attempt

    if fmt == "rot13":
        res, err = decode_rot13(text)
        s = score_text(res)
        if s > 0.4: attempt.update({"status": "success", "text": res, "score": s})
        return attempt

    if fmt == "rot47":
        res, err = decode_rot47(text)
        s = score_text(res)
        if s > 0.4: attempt.update({"status": "success", "text": res, "score": s})
        return attempt

    if fmt == "rail_fence":
        res, err = try_rail_fence(text)
        if not err: attempt.update({"status": "success", "text": res["plaintext"], **res})
        return attempt

    if fmt == "xor":
        res, err = try_xor(text)
        if not err: 
            attempt.update({"status": "success", **res})
            if "plaintext" in res: attempt["text"] = res["plaintext"]
        return attempt

    # Structured Text
    if fmt == "jwt":
        res, err = decode_jwt(text)
        if not err: attempt.update({"status": "success", "jwt": res})
        return attempt

    if fmt == "url":
        res, err = decode_urlencoded(text)
        if not err: attempt.update({"status": "success", "decoded": res})
        return attempt

    if fmt == "html":
        attempt.update({"status": "success", "text": html.unescape(text)})
        return attempt

    # Text-to-Bytes
    decoded_bytes = None
    if fmt == "base64": decoded_bytes, _ = decode_base64(text)
    elif fmt == "base32": decoded_bytes, _ = decode_base32(text)
    elif fmt == "ascii85": decoded_bytes, _ = decode_ascii85(text)
    elif fmt == "hex": decoded_bytes, _ = decode_hex(text)
    elif fmt == "quoted-printable": decoded_bytes, _ = decode_quoted_printable(text)
    
    if decoded_bytes:
        attempt["status"] = "success"
        attempt["bytes_len"] = len(decoded_bytes)
        attempt["entropy"] = round(calculate_entropy(decoded_bytes), 2)
        
        # Decompression
        decomp, algo = try_decompress(decoded_bytes)
        if decomp:
            attempt["compression"] = algo
            decoded_bytes = decomp
            attempt["decompressed_len"] = len(decoded_bytes)
            attempt["entropy"] = round(calculate_entropy(decoded_bytes), 2)
        
        # Magic Byte Check
        label, ext = detect_magic(decoded_bytes)
        if label != "unknown":
            attempt["magic"] = label
            # Extraction
            if extract_dir:
                if not os.path.exists(extract_dir): os.makedirs(extract_dir)
                fhash = hashlib.sha256(decoded_bytes).hexdigest()[:16]
                fname = f"extracted_{fhash}{ext}"
                fpath = os.path.join(extract_dir, fname)
                with open(fpath, "wb") as f: f.write(decoded_bytes)
                attempt["extracted_path"] = os.path.abspath(fpath)
            return attempt

        # If printable, treat as text
        if is_mostly_printable(decoded_bytes):
            attempt["text"] = decoded_bytes.decode("utf-8", errors="replace")
        
    return attempt

def recursive_solve(text: str, extract_dir: str | None, depth: int = 0, max_depth: int = 5) -> list[dict]:
    if depth >= max_depth: return []
    
    candidates = detect_candidates(text)
    if not candidates: return []
    
    strong_formats = {"jwt", "base64", "base32", "url", "hex", "ascii85", "quoted-printable"}
    
    # We will collect all successful results at this level
    results = []
    
    for fmt in candidates:
        if fmt in ("xor", "caesar", "rail_fence", "atbash", "rot47", "rot13") and depth > 1:
            continue
            
        res = attempt_decode(text, fmt, extract_dir)
        if res["status"] == "success":
            results.append(res)
            
            # If magic file or compression, this is DEFINITELY the right path. Return immediately.
            if "magic" in res or "compression" in res:
                return [res]
            
            # If Strong Format, we prefer this path, but maybe allow checking others?
            # Usually Strong Formats are unambiguous (Base64 is Base64).
            # But sometimes Hex can be Text.
            # Let's prioritize Strong Formats: if we found one, we likely stick with it.
            if fmt in strong_formats:
                # But wait, what if we have multiple strong candidates?
                # e.g. a string that is both Hex and Base64?
                # Let's collect them and verify which one produces "better" output?
                # For now, Greedy on Strong is usually fine.
                 pass

    if not results:
        return []

    # Select the BEST result to recurse on.
    # Logic:
    # 1. Magic/Compression/JWT matches are TOP priority (already returned above).
    # 2. Strong + Readble Text > Weak + Readable Text.
    # 3. Weak + Readable Text > Strong + Binary Garbage.
    
    strong_results = [r for r in results if r["format"] in strong_formats]
    weak_results = [r for r in results if r["format"] not in strong_formats]
    
    # Check if any strong result yielded good text or structured data
    best_strong = None
    for res in strong_results:
        # Check for meaningful text
        txt = res.get("text")
        if not txt and res.get("decoded"): txt = res["decoded"].get("text")
        
        if txt and score_text(txt) > 0.4:
            best_strong = res
            break
        if "jwt" in res:
            best_strong = res
            break
            
    if best_strong:
        # We found a strong format that makes sense. Use it.
        chain = [best_strong]
        next_text = best_strong.get("text") or (best_strong.get("decoded") or {}).get("text")
        if next_text and next_text != text:
             chain.extend(recursive_solve(next_text, extract_dir, depth + 1, max_depth))
        return chain

    # If no "Good" strong result, check weak results for High Score Text
    best_weak = None
    best_weak_score = -1.0
    
    for res in weak_results:
        s = res.get("score", 0.0)
        if s > best_weak_score:
            best_weak_score = s
            best_weak = res
            
    # If we have a very good weak result, prefer it over binary garbage
    if best_weak and best_weak_score > 0.6: # Higher threshold for override
        chain = [best_weak]
        if "text" in best_weak and best_weak["text"] != text:
             chain.extend(recursive_solve(best_weak["text"], extract_dir, depth + 1, max_depth))
        return chain
        
    # Fallback: If we had strong results (even if binary), usage them (maybe it IS binary)
    if strong_results:
        # Pick the one with lowest entropy? Or just first?
        # Maybe Base64 is better than Hex?
        best_res = strong_results[0]
        chain = [best_res]
        # Recursion on binary? Usually we don't recurse on raw binary unless it had magic.
        # But maybe we want to output it.
        return chain
        
    # Last resort: weak result with low score? No, dangerous.
    return []

def main() -> None:
    parser = argparse.ArgumentParser(description="Deep Decoder: Advanced Recursive Decoding")
    parser.add_argument("--input", help="Input string")
    parser.add_argument("--file", help="Input file")
    parser.add_argument("--pretty", action="store_true", help="Pretty JSON")
    parser.add_argument("--extract-dir", help="Extraction directory")
    args = parser.parse_args()

    if not args.input and not args.file:
        raw = "" 
        # Optional: Read from stdin? For now just exit
        try:
             import sys
             if not sys.stdin.isatty():
                 raw = sys.stdin.read().strip()
        except: pass
        if not raw:
            raise SystemExit("Use --input or --file")
    elif args.file:
        with open(args.file, "rb") as f: # Read bytes initially?
            # heuristic: try read as utf-8, if fail, read as binary -> hex?
            # Simpler: read text if possible, else complain or treat as raw?
            # The current tool assumes "text" input mostly. 
            # If binary file, we probably want to just check magic bytes directly?
            # Let's read as binary, verify if valid utf-8.
            bdata = f.read()
            try:
                raw = bdata.decode("utf-8")
            except:
                # Binary file: convert to hex to allow 'decode_hex' to pick it up?
                # Or just check magic bytes immediately?
                # Let's assume input is string for the recursive solver.
                # If really binary, maybe just hex encode it?
                raw = bdata.hex() # Treat binary input as HEX string for the tool to start processing
    else:
        raw = args.input

    normalized = normalize_input(raw)
    attempts = recursive_solve(normalized, args.extract_dir)
    
    # Analyze final result features
    final_type = "unknown"
    if attempts:
        last = attempts[-1]
        if "magic" in last: final_type = "file:" + last["magic"]
        elif "text" in last: final_type = "text"
        elif "jwt" in last: final_type = "jwt"
    
    result = {
        "input_preview": raw[:64],
        "candidates": detect_candidates(normalized),
        "final_type": final_type,
        "attempts": attempts
    }
    
    if args.pretty:
        print(json.dumps(result, indent=2, ensure_ascii=True))
    else:
        print(json.dumps(result, ensure_ascii=True))

if __name__ == "__main__":
    main()
