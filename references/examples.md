# Deep Decoder Examples

## For AI Agents

### Scenario 1: Malicious Traffic Analysis
**Context**: You find a suspicious PowerShell command with a long string.
**Input**: `powershell -enc SUVYKE5ldy1PYmplY3Qg...`
**Action**:
1. Run `python scripts/deep_decode.py --input "SUV..."`
2. Tool identifies `Base64` -> `Unicode/UTF-16LE`.
3. Tool Output: `IEX(New-Object Net.WebClient).DownloadString(...)`
4. **Agent Outcome**: You now see the malicious command.

### Scenario 2: CTF Challenge (Binaries)
**Context**: You are given a text file that contains "random" hex characters.
**Input**: `504B03041400...`
**Action**:
1. Run `python scripts/deep_decode.py --file challenge.txt --extract-dir ./output`
2. Tool Output:
   - `format`: `hex`
   - `magic`: `ZIP`
   - `extracted_path`: `/.../extracted_a1b2.zip`
3. **Agent Outcome**: The tool found a ZIP file. **Do not** try to read the ZIP content as text. Instead, use `unzip` or `list_dir` on the `extracted_path`.

### Scenario 3: Mystery Cipher
**Context**: User asks "What does 'svool' mean?"
**Action**:
1. Run `python scripts/deep_decode.py --input "svool"`
2. Tool Output: `{"format": "atbash", "text": "hello"}`
3. **Agent Outcome**: Reply to user: "It appears to be Atbash cipher for 'hello'."

## Tips for Agents

- **Always check `magic`**: If the output JSON has a `magic` field (e.g., `PNG`, `ELF`), it is a BINARY file. Tell the user you extracted it.
- **Recursion is Automatic**: You don't need to manually decode Base64 then Gzip. The tool does it all in one pass.
- **Failures**: If `status` is `failed` and no candidates are found, the data might be encrypted with a strong key (AES) or is just random noise.
