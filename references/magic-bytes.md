| File type | Magic bytes (hex) | Extension |
| --- | --- | --- |
| **Images** | | |
| JPEG | `FF D8 FF` | .jpg |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | .png |
| GIF | `47 49 46 38` (GIF8...) | .gif |
| BMP | `42 4D` | .bmp |
| WEBP | `RIFF` ... `WEBP` | .webp |
| **Documents** | | |
| PDF | `25 50 44 46 2D` (%PDF-) | .pdf |
| MS Office (Legacy) | `D0 CF 11 E0 A1 B1 1A E1` | .doc / .xls |
| **Archives** | | |
| ZIP / JAR / APK | `50 4B 03 04` | .zip |
| GZIP | `1F 8B 08` | .gz |
| 7Z | `37 7A BC AF 27 1C` | .7z |
| RAR | `52 61 72 21 1A 07 00` | .rar |
| Deb | `21 2E 61 72 63 68` (!.arch) | .deb |
| **Executables/System** | | |
| ELF (Linux) | `7F 45 4C 46` | .bin |
| PE (Windows) | `4D 5A` (MZ) | .exe |
| Java Class | `CA FE BA BE` | .class |
| SQLite DB | `53 51 4C 69 74 65` | .db |
| **Media** | | |
| MP3 | `49 44 33` (ID3 tag) | .mp3 |
| MP4 | `... 66 74 79 70` (ftyp) | .mp4 |
| ZLIB | `78 01` / `78 9C` / `78 DA` | .zlib |
