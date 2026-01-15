| Label | Input | Expected |
| --- | --- | --- |
| **Encodings** | | |
| Base64-Text | `SGVsbG8sIHdvcmxkIQ==` | base64 -> "Hello, world!" |
| Base64-Image | `iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII=` | base64 -> PNG magic bytes |
| JWT | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdCIsImFkbWluIjpmYWxzZX0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c` | jwt -> header/payload JSON |
| URL | `name=Alice%20Smith&title=Senior%2BDev` | url -> querystring |
| Hex | `48656c6c6f2c20776f726c6421` | hex -> "Hello, world!" |
| HTML | `&lt;div&gt;Hello&nbsp;World&lt;/div&gt;` | html -> "<div>Hello World</div>" |
| Base32 | `JBSWY3DPEBLW64TMMQQQ====` | base32 -> "Hello World!" |
| Ascii85 | `<~87cURD]i,"Ebo80~>` | ascii85 -> "Hello World!" |
| Quoted-Printable | `=48=65=6C=6C=6F=20=57=6F=72=6C=64=21` | quoted-printable -> "Hello World!" |
| **Ciphers** | | |
| Rot13 | `Uryyb Jbeyq!` | rot13 -> "Hello World!" |
| Rot47 | `,Ight` | rot47 -> "x89E" (Wait, example?) -> `,Ight` rot47 is `x89E`? No, let's use `abc` -> `234`. `Hello` -> `w6==@`. |
| Atbash | `svool dliow` | atbash -> "hello world" |
| Rail Fence | `hlowrdelol` | rail_fence (2 rails) -> "helloworld" |
| XOR | (Hex) `3E333C3C39762139243A3277` | xor (key=0x56) -> "Hello World" |
| **Recursion** | | |
| Base64 -> Gzip | `H4sIAAAAAAAA/8tIzcnJVwjPL8pJ4QIAvZ0P/wwAAAA=` | base64 -> gzip -> "Hello World!" |
| Recursion (URL->B64) | `JTIySGVsbG8lMjI=` | url -> base64 -> "Hello" |
