# LarvSecurity — Local-First Desktop Security Toolkit

A production-quality **desktop security workstation written in Rust**: password generation,
JWT signing/decoding/verification, authenticated encryption, hashing, key generation,
encoding utilities, and secure random generation — all running **locally on your machine**.
No servers, no telemetry, no network calls.

![Rust](https://img.shields.io/badge/rust-stable-orange)
![GUI](https://img.shields.io/badge/gui-egui%20%2F%20eframe-blue)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green)

## Features

| Tool | What it does |
|---|---|
| **Password Generator** | Random passwords (CSPRNG, configurable policy), passphrases + diceware wordlists, PINs, pattern generator, entropy analysis, crack-time simulator, bulk generation (500/API keys), opt-in breach check (k-anonymity) |
| **JWT Generator** | Sign tokens with HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512. Claim templates, payload presets, session history, cURL/Python/JS/Rust snippets, JWE (`dir`+A256GCM) |
| **JWT Decoder** | Split header / payload / signature, pretty JSON. Decoding never verifies |
| **JWT Verifier** | Pinned-algorithm signature verification + `exp`/`nbf`/`iss`/`aud` inspection with clear warnings |
| **Authenticator** | TOTP/HOTP (RFC 6238/4226, SHA-1/256/512), live codes, QR handoff, verify box |
| **Vault** | Master-password vault (AES-256-GCM + Argon2id) for logins + secure notes, auto-lock timer, panic lock, seal/open vault files |
| **Encrypt / Decrypt** | AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305. Password mode via Argon2id or raw-key mode. Text + file support |
| **Signatures / HMAC** | RSA PKCS#1/PSS + ECDSA file signing, standalone HMAC-SHA-2 tags |
| **SSH Keys / Certificates** | ed25519 + RSA OpenSSH keypairs with fingerprints; read-only X.509 inspector |
| **Checksums / Shredder** | Folder manifests (build + verify), 1/3/7-pass file shredding |
| **Hash Generator** | SHA-256/384/512, SHA3-256/512, BLAKE3 (+ legacy MD5/SHA-1, labeled). Streamed file hashing. Argon2id / PBKDF2 / scrypt |
| **Key Generator** | AES/ChaCha symmetric keys, RSA 2048/3072/4096 (background thread), EC P-256/P-384/P-521 PEM export |
| **Dev tools** | JSON format/validate/sort, timestamp converter, cron explainer, regex tester, line diff, QR (unicode + SVG) |
| **Encoding** | Base64, Base64URL, Hex, URL encode/decode — labeled as *not encryption* |
| **Random Generator** | Hex/Base64 bytes, URL-safe tokens, UUID v4, uniform integers, all from the OS CSPRNG |
| **Activity** | In-memory audit log (actions only), pinned tools, session timer, export |
| **Appearance** | Dark / light / system, 6 accents, font size + custom fonts, UI scale, corners, motion toggle, EN/AR chrome, portable workspace file |

Cross-cutting: command palette (`Ctrl+K`), pinned tools, clipboard auto-clear, secrets cleared on tool switch,
`zeroize` on sensitive buffers, structured errors (never panics, never logs secrets).
Workspace file (`LarvSecurity-config.json`) persists appearance + favorites + presets — never secrets.
Two features use network, both strictly opt-in and off by default: breach check (k-anonymity) and the release update check.

## Security model

- Only audited crates do crypto (`aes-gcm`, `chacha20poly1305`, `argon2`, `rsa`, `p256`/`p384`/`p521`,
  `sha2`/`sha3`/`blake3`, `hmac`, `rand` with `OsRng`). No custom primitives, no `unsafe` crypto.
- Verification **pins the expected algorithm** — the token's `alg` header is never trusted.
- Passwords are never used as keys directly (Argon2id KDF); fresh random nonce + salt every time.
- This tool protects against weak choices and accidents — it cannot protect a compromised OS.
  No `100% secure` claims, ever.

## Build & run

Requires a [Rust toolchain](https://rustup.rs/) (stable).

```bash
cargo run            # debug build + launch GUI
cargo test           # 46 unit tests (vectors, roundtrips, tamper checks)
cargo build --release
```

Windows / macOS / Linux supported via `eframe`.

## Project layout

```text
src/
├── main.rs            # eframe entry point
├── app/               # ToolkitApp, navigation, theme, central state
├── ui/                # one module per tool + sidebar, components, background FX
├── crypto/            # crypto/service layer (UI never touches primitives)
├── models/            # configs, JWT/cipher types, structured errors
└── utils/             # clipboard auto-clear, validation, secure memory
```

## License

MIT OR Apache-2.0.
