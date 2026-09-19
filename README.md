# XCA RS

A from-scratch rewrite of [XCA](https://github.com/chris2511/xca) (X Certificate
and Key Management) in **Rust**, with a **GTK4 + libadwaita** interface — the
same application concept as XCA (manage private keys, certificates, certificate
signing requests, revocation), restated as a native GNOME app. Besides the
classic RSA/EC/Ed25519 world it speaks **GOST**: CryptoPro-compatible keys,
containers, signatures and PDF stamps.

## Features

- **Private keys**: generate RSA 2048/3072/4096, EC P-256/P-384/P-521, Ed25519
  and GOST R 34.10-2012 (256/512-bit, through the OpenSSL gost engine —
  install `openssl-gost-engine`); store, export (PKCS#8 PEM), delete.
- **Certificates**: create self-signed CAs, issue certificates from a CA,
  validity, serial, SKI/AKI, basic constraints, key usage, EKU presets
  (server/client), subject alt names (typed XCA-style SAN editor: DNS / IP /
  email / URI entries with add/remove), subject title (T, used by GOST
  profiles); PEM (optionally with chain), DER and PKCS#12 / PFX export
  (optionally with the issuing chain, password-protected). The list shows the
  issuer CN and the signature algorithm; properties include the parsed
  signature algorithm.
- **Certificate requests (CSRs)**: create from subject + key, sign them with a
  CA from the database; the list shows whether a request is already signed.
- **Revocation**: revoke certificates (tracked per CA, `REVOKED` badge in the
  list), generate CRLs (with AKI and CRL Number) for any CA that has its key
  in the database, export CRLs as PEM.
- **Import**: PEM and DER files with certificates, requests and private keys;
  PKCS#12 bundles with password prompt; duplicate detection.
- **CryptoPro compatibility**: closed key containers (the `*.000` folders
  written by CryptoPro CSP — `header.key` / `masks.key` / `primary.key`, with
  CPKDF password derivation and GOST 28147-89 decryption implemented natively,
  no CryptoPro installation needed) and PFX files produced by CryptoPro CSP 5
  (including its GOST keybag scheme and passwordless PFX) import directly;
  the private key is linked to its certificate automatically.
- **File signatures (CMS)**: sign any file detached (`.p7s`) or attached
  (`.p7m`) with a certificate — and optionally its CA chain — from the
  database; verification shows a full report with the signer chain. Works
  with RSA, EC, Ed25519 and GOST certificates.
- **PDF signing**: sign PDFs in place with a visible stamp — pick the spot by
  clicking on a live page preview (rendered with poppler); the stamp shows the
  signer CN, date and time, title, organization and the certificate
  fingerprint (SHA-256). The signature is written as an incremental CMS
  update: the original content and any earlier signatures stay intact, and
  signing an already-signed document asks for confirmation. An invisible
  signature is a toggle away. The verify dialog extracts every embedded PDF
  signature, checks each revision against its certificate chain and warns
  about modifications made after signing.
- **PKCS#11 hardware tokens** (via the `cryptoki` crate): connect to a module,
  list token keys, and create a CA whose private key never leaves the token
  (TBS is signed on the token with CKM_SHA256_RSA_PKCS / pure EdDSA, the
  final certificate DER is assembled locally and verified). RSA and Ed25519
  token keys are supported for signing.
- **Native XCA database format**: xca-rs reads and writes the same `.xdb`
  SQLite database as the original XCA — open your existing XCA database
  directly and keep using it in both programs. Private keys are stored
  PKCS#8-encrypted (PBES2/AES) with the database password (`pwhash`
  scheme); set or change the password via the menu, unlock prompt on
  start. Databases of the earlier xca-rs-specific format (SQLCipher) are
  migrated automatically on first open (the original is kept as
  `*.old.bak`).
- **Database selection**: the menu (☰ → *Database*) can open an existing
  database or create a new one; the last used database is remembered in
  `~/.config/xca-rs/config.ini` and reopened on start. The default is
  `~/.local/share/xca-rs/xca-rs.db`; the `XCA_RS_DB` environment variable
  overrides everything.
- **Localization**: the UI is translatable; Russian is included. The language
  is detected from `LANG`/`LC_ALL` (or forced with `XCA_RS_LANG=ru|en`).

## Localization

Translations use [`rust-i18n`](https://crates.io/crates/rust-i18n): the files in
`locales/*.toml` are embedded into the binary at compile time, and source code
wraps user-visible strings in the `tr!()` macro (the English text doubles as
the lookup key, so a missing translation simply falls back to English).

To add a language:

1. create `locales/<lang>.toml` (copy `ru.toml`, translate the values);
2. rebuild — that's it; the locale is picked from `LANG` at startup.

Interpolation uses `%{name}` placeholders, e.g.
`tr!("Key “%{name}” created", name = label)`.

## Status / scope

A functional core, not a 1:1 port of XCA's ~37k lines of C++. Not covered
yet (see the original C++ code for reference):

- PKCS#11: browsing slot/key pickers are minimal (first token), EC token-key
  signing, moving/copying keys onto tokens, PIN change dialogs
- CRL distribution points, per-entry revocation reasons
- Certificate templates, database i18n; OpenSSL dumps and a few technical
  field subtitles remain English
- CSR extensions (the openssl crate cannot add them yet), NSPKI import
- PDF: encrypted documents are refused; signing assumes the whole file fits
  in memory

## Build and run

Dependencies (Arch names): `rust`, `gcc`, `pkgconf`, `gtk4`, `libadwaita`,
`openssl`, `poppler` (poppler-glib, for the PDF page preview), plus a C
compiler for the bundled SQLite/SQLCipher amalgamation. `openssl-gost-engine`
is optional and only needed for GOST keys and signatures.

```sh
cargo run --release
```

Tests (crypto round-trips, CRL building, DER assembly, PKCS#12, XCA-format
storage and interop, migration, GOST 28147-89 container/keybag decoding,
PDF signing):

```sh
cargo test
```

## Packaging

- **Arch Linux**: the [AUR](https://aur.archlinux.org) carries `xca-rs`
  (builds from the release tarball) and `xca-rs-bin` (installs the prebuilt
  binary from the GitHub release).
- **Debian**: `packaging/deb/build.sh` → `xca-rs_…_amd64.deb` (uses
  `dpkg-deb` when present, otherwise assembles the package with `ar`+`tar`).

The Debian script builds from the local working copy; the About dialog
credits Denis "RinWate" Egorov <rinwate@yandex.ru> (https://github.com/RinWate).

## License

GPL-2.0-or-later, like the original XCA.
