# XCA RS

A from-scratch rewrite of [XCA](https://hohnstaedt.github.io/xca/) (X Certificate
and Key Management) in **Rust**, with a **GTK4 + libadwaita** interface — the
same application concept as XCA (manage private keys, certificates, certificate
signing requests, revocation), restated as a native GNOME app.

## Features

- **Private keys**: generate RSA 2048/3072/4096, EC P-256/P-384/P-521, Ed25519;
  store, export (PKCS#8 PEM), delete.
- **Certificates**: create self-signed CAs, issue certificates from a CA,
  validity, serial, SKI/AKI, basic constraints, key usage, EKU presets
  (server/client), subject alt names (typed XCA-style SAN editor: DNS / IP /
  email / URI entries with add/remove); PEM (optionally with chain), DER and
  PKCS#12 / PFX export (optionally with the issuing chain, password-protected).
- **Certificate requests (CSRs)**: create from subject + key, sign them with a
  CA from the database.
- **Revocation**: revoke certificates (tracked per CA, `REVOKED` badge in the
  list), generate CRLs (with AKI and CRL Number) for any CA that has its key
  in the database, export CRLs as PEM.
- **Import**: PEM and DER files with certificates, requests and private keys;
  PKCS#12 bundles with password prompt; duplicate detection.
- **Details view**: parsed fields plus the full OpenSSL text dump.
- **Native XCA database format**: xca-rs reads and writes the same `.xdb`
  SQLite database as the original XCA — open your existing XCA database
  directly and keep using it in both programs. Private keys are stored
  PKCS#8-encrypted (PBES2/AES) with the database password (`pwhash`
  scheme); set or change the password via the menu, unlock prompt on
  start. Databases of the earlier xca-rs-specific format (SQLCipher) are
  migrated automatically on first open (the original is kept as
  `*.old.bak`).
- **PKCS#11 hardware tokens** (via the `cryptoki` crate): connect to a module,
  list token keys, and create a CA whose private key never leaves the token
  (TBS is signed on the token with CKM_SHA256_RSA_PKCS / pure EdDSA, the
  final certificate DER is assembled locally and verified). RSA and Ed25519
  token keys are supported for signing.
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

## Build and run

Dependencies (Arch names): `rust`, `gtk4`, `libadwaita`, `openssl`, plus a C
compiler for the bundled SQLite/SQLCipher amalgamation.

```sh
cargo run --release
```

Tests (crypto round-trips, CRL building, DER assembly, PKCS#12, XCA-format
storage and interop, migration):

```sh
cargo test
```

## Packaging

- **Arch**: `cd packaging && makepkg -f` → `xca-rs-…-x86_64.pkg.tar.zst`
  (installs `/usr/bin/xca-rs`, a desktop file and an icon).
- **Debian**: `packaging/deb/build.sh` → `xca-rs_…_amd64.deb` (uses
  `dpkg-deb` when present, otherwise assembles the package with `ar`+`tar`).

Both build from the local working copy; the About dialog credits
Denis "RinWate" Egorov <rinwate@yandex.ru> (https://github.com/RinWate).

## License

GPL-2.0-or-later, like the original XCA.
