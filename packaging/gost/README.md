# Embedded gost engine

`gost.so` is the OpenSSL **engine** build of
[gost-engine](https://github.com/gost-engine/engine), commit
`4632029f872981c9f969f1cee8b4fb590dab598b` (2026-09-25), built against
OpenSSL 3.5 with:

```sh
git clone --recursive https://github.com/gost-engine/engine
cmake -S engine -B engine/build -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=/usr \
  -DOPENSSL_ENGINES_DIR=/usr/lib/x86_64-linux-gnu/engines-3
cmake --build engine/build
# → engine/build/bin/gost.so
```

xca-rs embeds this module (`include_bytes!` from `src/crypto.rs`), unpacks
it into the user cache directory (`~/.cache/xca-rs/gost.so`) and loads it
through `OPENSSL_ENGINES` + `ENGINE_by_id` — so GOST keys and signatures
work on machines with no gost engine installed. A system gost provider or
engine, when present, takes precedence.

Why the engine and not the provider build (`gostprov.so`) from the same
sources: X509/CMS signature verification resolves digest algorithms
through the legacy name/sigid tables (`OBJ_add_sigid`,
`EVP_get_digestbynid`), which only the engine registers — with a pure
provider, `X509_verify` fails with "unknown message digest algorithm"
(checked against OpenSSL 3.5.5, see `ASN1_item_verify_ctx`).

The module links against `libcrypto.so.3` — rebuild it when raising the
baseline OpenSSL version.
