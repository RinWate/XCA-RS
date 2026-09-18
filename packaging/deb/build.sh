#!/usr/bin/env bash
# Build a Debian package for xca-rs.
# Uses dpkg-deb when available; otherwise assembles the .deb manually
# with ar + tar (same layout: debian-binary, control.tar.gz, data.tar.xz).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
CARGO="${CARGO:-cargo}"
version="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$root/Cargo.toml" | head -n1)"
out="$root/xca-rs_${version}-1_amd64.deb"

"$CARGO" build --release --locked --manifest-path "$root/Cargo.toml"
bin="$root/target/release/xca-rs"
command -v strip >/dev/null && strip --strip-unneeded "$bin" || true

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
install -Dm755 "$bin" "$stage/usr/bin/xca-rs"
install -Dm644 "$root/packaging/org.xca.rs.desktop" "$stage/usr/share/applications/org.xca.rs.desktop"
install -Dm644 "$root/packaging/org.xca.rs.svg" "$stage/usr/share/icons/hicolor/scalable/apps/org.xca.rs.svg"

mkdir -p "$stage/DEBIAN"
cat > "$stage/DEBIAN/control" <<EOF
Package: xca-rs
Version: $version-1
Section: utils
Priority: optional
Architecture: amd64
Depends: libc6, libglib2.0-0t64 | libglib2.0-0, libgtk-4-1, libadwaita-1-0, libssl3t64 | libssl3
Maintainer: Denis "RinWate" Egorov <rinwate@yandex.ru>
Homepage: https://github.com/RinWate
Description: XCA rewritten in Rust with GTK4 and libadwaita
 Certificate and key management: private keys, certificates, CSRs, CRLs,
 PKCS#11 hardware tokens and SQLCipher-encrypted storage - a native GNOME
 restatement of XCA.
EOF

if command -v dpkg-deb >/dev/null; then
    dpkg-deb --build --root-owner-group "$stage" "$out"
else
    tmp="$(mktemp -d)"
    printf '2.0\n' > "$tmp/debian-binary"
    tar -C "$stage" --owner=0 --group=0 --numeric-owner -czf "$tmp/control.tar.gz" DEBIAN
    tar -C "$stage" --owner=0 --group=0 --numeric-owner -cJf "$tmp/data.tar.xz" usr
    rm -f "$out"
    (cd "$tmp" && ar rcD "$out" debian-binary control.tar.gz data.tar.xz)
    rm -rf "$tmp"
fi

echo "Built: $out"
