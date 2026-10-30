#!/usr/bin/env bash
# FIMEY-FIM installer - ALWAYS a fresh install.
# Anything left by a previous install (service, program, records) is archived/removed, and nothing is
# configured: you set it up manually (fim init -> fim add -tfc -> add files).
# To update the program and KEEP your records, run:  ./install.sh --upgrade
set -euo pipefail
cd "$(dirname "$0")"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
find_cargo() {
  command -v cargo && return 0
  for h in "${HOME:-/root}" "/home/${SUDO_USER:-nobody}" /root; do
    if [ -x "$h/.cargo/bin/cargo" ]; then export CARGO_HOME="$h/.cargo" RUSTUP_HOME="$h/.rustup"; echo "$h/.cargo/bin/cargo"; return 0; fi
  done
  return 1
}
if [ -d src ]; then
  if CARGO=$(find_cargo); then
    PATH="$(dirname "$CARGO"):$PATH" "$CARGO" build --release --locked; SRC="$PWD/target/release/fimeyfim"
  elif [ -x target/release/fimeyfim ] && [ target/release/fimeyfim -nt src/main.rs ]; then
    echo "Cargo not found - using the up-to-date build in target/release/fimeyfim"; SRC="$PWD/target/release/fimeyfim"
  elif [ -x fimeyfim ]; then SRC="$PWD/fimeyfim"
  else
    cat >&2 <<'MSG'
Rust (cargo) was not found. Install it and run ./install.sh again:
  sudo apt install -y cargo                                   (Kali / Debian / Ubuntu)
  curl --proto '=https' -sSf https://sh.rustup.rs | sh        (any Linux; then: source ~/.cargo/env)
Or download the prebuilt binary from the GitHub Releases page, save it here as ./fimeyfim, and run ./install.sh.
MSG
    exit 1
  fi
else SRC="$PWD/fimeyfim"; [ -x "$SRC" ] || { echo "Binary ./fimeyfim not found next to install.sh" >&2; exit 1; }; fi
BIN=/usr/local/bin/fimeyfim
if [ "${1:-}" = "--upgrade" ]; then $SUDO "$SRC" --upgrade; exit; fi
ts=$(date +%Y%m%d%H%M%S)
$SUDO systemctl disable --now fimeyfim 2>/dev/null || true
$SUDO pkill -x fimeyfim 2>/dev/null || true
$SUDO rm -f /etc/systemd/system/fimeyfim.service "$BIN"
$SUDO systemctl daemon-reload 2>/dev/null || true
for d in /var/lib/fimeyfim /var/log/fimeyfim; do
  if [ -e "$d" ]; then $SUDO mv "$d" "$d.archive-$ts"; echo "Archived previous records: $d.archive-$ts"; fi
done
$SUDO install -m 0755 "$SRC" "$BIN"
echo "Fresh install complete. Nothing is configured. Next: sudo fimeyfim -> fim init -> fim add -tfc <dir> -> add files."
