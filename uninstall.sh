#!/usr/bin/env bash
# Removes FIMEY-FIM from this host. Records are archived (audit trail) unless you purge them.
#   ./uninstall.sh [--purge] [--delete-folder]
#   --purge          also delete the archived records (*.archive-*)
#   --delete-folder  also delete this downloaded project folder
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
PURGE=0; DELDIR=0
for a in "$@"; do case "$a" in --purge) PURGE=1;; --delete-folder) DELDIR=1;; esac; done
ask() { [ -t 0 ] || return 1; read -r -p "$1 [y/N]: " r; [ "${r,,}" = "y" ]; }
ts=$(date +%Y%m%d%H%M%S)
$SUDO systemctl disable --now fimeyfim 2>/dev/null || true
$SUDO pkill -x fimeyfim 2>/dev/null || true
$SUDO rm -f /etc/systemd/system/fimeyfim.service /usr/local/bin/fimeyfim
$SUDO systemctl daemon-reload 2>/dev/null || true
for d in /var/lib/fimeyfim /var/log/fimeyfim; do
  if [ -e "$d" ]; then $SUDO mv "$d" "$d.archive-$ts"; fi
done
echo "FIMEY-FIM removed. A later install starts from scratch. TFC copies were not touched."
if [ $PURGE -eq 1 ] || ask "Delete the archived records (audit trail) too?"; then
  $SUDO rm -rf /var/lib/fimeyfim.archive-* /var/log/fimeyfim.archive-*; echo "Archived records deleted."
else echo "Records kept as /var/lib/fimeyfim.archive-* and /var/log/fimeyfim.archive-*"; fi
if [ $DELDIR -eq 1 ] || ask "Delete this project folder ($DIR)?"; then
  if [ -f "$DIR/Cargo.toml" ] && grep -q 'name = "fimeyfim"' "$DIR/Cargo.toml"; then cd /; rm -rf "$DIR"; echo "Project folder deleted."
  else echo "Not deleted: $DIR does not look like the FIMEY-FIM project."; fi
fi
