#!/usr/bin/env bash
# Run as the Linux desktop user after cargo build --release.
set -eu
export LC_ALL=C
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
bin="${CARGO_TARGET_DIR:-$repo/target}/release/airpods"
"$bin" --help >/dev/null
log=$(mktemp "${TMPDIR:-/tmp}/airpods-arbitration-XXXXXXXX.log")
echo "Saving daemon and connection events to $log"
restore=no
pid=
cleanup() {
    if [[ -n $pid ]]; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" || true
    fi
    if [[ $restore == yes ]]; then systemctl --user start airpods.service; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if systemctl --user is-active --quiet airpods.service; then
    restore=yes
    systemctl --user stop airpods.service
fi
if busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s com.apple.Airpods | grep -q true; then
    echo "An independently launched AirPods daemon is running. Stop that copy and rerun." >&2
    exit 1
fi
RUST_LOG=info "$bin" daemon >>"$log" 2>&1 &
pid=$!
for ((i=0; i<100; i++)); do
    grep -q 'Daemon ready' "$log" && break
    kill -0 "$pid" 2>/dev/null || break
    sleep .1
done
if ! grep -q 'Daemon ready' "$log"; then tail -12 "$log"; exit 1; fi
printf 'Linux Connect requested %s\n' "$(date -u +%FT%TZ)" >>"$log"
echo 'Connecting Linux once. Leave Linux audio paused. If iPhone playback stops, tap Play there once.'
timeout 20 "$bin" up >>"$log" 2>&1 || true
sleep 30
grep -E 'Arbitration|Reconnecting the AirPods|L2CAP connection attempt|Handshake|Features acknowledged' "$log" || true
