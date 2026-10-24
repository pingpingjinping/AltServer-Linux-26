#!/usr/bin/env bash
# Test Keeper's generator without mounting or changing the insurance instance.
set -Eeuo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
WORK=${ALTSERVER_TRIAL_DIR:-$HOME/altserver-keeper-auth-20261024}
NAME=anisette-keeper-v3-backend
UNIT=anisette-keeper-v3-bridge.service
FRESH_DROPIN=/run/systemd/system/anisette-keeper-v3-bridge.service.d/90-fresh-headers.conf
FRESH_STATE=$WORK/v3-fresh-state.plist
DROPIN=/run/systemd/system/altserver.service.d/90-keeper-auth-trial.conf
MARKER=$WORK/V3_BRIDGE_APPLIED
IMAGE=ghcr.io/pingpingjinping/altkeeper:latest
URL=https://ani3.stikstore.app
USER_AGENT='AuthKit/1 (Macintosh; OS X 26.5.2) (com.apple.dt.Xcode/26.0)'
die() { echo "ERROR: $*" >&2; exit 1; }
if [[ -f /opt/altserver-keeper-v3/APPLIED && ${1:-} != status ]]; then
    die 'Persistent deployment is active. Use sudo python3 scripts/keeper-v3-persist.py rollback first.'
fi
[[ $WORK = /* && $WORK != *[[:space:]]* ]] || die 'Use an absolute trial path without whitespace.'

rollback() {
    [[ -f $MARKER ]] || { echo 'No v3 bridge trial recorded.'; return; }
    sudo systemctl stop altserver.service
    sudo install -m 644 "$WORK/v3-previous-dropin" "$DROPIN"
    sudo systemctl daemon-reload
    sudo systemctl stop "$UNIT" || true
    sudo rm -f "$FRESH_DROPIN"
    rm -f "$FRESH_STATE"
    sudo systemctl daemon-reload
    sudo systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
    if sudo docker container inspect "$NAME" >/dev/null 2>&1; then
        sudo docker rm -f "$NAME" >/dev/null
    fi
    if [[ $(cat "$WORK/v3-previous-active") = active ]]; then
        sudo systemctl start altserver.service
    fi
    rm -f "$MARKER"
    echo 'Previous Anisette connection restored; original Keeper was unchanged.'
}

apply_trial() {
    [[ -f $WORK/APPLIED && -f $WORK/READY && -f $DROPIN ]] || die 'Apply the original AltServer trial first.'
    [[ ! -f $MARKER ]] || die 'V3 trial is already applied; use status or rollback.'
    [[ -f $ROOT/scripts/keeper_v3_anisette_bridge.py ]] || die 'Missing Python bridge.'
    local image_id
    image_id=$(sudo docker image inspect --format '{{.Id}}' "$IMAGE") || die 'The existing Keeper image is not available locally; no pull or rebuild was attempted.'
    if sudo docker container inspect "$NAME" >/dev/null 2>&1; then
        die 'Trial backend name is already in use.'
    fi
    [[ $(systemctl show "$UNIT" -p LoadState --value) = not-found ]] || die 'Trial bridge unit already exists.'
    for port in 14951 16971; do
        [[ -z $(sudo ss -ltnp "sport = :$port" | tail -n +2) ]] || die "Port $port is occupied."
    done
    (cd "$WORK/AltServer/build" && sha256sum -c "$WORK/SHA256SUMS")
    sudo cat "$DROPIN" > "$WORK/v3-previous-dropin"
    systemctl is-active altserver.service > "$WORK/v3-previous-active" || true
    # New state only. Do not copy /srv/altkeeper, account files or pairing records.
    mkdir -p "$WORK/keeper-v3-only-state"
    touch "$MARKER"
    trap 'rc=$?; trap - ERR; rollback; exit "$rc"' ERR
    sudo docker run -d --pull=never --name "$NAME" --restart no \
        --network bridge -p 127.0.0.1:14951:49500 \
        -v "$WORK/keeper-v3-only-state:/data" \
        -e "ALTKEEPER_ANISETTE_URL=$URL" \
        --entrypoint /usr/local/bin/altkeeper "$image_id" \
        altserver --port 49500 --dir /data >/dev/null
    sudo systemd-run --unit="$UNIT" --property="User=$(id -un)" \
        --property="Group=$(id -gn)" --property=NoNewPrivileges=yes \
        /usr/bin/python3 "$ROOT/scripts/keeper_v3_anisette_bridge.py" \
        --port 16971 --backend-port 14951 --client-info-url "$URL/v3/client_info"
    local ready=0
    for _ in {1..20}; do
        if curl -fsS --max-time 2 http://127.0.0.1:16971/healthz >/dev/null 2>&1; then
            ready=1; break
        fi
        sleep 1
    done
    [[ $ready = 1 ]]
    echo 'Generating isolated v3 Anisette state; no Apple ID login is requested...'
    if ! curl -fsS --max-time 100 http://127.0.0.1:16971/ -o "$WORK/v3-bridge-check.json"; then
        echo 'V3 generator failed; restoring the previous data source.' >&2
        trap - ERR
        rollback
        return 1
    fi
    python3 - "$WORK/v3-bridge-check.json" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
try:
    d = json.loads(p.read_text())
    required = ['X-Apple-I-MD', 'X-Apple-I-MD-M', 'X-Apple-I-MD-LU', 'X-Mme-Device-Id',
                'X-MMe-Client-Info', 'X-Apple-I-SRL-NO', 'X-Apple-I-Client-Time']
    assert all(isinstance(d.get(k), str) and d[k] for k in required)
    print('Keeper v3 data received (values redacted).')
finally:
    p.unlink(missing_ok=True)
PY
    printf '[Service]\nExecStart=\nExecStart=/usr/bin/env "ALTSERVER_ANISETTE_SERVER=http://127.0.0.1:16971" "ALTSERVER_GSA_USER_AGENT=%s" "%s/AltServer/build/AltServer-aarch64"\n' \
        "$USER_AGENT" "$WORK" | sudo tee "$DROPIN" >/dev/null
    sudo systemctl daemon-reload
    sudo systemctl restart altserver.service
    sleep 2
    systemctl is-active --quiet altserver.service
    trap - ERR
    echo 'AltServer now uses isolated Keeper v3 data. Actual phone refresh remains unverified.'
    echo "Restore previous data source: bash $ROOT/scripts/keeper-v3-anisette-trial.sh rollback"
}

refresh_identity() {
    [[ -f $MARKER ]] || die 'The v3 trial is not active; run apply first.'
    trap 'rc=$?; trap - ERR; rollback; exit "$rc"' ERR
    sudo systemctl restart "$UNIT"
    local ready=0
    for _ in {1..25}; do
        if curl -fsS --max-time 2 http://127.0.0.1:16971/healthz >/dev/null 2>&1; then
            ready=1; break
        fi
        sleep 1
    done
    [[ $ready = 1 ]]
    curl -fsS --max-time 100 http://127.0.0.1:16971/ -o "$WORK/v3-identity-check.json"
    python3 - "$WORK/v3-identity-check.json" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
try:
    data = json.loads(p.read_text())
    print('Forwarded client_info: ' + data['X-MMe-Client-Info'])
finally:
    p.unlink(missing_ok=True)
PY
    trap - ERR
    echo 'Provider identity refreshed; the phone authentication result remains unverified.'
}

check_bridge() {
    sudo systemctl daemon-reload || return 1
    sudo systemctl restart "$UNIT" || return 1
    local ready=0
    for _ in {1..25}; do
        if curl -fsS --max-time 2 http://127.0.0.1:16971/healthz >/dev/null 2>&1; then
            ready=1; break
        fi
        sleep 1
    done
    [[ $ready = 1 ]] || return 1
    curl -fsS --max-time 100 http://127.0.0.1:16971/ -o /dev/null
}

header_mode() {
    [[ -f $MARKER ]] || die 'The v3 trial is not active; run apply first.'
    local desired=$1 previous=cached
    [[ ! -f $FRESH_DROPIN ]] || previous=fresh
    [[ $desired != "$previous" ]] || { echo "Header mode is already $desired."; return; }
    if [[ $desired = fresh ]]; then
        # Copy only the isolated trial identity. The root-owned source is unchanged.
        sudo install -m 600 -o "$(id -u)" -g "$(id -g)" \
            "$WORK/keeper-v3-only-state/state/anisette_state" "$FRESH_STATE"
        python3 - "$ROOT/scripts/keeper_v3_anisette_bridge.py" "$FRESH_STATE" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('bridge', sys.argv[1])
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
try:
    bridge.read_fresh_state(sys.argv[2])
except Exception:
    sys.exit('The isolated trial state could not be validated (values redacted).')
PY
        sudo install -d -m 755 "$(dirname -- "$FRESH_DROPIN")"
        printf '[Service]\nEnvironment="ALTSERVER_ANISETTE_FRESH_STATE=%s"\n' "$FRESH_STATE" | \
            sudo tee "$FRESH_DROPIN" >/dev/null
    else
        sudo rm -f "$FRESH_DROPIN"
    fi
    if check_bridge; then
        if [[ $desired = cached ]]; then rm -f "$FRESH_STATE"; fi
        echo "Header mode switched to $desired; data generation check passed."
        echo 'No Apple ID login was attempted; phone refresh and HTTP 503 remain unverified.'
        return
    fi
    echo 'Header-mode check failed; restoring the previous header mode.' >&2
    if [[ $previous = fresh ]]; then
        printf '[Service]\nEnvironment="ALTSERVER_ANISETTE_FRESH_STATE=%s"\n' "$FRESH_STATE" | \
            sudo tee "$FRESH_DROPIN" >/dev/null
    else
        sudo rm -f "$FRESH_DROPIN"
    fi
    if ! check_bridge; then
        echo 'ERROR: The previous header mode also failed its check; inspect the trial bridge logs.' >&2
    fi
    if [[ $previous = cached ]]; then rm -f "$FRESH_STATE"; fi
    return 1
}

case ${1:-} in
    apply) apply_trial ;;
    refresh-identity) refresh_identity ;;
    fresh-headers) header_mode fresh ;;
    cached-headers) header_mode cached ;;
    rollback) rollback ;;
    status) sudo systemctl --no-pager status "$UNIT" || true; sudo docker ps -a --filter "name=^/$NAME$" ;;
    *) echo "Usage: bash $0 apply|refresh-identity|fresh-headers|cached-headers|status|rollback"; exit 2 ;;
esac
