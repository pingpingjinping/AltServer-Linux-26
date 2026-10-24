#!/usr/bin/env bash
# Test Keeper's generator without mounting or changing the insurance instance.
set -Eeuo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
WORK=${ALTSERVER_TRIAL_DIR:-$HOME/altserver-keeper-auth-20261024}
NAME=anisette-keeper-v3-backend
UNIT=anisette-keeper-v3-bridge.service
DROPIN=/run/systemd/system/altserver.service.d/90-keeper-auth-trial.conf
MARKER=$WORK/V3_BRIDGE_APPLIED
IMAGE=ghcr.io/pingpingjinping/altkeeper:latest
URL=https://ani3.stikstore.app
USER_AGENT='AuthKit/1 (Macintosh; OS X 26.5.2) (com.apple.dt.Xcode/26.0)'
die() { echo "ERROR: $*" >&2; exit 1; }
[[ $WORK = /* && $WORK != *[[:space:]]* ]] || die 'Use an absolute trial path without whitespace.'

rollback() {
    [[ -f $MARKER ]] || { echo 'No v3 bridge trial recorded.'; return; }
    sudo systemctl stop altserver.service
    sudo install -m 644 "$WORK/v3-previous-dropin" "$DROPIN"
    sudo systemctl daemon-reload
    sudo systemctl stop "$UNIT" || true
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
        --port 16971 --backend-port 14951
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

case ${1:-} in
    apply) apply_trial ;;
    rollback) rollback ;;
    status) sudo systemctl --no-pager status "$UNIT" || true; sudo docker ps -a --filter "name=^/$NAME$" ;;
    *) echo "Usage: bash $0 apply|status|rollback"; exit 2 ;;
esac
