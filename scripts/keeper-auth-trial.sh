#!/usr/bin/env bash
# Isolated, reversible WalnutPi trial. Never modifies AltKeeper or old Anisette.
set -Eeuo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
WORK=${ALTSERVER_TRIAL_DIR:-$HOME/altserver-keeper-auth-20261024}
NAME=anisette-keeper-auth-trial
IMAGE=anisette-keeper-auth:20261024
PORT=16970
DROPIN=/run/systemd/system/altserver.service.d/90-keeper-auth-trial.conf
ANI_COMMIT=698f5d417e38f75c59230b6ecc4786a3a071dcc7
CLIENT_INFO='<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>'
USER_AGENT='AuthKit/1 (Macintosh; OS X 26.5.2) (com.apple.dt.Xcode/26.0)'

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $WORK = /* && $WORK != *[[:space:]]* ]] || die 'Trial directory must be an absolute path without whitespace.'
[[ $(uname -m) = aarch64 ]] || die 'This trial requires the ARM64 Pi.'

prepare() {
    command -v git >/dev/null
    sudo docker info >/dev/null
    mkdir -p "$WORK"
    local commit
    commit=$(git -C "$ROOT" rev-parse HEAD)
    if [[ ! -d $WORK/AltServer/.git ]]; then
        git clone --no-hardlinks "$ROOT" "$WORK/AltServer"
    fi
    [[ $(git -C "$WORK/AltServer" rev-parse HEAD) = "$commit" ]] || die 'Existing trial sources have a different commit; choose a new ALTSERVER_TRIAL_DIR.'
    git -C "$WORK/AltServer" diff --quiet || die 'Trial sources have local changes.'
    git -C "$WORK/AltServer" submodule update --init --recursive -- libraries/
    if [[ ! -d $WORK/Anisette/.git ]]; then
        git clone https://github.com/pingpingjinping/Anisette-server-26.git "$WORK/Anisette"
        git -C "$WORK/Anisette" checkout --detach "$ANI_COMMIT"
    fi
    [[ $(git -C "$WORK/Anisette" rev-parse HEAD) = "$ANI_COMMIT" ]] || die 'Unexpected Anisette commit.'
    git -C "$WORK/Anisette" diff --quiet || die 'Trial Anisette sources have local changes.'
    mkdir -p "$WORK/AltServer/build"
    echo 'Building AltServer (one compiler job to limit Pi memory use)...'
    sudo docker run --rm -v "$WORK/AltServer:/workdir" -w /workdir/build \
        ghcr.io/nyamisty/altserver_builder_alpine_aarch64 \
        bash -c 'make -f ../Makefile -j1' > "$WORK/altserver-build.log" 2>&1 || {
            tail -60 "$WORK/altserver-build.log"; return 1;
        }
    sudo chown -R "$(id -u):$(id -g)" "$WORK/AltServer/build"
    chmod 755 "$WORK" "$WORK/AltServer" "$WORK/AltServer/build"
    chmod 755 "$WORK/AltServer/build/AltServer-aarch64"
    timeout 15 "$WORK/AltServer/build/AltServer-aarch64" -h > "$WORK/altserver-help.log" 2>&1
    echo 'Building Anisette...'
    sudo docker build -t "$IMAGE" "$WORK/Anisette" > "$WORK/anisette-build.log" 2>&1 || {
        tail -60 "$WORK/anisette-build.log"; return 1;
    }
    sudo docker run --rm "$IMAGE" --help > "$WORK/anisette-help.log" 2>&1
    (cd "$WORK/AltServer/build" && sha256sum AltServer-aarch64) > "$WORK/SHA256SUMS"
    sudo docker image inspect --format '{{.Id}}' "$IMAGE" > "$WORK/image-id"
    printf '%s\n' "$commit" > "$WORK/commit"
    touch "$WORK/READY"
    echo "Build checks passed. Apply: bash $ROOT/scripts/keeper-auth-trial.sh apply"
}

rollback() {
    [[ -f $WORK/APPLIED ]] || { echo 'No recorded trial to roll back.'; return; }
    sudo systemctl stop altserver.service
    sudo rm -f -- "$DROPIN"
    sudo systemctl daemon-reload
    if sudo docker container inspect "$NAME" >/dev/null 2>&1; then
        sudo docker rm -f "$NAME" >/dev/null
    fi
    if [[ -d $WORK/anisette-data ]]; then
        mv "$WORK/anisette-data" "$WORK/anisette-data.saved.$(date +%s)"
    fi
    if [[ $(cat "$WORK/previous-active") = active ]]; then
        sudo systemctl start altserver.service
    fi
    rm -f "$WORK/APPLIED"
    echo 'Original AltServer configuration restored. AltKeeper and original Anisette were left intact.'
}

apply_trial() {
    [[ -f $WORK/READY ]] || die 'Run prepare first.'
    [[ ! -f $WORK/APPLIED && ! -e $DROPIN ]] || die 'Trial is already applied; use status or rollback.'
    [[ $(systemctl show altserver.service -p LoadState --value) = loaded ]] || die 'altserver.service was not found.'
    local service_type
    service_type=$(systemctl show altserver.service -p Type --value)
    [[ $service_type = simple || $service_type = exec ]] || die "Service type is $service_type; inspect the service before applying."
    if sudo docker container inspect "$NAME" >/dev/null 2>&1; then
        die "Container $NAME already exists; refusing to overwrite it."
    fi
    # AltKeeper's optional AltServer listener must not compete with this trial.
    if [[ -n $(sudo ss -ltnp 'sport = :49500' | tail -n +2) ]]; then
        die 'Port 49500 is in use. Leave Keeper intact and inspect its running mode before applying.'
    fi
    (cd "$WORK/AltServer/build" && sha256sum -c "$WORK/SHA256SUMS")
    [[ $(sudo docker image inspect --format '{{.Id}}' "$IMAGE") = "$(cat "$WORK/image-id")" ]] || die 'Trial image changed after build.'
    sudo docker inspect anisette > "$WORK/original-anisette.json"
    local data_target
    data_target=$(python3 - "$WORK/original-anisette.json" <<'PY'
import json, sys
mounts = json.load(open(sys.argv[1]))[0]['Mounts']
matches = [m['Destination'] for m in mounts if m['Destination'].rstrip('/').endswith('/anisette-v3')]
if len(matches) != 1:
    sys.exit('Cannot identify exactly one existing Anisette state mount; no service changes made.')
print(matches[0])
PY
    )
    [[ ! -e $WORK/anisette-data ]] || die 'Anisette trial data already exists; choose a new ALTSERVER_TRIAL_DIR.'
    mkdir "$WORK/anisette-data"
    sudo docker cp "anisette:$data_target/." "$WORK/anisette-data/"
    sudo chown -R 1000:1000 "$WORK/anisette-data"
    systemctl is-active altserver.service > "$WORK/previous-active" || true
    sudo systemctl cat altserver.service > "$WORK/original-altserver.service"
    touch "$WORK/APPLIED"
    trap 'rc=$?; trap - ERR; rollback; exit "$rc"' ERR
    sudo docker run -d --name "$NAME" --restart no \
        -p "127.0.0.1:$PORT:6969" \
        -e TZ=UTC -e "ANISETTE_CLIENT_INFO=$CLIENT_INFO" -e "ANISETTE_USER_AGENT=$USER_AGENT" \
        -v "$WORK/anisette-data:/home/Alcoholic/.config/anisette-v3" "$IMAGE" >/dev/null
    local ready=0
    for _ in {1..30}; do
        if curl -fsS --max-time 2 "http://127.0.0.1:$PORT/v3/client_info" -o "$WORK/client-info.json"; then
            ready=1; break
        fi
        sleep 1
    done
    [[ $ready = 1 ]]
    curl -fsS --max-time 15 "http://127.0.0.1:$PORT/" -o "$WORK/anisette-response.json"
    python3 - "$WORK/anisette-response.json" "$CLIENT_INFO" <<'PY'
import datetime, json, pathlib, sys
p = pathlib.Path(sys.argv[1])
try:
    d = json.loads(p.read_text())
    assert d['X-MMe-Client-Info'] == sys.argv[2], 'Unexpected client identity'
    for k in ['X-Apple-I-MD', 'X-Apple-I-MD-M', 'X-Mme-Device-Id', 'X-Apple-I-MD-LU']:
        assert isinstance(d[k], str) and d[k], 'Missing ' + k
    stamp = datetime.datetime.strptime(d['X-Apple-I-Client-Time'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
    assert abs((datetime.datetime.now(datetime.timezone.utc) - stamp).total_seconds()) < 120, 'Anisette clock differs from system clock'
    print('Anisette identity, OTP fields and UTC timestamp checks passed (values redacted).')
finally:
    p.unlink(missing_ok=True)
PY
    sudo install -d -m 755 "$(dirname "$DROPIN")"
    # ExecStart's env assignments take precedence even over an old EnvironmentFile.
    printf '[Service]\nExecStart=\nExecStart=/usr/bin/env "ALTSERVER_ANISETTE_SERVER=http://127.0.0.1:%s" "ALTSERVER_GSA_USER_AGENT=%s" "%s/AltServer/build/AltServer-aarch64"\n' \
        "$PORT" "$USER_AGENT" "$WORK" | sudo tee "$DROPIN" >/dev/null
    sudo systemctl daemon-reload
    sudo systemctl restart altserver.service
    sleep 2
    systemctl is-active --quiet altserver.service
    local pid
    pid=$(systemctl show altserver.service -p MainPID --value)
    [[ $(sudo readlink -f "/proc/$pid/exe") = "$WORK/AltServer/build/AltServer-aarch64" ]]
    trap - ERR
    echo 'Trial service is running. Real Apple login/refresh still needs an on-phone test.'
    echo "Rollback: bash $ROOT/scripts/keeper-auth-trial.sh rollback"
    echo 'This override is temporary: reboot restores the original service configuration.'
}

case ${1:-} in
    prepare) prepare ;;
    apply) apply_trial ;;
    rollback) rollback ;;
    status) systemctl --no-pager --full status altserver.service || true; sudo docker ps -a --filter "name=^/$NAME$" ;;
    *) echo "Usage: bash $0 prepare|apply|status|rollback"; exit 2 ;;
esac
