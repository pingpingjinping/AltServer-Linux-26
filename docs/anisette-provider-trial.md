# Isolated provider comparison — 2026-10-25

## Evidence and scope

The user reported both 80046 and 503 with the Windows **Client-Info-only**
experiment, then only 503 after returning to the original configuration.
This is an observation from a small number of attempts, not proof of the
meaning of 80046 or a fix.

The next experiment uses `https://mac-ani.jkcoxson.com` and a newly provisioned
identity. [iLoader commit 9025975](https://github.com/nab138/iloader/commit/9025975)
selects this default and classifies both it and the existing
`ani3.stikstore.app` as Mac providers. [xtool PR 380](https://github.com/xtool-org/xtool/pull/380)
also selects this endpoint. Thus this is a **different Mac provider plus new
state**, not a demonstrated Android-to-Mac conversion. Neither a public label
nor `/v3/client_info` proves the physical implementation of a remote service.

A success would justify further comparison; it would not distinguish the
provider effect from the effect of starting with fresh state. The phone's
GrandSlam User-Agent and authentication implementation are unchanged.

## Isolation

- The persistent bridge, its `/opt/altserver-keeper-v3/anisette-state.plist`,
  original Keeper, accounts and pairing records are never mounted in the
  bootstrap container or sent to the new provider.
- Provisioning starts with an empty directory below `/run/altserver-identity-trial`.
  Only new Anisette provisioning material is exchanged with the provider and
  Apple's provisioning endpoints. No Apple ID login is requested.
- The helper uses the immutable local image ID referenced by the old
  `anisette-keeper-v3-backend` container, not a moving latest tag or the running
  insurance instance. No pull or build is performed.
- The temporary bootstrap only receives an `AnisetteDataRequest`. Its RPC is
  bound to loopback port 14952. It is stopped and removed by verified ID/label
  after extracting the new state. It has no USB/pairing/account mounts.
- The new state is mode 0600, readable by pi. The existing deployed bridge code
  runs on loopback 16972 using this state and the new provider's metadata.
- AltServer switches only after the new direct fresh-header response validates.
  Failures before the switch leave AltServer running on 16971; failures during
  the switch trigger rollback. Phone authentication outcomes remain manual.
- Runtime files disappear on reboot and the persistent setup returns. The
  provider and Client-Info-only trials use the same exclusive trial slot and
  cannot be applied on top of each other.

## Run on the Pi

The prior Client-Info trial must already be rolled back. Then:

```sh
cd ~/altserver-keeper-auth-src &&
git fetch origin codex/keeper-v3-data-20261024 &&
git restore --source=FETCH_HEAD -- \
  scripts/anisette-identity-trial.py \
  scripts/anisette-provider-trial.py &&
sudo python3 scripts/anisette-provider-trial.py apply
```

Wait for `Isolated provider trial active: jkcoxson-mac`. Then reopen AltStore,
refresh one app and record the exact outcome and time. A successful setup is
not proof that Apple authentication works. Any actual AltStore refresh must be
finished before beginning a Keeper-only expiry observation period.

If setup fails, paste its short error output first. Do not delete existing
states or rerun persistence installation. The helper may refuse unknown or
edited trial files to avoid overwriting unrelated changes.

## Status and rollback

```sh
sudo python3 ~/altserver-keeper-auth-src/scripts/anisette-provider-trial.py status
sudo journalctl -u anisette-identity-trial.service -n 20 --no-pager -o cat
```

To restore the persistent provider and port 16971:

```sh
sudo python3 ~/altserver-keeper-auth-src/scripts/anisette-provider-trial.py rollback
```

Use this provider helper to roll back this experiment, not the Client-Info
helper and not the persistence installer. The temporary provider state is
discarded; the original persistent state and Keeper are preserved.

The dashboard still monitors the persistent bridge. Use the trial status
command to verify the temporary path; the dashboard cannot verify Apple auth.

## Validation limits

Offline tests cover the exclusive trial slot, provider identity forwarding,
empty mount and pinned image selection, prepare failure cleanup, create timeout
recovery, ownership checks, endpoint rollback and unchanged baseline state.
Generated systemd units are syntax-checked. Real provisioning, deployed image
compatibility and phone refresh require execution on the Pi; no claim of live
success is made by these checks.
