# WalnutPi: AltKeeper authentication comparison and reversible trial

This is an experiment, not a confirmed fix for Apple's GrandSlam `-80045`.
AltKeeper's successful profile renewal does not prove that AltStore's login,
signing or legacy Wi-Fi installation path will work after these changes.

## What transfers from Keeper

Compared with `pingpingjinping/altkeeper` at
`8cb2901df985266b172ee3b41d6d0eb11d637aa3`:

| Area | Finding / change |
| --- | --- |
| AuthKit client identity | Anisette26 advertised Mac17,3 / Xcode. Match Keeper's Mac15,7 / macOS 27.0 / com.apple.akd/1.0 defaults instead. |
| HTTP User-Agent | Keeper uses modern `AuthKit/1 ... Xcode/26.0`, not the older `akd/1.0 CFNetwork/808.1.4`. Retain the modern AltServer default and make it configurable with `ALTSERVER_GSA_USER_AGENT`. Match it in Anisette's `/v3/client_info` via `ANISETTE_USER_AGENT`. |
| Connection handling | AltServer26 already creates a fresh cpprest client and sends `Connection: close` for GrandSlam. Retain that implementation. |
| Accept header | Match Keeper's `text/x-xml-plist` for GrandSlam. |
| Timestamp | Generate an explicit UTC timestamp with exactly one `Z`, regardless of server timezone or fractional seconds. |
| Diagnostics | Remove raw Anisette payloads and authentication header values. Reject malformed or failed Anisette responses before constructing an authentication object. |
| Device communication | Keeper's remote pairing / tunnel is separate from authentication. This patch does not port that Rust stack into AltServer. |
| Anisette state | Keeper's per-client v3 provisioning state and this server's v1-compatible state are different. Do not copy Keeper's state into Anisette26. |

Reference implementation:
`vendor/isideload/src/anisette/remote_v3/mod.rs` and
`vendor/isideload/src/auth/grandslam.rs` in the Keeper commit above.
The earlier trial that switched AltServer to the old `akd/1.0` User-Agent is
superseded by this trial.

## Pi build and apply

Run as the normal `pi` user, with sudo access. This needs Docker, git, Python 3,
curl and an ARM64 Pi. Builds run before service changes, using one compiler
job. Anisette's image is pinned to Debian bookworm rather than moving stable.

```bash
git clone --branch codex/keeper-auth-20261024 \
  https://github.com/pingpingjinping/AltServer-Linux-26.git \
  ~/altserver-keeper-auth-src
cd ~/altserver-keeper-auth-src
bash scripts/keeper-auth-trial.sh prepare && \
  bash scripts/keeper-auth-trial.sh apply
```

The script copies the old `anisette` container's state into a separate trial
directory, starts `anisette-keeper-auth-trial` on localhost port **16970**, and
checks its identity, required OTP fields and clock. It leaves the old Anisette
container, images, source trees and state unchanged. The AltServer executable
is selected through a temporary `/run/systemd/system` drop-in. It does not
overwrite the original executable or enable any service or timer.

AltKeeper's files, `/srv/altkeeper`, containers and manual-only renewal setup
are never modified. If something listens on Keeper's AltServer port 49500, the
script refuses to apply rather than stopping it. The service must be a
`simple` or `exec` systemd service; other launch arrangements need inspection.

After service checks pass, unlock the phone and try one AltStore refresh.
Service health is not proof of a successful Apple login or refresh. If it
fails, record the error code and roll back. Do not publish unreviewed logs;
pre-existing code outside the changed diagnostics may contain account data.

```bash
bash ~/altserver-keeper-auth-src/scripts/keeper-auth-trial.sh status
bash ~/altserver-keeper-auth-src/scripts/keeper-auth-trial.sh rollback
```

An application failure automatically attempts rollback. Rollback removes only
the trial drop-in and container and restores whether AltServer was running.
Reboot also removes the temporary override; the trial container has no restart
policy. Failed / rolled-back trial data is retained under a timestamped name.
No certificate revocation, device unpairing, app reinstall or profile removal
is performed by the script.

Build logs are under `~/altserver-keeper-auth-20261024/`. A preflight failure
before the application marker leaves production services unchanged. If an
interrupted apply cannot clean up, run the rollback command above.
