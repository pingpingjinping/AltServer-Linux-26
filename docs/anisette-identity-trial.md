# Temporary Client-Info comparison

This trial changes only the `X-MMe-Client-Info` returned to AltServer. It does
not install a Windows ADI implementation or change the phone's GrandSlam
User-Agent. The current provider, provider request UA, isolated ADI state,
AltServer binary and original Keeper remain unchanged.

The existing persistent bridge remains on 16971. A temporary Python service
imports its deployed code and reads the same isolated state, serving altered
response Client-Info on loopback 16972. A runtime-only AltServer drop-in selects
16972 after a data generation check passes. No Apple account login is performed
by the installer. Setup failures trigger rollback; phone refresh failures do not
trigger automatic rollback because the Pi cannot observe their outcome.

All trial files are under `/run`. Reboot clears the experiment and restores the
persistent configuration. The trial neither enables a new boot service nor
modifies the persistence installer's files or manifest.

## Apply on the Pi

```sh
cd ~/altserver-keeper-auth-src &&
git fetch origin codex/keeper-v3-data-20261024 &&
git restore --source=FETCH_HEAD -- scripts/anisette-identity-trial.py &&
sudo python3 scripts/anisette-identity-trial.py apply windows
```

Wait for `Client-Info-only trial active: windows`, then reopen AltStore and
refresh one app. Record success or the exact error and time. A single success
is not evidence of a fix: the baseline already succeeds intermittently.
Doing an actual AltStore refresh also interrupts a Keeper-only expiry
experiment for that app; finish these comparisons before beginning that
observation period.

The Windows string comes from the **unmerged**
[SideSign PR 8](https://github.com/SideStore/SideSign/pull/8). That proposal
changes several other things; this experiment deliberately tests one field.
An optional `apply android` profile uses the string reported in
[SideSign PR 5](https://github.com/SideStore/SideSign/pull/5). Roll back before
switching profiles; neither profile is a proven solution for this phone.

## Status and rollback

```sh
sudo python3 ~/altserver-keeper-auth-src/scripts/anisette-identity-trial.py status
sudo journalctl -u anisette-identity-trial.service -n 20 --no-pager -o cat
```

No OTP, ADI blob or account credentials are logged by this trial.

To return to the current persistent provider Client-Info and port 16971:

```sh
sudo python3 ~/altserver-keeper-auth-src/scripts/anisette-identity-trial.py rollback
```

Use this rollback for this experiment, **not** `keeper-v3-persist.py rollback`.
Before removing the persistent deployment, undo this temporary experiment.
After reboot, this rollback reports that no temporary experiment is installed.

The existing dashboard monitors the persistent bridge, which remains active.
Its Running label does not verify the trial bridge, Apple authentication, or
phone refresh. Use the trial status command above to check the selected path.

## Offline validation

```sh
python3 -m unittest discover -s tests -p 'test_anisette_identity_trial.py'
python3 -m unittest discover -s tests -p 'test_fresh_anisette_bridge.py'
```

Checks cover response-only changes, unchanged provider identity, failed
provider checks before switching, rollback after a failed endpoint check,
refusal to overwrite edited trial files, and unchanged permanent/ADI files.
