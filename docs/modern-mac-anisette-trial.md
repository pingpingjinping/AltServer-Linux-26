# Fresh modern-Mac anisette trial

This adds the first three selected SideInstaller v1.6.1 improvements to the
existing persistent Keeper v3 adapter deployment:

1. Retry provider `get_headers` HTTP 5xx responses, at most three requests with
   one second between retries. A 4xx response, I/O timeout or malformed response
   fails immediately. Apple account authentication is never retried here.
2. Replace the direct-provider path's 90-second I/O timeout with five seconds
   per socket operation and a 20-second retry window. Check the window between
   body reads and before further attempts. These are transport/retry bounds,
   not a hard real-time guarantee for OS DNS resolution or the entire Classic
   workflow. Provider response size is limited. Existing cached Keeper RPC mode
   retains its old behavior.
3. Provision a new isolated Mac identity with the same Client-Info and UA used
   by the trial. Mac providers advertising macOS older than 10.13 are upgraded
   to SideStore's MacBookPro18,3/macOS 26.6 profile. Already-current Mac metadata
   is preserved. The new state's provider, Client-Info and UA are recorded and
   checked before serving it; an old or mismatched state is refused.

The fresh provisioning protocol follows the v3 identifier/start/end/success
exchange used by [SideInstaller v1.6.1](https://github.com/FrizzleM/SideInstaller/commit/54be3fa683db4fde8fa243d057664e9d90a0062d).
It uses Python's standard library and verified TLS, with bounded WebSocket
messages and validated handshake acceptance. It sends no Apple ID, password,
pairing record or existing ADI state to the provider. New machine provisioning
does not create app identifiers or install iPhone profiles.

SMS requests and trusted-device authentication are unchanged. This is not an
implementation of AltStore PR #1851 and does not change the iPhone app's own
authentication User-Agent. Successful header generation does not establish
that Classic login or refresh will succeed.

## Prerequisite and apply

This helper targets the persistent deployment created by `keeper-v3-persist.py`:
`altserver.service` and `anisette-keeper-v3.service` must be active, and the
existing binary, state and service drop-in must match the expected layout.
Other identity/provider trials must be rolled back first. Do not overwrite
existing runtime trial paths by hand.

The apply command uses the fixed Mac provider `https://mac-ani.jkcoxson.com`,
the same provider as the earlier isolated provider trial. It does not rotate
providers automatically. It creates new state under `/run`, validates provider
headers before switching AltServer to localhost port 16972, and adjusts the
Pi process's UA to the chosen profile. Original files under
`/opt/altserver-keeper-v3`, original boot configuration and AltKeeper remain
untouched. Runtime service files disappear at reboot, restoring the baseline.

From a checkout containing these scripts:

```sh
sudo python3 scripts/anisette-modern-mac-trial.py apply
sudo python3 scripts/anisette-modern-mac-trial.py status
```

If apply fails during provisioning or header validation it restores the
baseline before switching the phone-facing endpoint. A failed switch also
attempts baseline restoration. Edited service files are protected by the
existing controller's checksum checks. If restoration cannot finish, retain
the runtime trial directory and run the rollback command after fixing the
service problem.

Apply alone does not sign in to an Apple account or refresh an app. Test
Classic refresh separately once apply has succeeded. The first login after
the machine identity changes may ask for two-factor verification.

### Diagnose a provisioning transport failure

```sh
sudo python3 scripts/anisette-modern-mac-trial.py diagnose
```

This performs only public provider metadata and Apple URL-bag GETs. It does
not create a machine identity, read ADI state, change services, log in or
install profiles. Use the same user/sudo environment as the failed apply.
Errors show a fixed phase name and safe typed details (DNS/errno, TLS reason
or certificate verification code, timeout, or HTTP status). Opaque exception
messages, response bodies, URLs and private provisioning values are redacted.
Apply also reports its actual failing phase, including Apple start/finish
provisioning and the provider WebSocket. A successful diagnosis does not test
those later steps; apply remains necessary to exercise them. TLS certificate
verification remains enabled.

## Rollback

```sh
sudo python3 scripts/anisette-modern-mac-trial.py rollback
```

The helper removes only its own unchanged runtime overrides and new identity,
then restores the previous endpoint. A trial applied by a different helper
must be rolled back by that helper. After reboot the runtime trial is already
gone, so rollback is a no-op.

## Validation

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile scripts/*.py
bash -n scripts/keeper-auth-trial.sh scripts/keeper-v3-anisette-trial.sh
```

Offline tests cover provider 5xx recovery, exhausted retries, 4xx/timeouts,
response bounds, Mac metadata selection, matching provisioning headers, state
isolation and rejection, WebSocket validation/fragmentation, failed provisioning,
failed switching and rollback. No live Apple login or WalnutPi deployment is
part of these automated tests. No C++ rebuild is needed for the runtime trial.
