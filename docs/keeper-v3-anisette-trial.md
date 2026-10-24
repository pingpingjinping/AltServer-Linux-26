# Compare the actual Keeper v3 data source without a Pi rebuild

The first trial returned valid local HTTP 200 responses and delivered Anisette
data to AltStore, but the phone still reported "Apple's authentication servers
returned an error (HTTP 503)". Local HTTP success does not establish Apple's
acceptance of the data. Changing the C++ server's own GrandSlam transport also
does not rewrite the phone's Apple authentication requests.

This second experiment keeps the compiled C++ AltServer and changes only its
Anisette data source. It reuses the locally installed Keeper image by immutable
image ID in a **separate container**, with a **new state directory** and
`ALTKEEPER_ANISETTE_URL=https://ani3.stikstore.app`.

The data path is:

1. AltStore asks the existing C++ AltServer for Anisette data.
2. AltServer GETs a Python standard-library adapter on localhost port 16971.
3. The adapter sends only `AnisetteDataRequest` to the separate Keeper backend
   through localhost port 14951. It validates and maps the response to the v1
   JSON fields expected by AltServer.
4. AltStore receives the data and performs its own Apple authentication.

No Keeper insurance container, `/srv/altkeeper`, account file, pairing record,
phone access, renewal configuration or manual-only setup is changed or copied.
The private backend has its own Docker bridge network namespace rather than
host networking; its only published TCP port is bound to 127.0.0.1. The adapter
also binds exclusively to 127.0.0.1. Only the new backend provisions its own
Anisette identity using the configured remote server; no Apple ID login is
requested by this setup script.

The adapter reads `client_info` from the same provider's `/v3/client_info`
endpoint at startup, rather than forwarding the Mac15,7 description hardcoded
in the Keeper fork. The provider's public `user_agent` is reported for diagnosis
but cannot be injected into the phone's authentication transport through the
v1 Anisette RPC response. AltSign's default phone User-Agent and Keeper's own
User-Agent can therefore still differ. Matching the description is not proof
of a successful Apple login.

To update an already-running trial after updating the Python and shell scripts:

```bash
bash ~/altserver-keeper-auth-src/scripts/keeper-v3-anisette-trial.sh refresh-identity
```

This restarts only the adapter and checks a response. A failure attempts to
restore the previous pre-v3 data source. It requires no binary or image rebuild.

The image is not pulled or built. The local Keeper image must already exist.
This isolates data generation for comparison; it is not a confirmed 503 fix
and it is not a test of the C++ signing/installation path.

## Compare with Keeper's 20-second cache bypassed

The Pi trial installed four LiveContainer profiles created on 24 October 2026
at 17:31 KST, expiring on 31 October at 17:31 KST; the app opened successfully.
Other attempts returned HTTP 503. Local probes confirmed that requests three
seconds apart reused the same OTP and timestamp, while a request about 27
seconds later returned different values. This establishes the cache behavior,
not that the cache causes Apple's rejection.

For a controlled comparison, update the Python adapter and this helper, then:

```bash
bash ~/altserver-keeper-auth-src/scripts/keeper-v3-anisette-trial.sh fresh-headers
```

This copies only the **isolated trial's** `state/anisette_state` to a private,
user-readable snapshot. A temporary environment drop-in changes only the
adapter. Each incoming request now POSTs to the same provider's `v3/get_headers`
using the same keychain identifier and adi.pb; UUID and local-user ID are derived
as in Keeper. The client description, serial number, locale and timezone stay
the same as the existing bridge. The original trial state is not modified.
Calls are serialized and there is no automatic fallback to cached RPC data.
The provider itself can still return equal OTPs; equality alone is not a failure.
This mode does not log in to an Apple account or change the phone's User-Agent.

The adapter is restarted and a real header generation request is checked. If
that check fails, the helper attempts to restore the previous mode. No image or
AltServer binary rebuild is needed. A malformed/retired identity fails closed;
this mode intentionally does not re-provision an identity, since doing so would
confound the comparison.

Restore the cached baseline without reverting the whole v3 experiment:

```bash
bash ~/altserver-keeper-auth-src/scripts/keeper-v3-anisette-trial.sh cached-headers
```

Run one phone refresh with ProxyPin disabled and record its result. A single
success does not prove a fix because the cached baseline already succeeded.
If HTTP 503 still occurs, cache bypass is not a complete fix; investigate the
phone's actual GrandSlam request and identity independently. Offline checks:
`python3 -m unittest discover -s tests -p 'test_fresh_anisette_bridge.py'`.

After updating the three scripts, run:

```bash
bash ~/altserver-keeper-auth-src/scripts/keeper-v3-anisette-trial.sh apply
```

The existing AltServer trial must be running. The setup checks ports and the
compiled binary checksum, starts the isolated backend and adapter, and validates
a real data response before changing the existing temporary AltServer drop-in.
Failure attempts rollback. Newly generated state is retained for diagnosis and
retry; the old Anisette trial container and data remain untouched.

Restore just the previous data source:

```bash
bash ~/altserver-keeper-auth-src/scripts/keeper-v3-anisette-trial.sh rollback
```

Restore the original pre-experiment AltServer setup and remove both trials:

```bash
bash ~/altserver-keeper-auth-src/scripts/keeper-auth-trial.sh rollback
```

If generation fails, inspect only these trial components:

```bash
sudo journalctl -u anisette-keeper-v3-bridge.service -n 40 --no-pager
sudo docker logs --tail 40 anisette-keeper-v3-backend
```

The adapter never logs raw response values. Upstream backend logs can contain
identifiers; review those locally before sharing. Reboot removes the temporary
service override and adapter service, and the new container has no restart
policy. The main trial's original caveats still apply.
