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

The image is not pulled or built. The local Keeper image must already exist.
This isolates data generation for comparison; it is not a confirmed 503 fix
and it is not a test of the C++ signing/installation path.

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
