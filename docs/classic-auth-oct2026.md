# October 2026 authentication preparation (not deployed)

This branch starts at `main` commit `2577d269165e27cc548c7d435f96b3e2a47188e7`.
It does not include PR #4 (`9ab184b524c273770cd86b113cdbcc1fe2f7a531`).
No Pi connection, service change, account login, app refresh, ADI migration,
provisioning, merge or deployment is part of this work.

## Official source audit — 2026-10-30 KST

The [official AltStore announcement](https://fosstodon.org/@altstore) announces
Classic 2.3.2, AltServer Windows 1.8.1 and macOS 1.8.3, with fixes for HTTP 503
and -80046. Release availability is distinct from source availability.
At inspection, the public `altstoreio/AltStore` `classic` ref still resolves to
`bbc10d6964185b75a46c6ddd7476ac08df095308` (Classic 2.3.1 / macOS 1.8.2), with
AltSign pinned to `e639bdfbea185d5c229b11f62e25c5d78649d5c4` on `notarized`.
The public `rileytestut/AltServer-Windows` default ref is still
`41fb42bc78056f59e64566f7561ba405ef59b5d9` (2021). No public release tag or
source ref tying the new Windows/macOS/Classic binaries to exact new code was
available. **This PR does not claim to reproduce the unpublished 2.3.2/1.8.3
or Windows 1.8.1 binary implementation. Recheck upstream before merging.**

GitHub's PR badge is insufficient: several changes were manually incorporated
by the maintainer while their original PRs remain open or closed-unmerged.

| Requested source | Verified status | Treatment here |
| --- | --- | --- |
| [AltStore #1834](https://github.com/altstoreio/AltStore/pull/1834) | Closed, not a GitHub merge; incorporated as `bf940f0d9e647e6598c064dc35b1ed696169b89b` and `57da1c3`; maintainer confirms in discussion | Follow official provider/provisioning identity checks; do not copy macOS Keychain, local ADI or UI code |
| [AltStore #1835](https://github.com/altstoreio/AltStore/pull/1835) | Open; official Classic fix is `b726cfecaf1d1b44756225a0a090296c8426dccd` | Prefer official implementation; no cherry-pick of proposal |
| [AltSign #59](https://github.com/rileytestut/AltSign/pull/59) | Open badge; incorporated as `1599a32e9598d1377b0579af546073820dd344c6` | 409/no-au, skip re-sending code, refresh after code entry and before post-2FA login/apptokens |
| [AltSign #61](https://github.com/rileytestut/AltSign/pull/61) | Open badge; incorporated as `06c4bdd5ff5fe56dd58ac8f97589faf477cc0327`, `ac6ed1943dbb2e22cef285a9ab65bfcc24d4ea2b`, `5ba595a88e3fc0cc63e90f9784ee9f58a4d26ee1` | Matched UA/client-info, minimal string CPD, HTTP status before plist, no redirects, one init resync with same A2k |
| [AltStore #1851](https://github.com/altstoreio/AltStore/pull/1851) | Open, not present in inspected public Classic ref | Supports the provider-UA requirement already in official AltSign; no claim it shipped in 2.3.2 |
| [AltStore #1853](https://github.com/altstoreio/AltStore/pull/1853) | Open, unmerged proposal | Do not hardcode its Mac15,7/macOS 27 identity or auto-reprovision; optional recorded identity mode only |

The official source bodies inspected are `AltSign/Sources/ALTAppleAPI+Authentication.swift`
and `AltServer/Anisette Data/RemoteAnisetteDataFetcher.swift` at the pinned refs.
No macOS Swift/Objective-C runtime implementation is imported into Linux.

## Linux behavior

The default remains `legacy`. `ALTSERVER_AUTH_MODE=official-2026` enables the new
flow for AltServer's own account authentication. It does not change the wire
format of Anisette returned to a phone; Classic chooses its own authentication
headers and must be tested separately after its update.

* Carry User-Agent with each Anisette object, rather than inferring it from a
  hardcoded Mac/Xcode UA. Require both headers to equal the provisioning record.
  In modern mode an existing `ALTSERVER_GSA_USER_AGENT` override must also match.
* Before complete, apptokens, requesting a 2FA code, validating a typed code and
  restarting after 2FA, fetch fresh data. Reject every OTP previously consumed
  in the transaction, including nonconsecutive reuse. Unlike official AltSign,
  which shares its initial CPD across init/complete, this mode also refreshes
  before complete. This stricter Linux choice needs a later live compatibility
  check. Refresh failures stop instead of falling back to stale data.
* Refreshed/resynchronized machine, device, local-user and client identities
  must remain unchanged. Minimal CPD contains the official nine string fields.
* `hsc=409` without `au` prompts for the already-sent trusted-device code.
  `trustedDeviceSecondaryAuth` requests a trusted-device code; `secondaryAuth`
  uses SMS. Validate after refreshing. SMS success requires `X-Apple-PE-Token`.
  There is at most one 2FA challenge/restart per transaction.
* `hsc=434` is accepted only on init, even if `ec` is also nonzero. Pass string
  or base64-encoded binary `X-Apple-I-MD-DATA` to the isolated provider, retry once
  with the same SRP context/public key, and use the resynced CPD thereafter.
  Missing resync data, unsupported backends, later-stage/repeated 434 all stop.
* HTTP errors (including HTML 503), redirects, malformed responses, -80045,
  -80046 and -23782 produce fixed diagnostics without opaque Apple text.
  None triggers repeated login, provider switching, identity rewriting or ADI reset.
  503 is not treated as proof of rate limiting or of an identity mismatch.
* The modern cookie jar belongs to one transaction and survives its 2FA restart.
* Certificate verification is enabled for **both modes**, including the old
  authentication/SMS clients that previously explicitly disabled it. The dormant,
  uncompiled duplicate authentication source is also hardened to prevent future reuse. Redirects
  are disabled for authentication; timeouts are bounded. TLS hardening is an
  intentional security change to the legacy transport. There is no insecure
  fallback, system trust modification, or bundled CA imported from PR #4.

Anisette stream diagnostics now redact OTPs and personal device identifiers.
Existing AltKeeper scripts and normal renewal path, provider settings and ADI
files are untouched. The adapter below does not use Keeper RPC or create state.

## Optional isolated adapter

`scripts/official_auth_anisette_adapter.py` is a separate foreground process;
no unit files, scheduled task or automatic activation are installed.
It only reads an explicit plist containing `keychain_identifier` (16 bytes),
`adi_pb` (decoded bytes), `provider_url`, `provisioned_client_info` and
`provisioned_user_agent`. This is the existing isolated modern-Mac trial's state
format, not an arbitrary macOS Keychain/Rust state export. It neither writes nor
provisions that file. Use an independently provisioned test identity, never a
copy of the active AltKeeper/AltServer identity: provider-side resync can affect
that identity even though the local file is read-only.

Default `--identity-source provider` requires the provider's advertised pair to
match its saved provisioning pair on every fetch. Optional
`--identity-source provisioned` selects the already recorded pair when a
provider's public advertisement is obsolete. It does not invent a pair, edit
headers or re-provision; first provision a separate test identity with those
exact values outside this PR. Do not assume that merely editing a plist creates
a valid provisioning record. No default modern-Mac identity is supplied here.

The loopback JSON contract is GET `/` for fresh headers, POST `/resync` with
`{"sim":"..."}` for resync. Responses contain the existing v1 fields plus
`authenticationUserAgent`, `provisionedClientInfo`, `provisionedUserAgent`.
Upstream resync uses v3 `get_headers` with `sim`, `device_id`, `md_lu`,
`identifier`, `adi_pb`, as in the official fetcher. Provider HTTP/TLS failures
stop; opaque bodies and state values are never logged. The adapter does not
serve Apple credentials, receive 2FA codes or invoke provisioning endpoints.

The following are **future manual test examples, not deployment steps executed
by this PR**. Use a separate Linux test host and isolated identity only:

```sh
python3 scripts/official_auth_anisette_adapter.py \
  --state /path/to/separately-provisioned-test-state.plist \
  --provider https://YOUR_TEST_PROVIDER --port 16971
```

In another test-host terminal, set process-local values before starting the test
binary in the foreground. Do not edit the running Pi's service or Keeper config:

```sh
export ALTSERVER_AUTH_MODE=official-2026
export ALTSERVER_ANISETTE_SERVER=http://127.0.0.1:16971/
# Leave ALTSERVER_GSA_USER_AGENT unset, or set it to the exact recorded pair's UA.
```

## Validation and merge gate

Offline adapter tests mock every upstream exchange; local HTTP exercises the
actual loopback handler. Existing 49 adapter/rollback tests run unchanged.
Compiled ARM64 protocol tests link the production authentication request/parser
and 2FA methods, replacing only HTTP transport and OTP callbacks. They inspect
headers/CPD, one-shot resync, A2k preservation, code dispatch, OTP reuse rejection,
identity changes, cancellation, and HTTP/Apple errors. No test uses an Apple
account. Full SRP crypto against a live Apple response remains unverified.

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile scripts/*.py
# Inside the existing ARM64 builder, from build/:
make -f ../Makefile -j2 all auth-tests
```

The PR runs Python checks and the existing native ARM64 builder in GitHub
Actions. ARM64 artifacts are review/test outputs only; no release or deployment
job is added. Legacy all-architecture publishing CI now triggers on main/tags,
not preparation branches, avoiding redundant release-style branch builds.

Before merge, after Classic 2.3.2 is available on the user's device:

1. Recheck official source refs and new release source mappings. If a published
   official fix supersedes a choice here, update this PR first.
2. Require the offline and ARM64 workflows to pass for the final PR head.
3. On an authorized isolated host, confirm the provider provisioning pair and
   initial/fresh OTP behavior; never log raw data. TLS failures must be fixed by
   an appropriate trust configuration, never by disabling verification.
4. Test one direct AltServer login with trusted-device 2FA. Separately test SMS
   if the account supports it. Confirm no duplicate code request after 409,
   fresh validate/apptokens and one bounded resync when genuinely requested.
5. Test updated Classic's LAN AltServer refresh separately: the phone owns that
   authentication flow, so this Linux change alone cannot guarantee a fix.
6. Compare install/refresh/signing/device-discovery behavior to the old binary.
   Confirm AltKeeper's independent scheduled renewal still uses its original path.
7. Obtain user approval for any future Pi test/deployment or merge. This PR
   intentionally provides no evidence of real-account or on-device success.

## Rollback

This preparation made no Pi/runtime changes, so there is nothing to roll back
on WalnutPi. Close the PR or delete only its branch if abandoning the work;
keep PR #4 independent.

For a later isolated foreground test, stop only the test binary and this new
adapter, close that test shell (or unset `ALTSERVER_AUTH_MODE`,
`ALTSERVER_ANISETTE_SERVER`, `ALTSERVER_GSA_USER_AGENT`), and use the saved previous
binary/config. Preserve the independent test-state file for inspection. Never
reset/delete active ADI, restore a test identity over the production identity,
or restart AltKeeper as part of rollback. If a branch was later merged, use a
reviewed revert commit and rebuild the previous version; do not force-reset main.
