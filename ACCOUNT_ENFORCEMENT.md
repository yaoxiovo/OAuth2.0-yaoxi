# Unified account enforcement

Production runs on the Tencent Seoul Node.js service with local SQLite.
The confirmed ladder is 7 fixed days, 30 fixed days, then permanent on the third
and subsequent confirmed porn violation. Review outcomes and provider errors must
never create violations.

`account-enforcement.mjs` owns the per-identity ledger, idempotency, dedicated
service HMAC verification and signed identity-token verification. Its storage is
provided by `server/storage.mjs`, with serialized SQLite transactions.
`worker.js` is the shared HTTP handler imported by `server/main.mjs`; its filename
does not imply a Cloudflare deployment. Production needs no KV/DO namespace.

Deployment requires the local SQLite database, imported account configuration,
private `JWT_SECRET` and `LUMITAPE_ENFORCEMENT_SECRET` (at least 32 characters).
See [server/DEPLOYMENT.md](server/DEPLOYMENT.md). Legacy Pages functions are
historical source only and are excluded from the production build.

The complete protocol, activation gates and outstanding product decisions are
recorded in `/root/lumitape/docs/ACCOUNT_ENFORCEMENT.md`. In particular: failure
policy for freeze requests is not decided. The user has confirmed that overturning a false positive removes
that specific strike. The new overturn action references the original event,
removes one strike exactly once and releases only the freeze caused by that event.
Manual unfreeze remains early release without overturning a verdict. Do not activate the new punishment path
until those contracts are settled.

Revocation is authoritative at the identity provider. Every relying application
must introspect credentials on every protected **server-side** request and verify
its own audience. Browser SDK guards or offline JWT signature checks alone cannot
implement immediate global revocation. Expiry and manual release never reset
the credential version; old sessions must not resume. No refresh-token issuance
or refresh endpoint was found in the current provider implementation.

Validation: `npm test` and `npm run build`. HTTP integration tests use real
local SQLite and exercise password login, restart persistence, signed service
mutations, revocation and release without Cloudflare compute or storage.

Production account management and false-positive correction are enabled in the
existing wallpaper admin. Automatic punishment has a separate activation flag
and remains disabled pending the failure policy and relying-app rollout.
An isolated real Cloudflare DO runtime passed seven checks (ladder, correction,
idempotency); the temporary Worker was then deleted. No production user was
frozen for testing, and no historical moderation log was replayed.
