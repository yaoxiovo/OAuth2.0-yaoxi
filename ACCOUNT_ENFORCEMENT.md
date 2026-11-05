# Unified account enforcement

Production deployed on 2026-11-05 from source a39a7bb; Worker version
96064fd0-0f19-492e-92ba-30c1932c9739. The confirmed ladder is
7 fixed days, 30 fixed days, then permanent on the third and subsequent confirmed
porn violation. Review outcomes and provider errors must never create violations.

`account-enforcement.mjs` owns the Durable Object, per-identity ledger, idempotency,
dedicated service HMAC verification and signed identity-token verification.
`worker.js` provides `/api/internal/account-enforcement`, `/api/auth/introspect`,
signing-time account checks and revocation metadata on `/api/status`.

Deployment requires the `ACCOUNT_ENFORCEMENT` SQLite Durable Object binding and
migration in wrangler.jsonc, the private runtime `JWT_SECRET` and the dedicated
`LUMITAPE_ENFORCEMENT_SECRET` (at least 32 random characters). No secret defaults
are accepted by the new service API or introspection endpoint. The legacy Pages
functions are not this deployment target and must not be used as an alternative
production issuer without porting these checks.

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

Validation: `npm run test:enforcement`, `npm run build`, and
`wrangler deploy --dry-run`. Local workerd startup may fail on hosts where its
TCMalloc virtual address allocation is unsupported; a successful bundle dry-run
does not prove a deployed Durable Object runtime has been tested.

Production account management and false-positive correction are enabled in the
existing wallpaper admin. Automatic punishment has a separate activation flag
and remains disabled pending the failure policy and relying-app rollout.
An isolated real Cloudflare DO runtime passed seven checks (ladder, correction,
idempotency); the temporary Worker was then deleted. No production user was
frozen for testing, and no historical moderation log was replayed.
