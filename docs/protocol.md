# HTTP contract

All parts speak this contract. Paths are relative to a base (default `/passkey`). Bodies are JSON.
Binary WebAuthn fields are base64url without padding, as in the W3C JSON forms.

## Errors

Every refusal has an HTTP status and this body:

```json
{ "error": { "code": "invalid_passkey", "message": "This passkey is not valid." } }
```

| Code | Status | Meaning |
|---|---|---|
| `invalid_request` | 422 | A field is missing or malformed |
| `ceremony_expired` | 400 | The ceremony is unknown, used, expired, or belongs to another account or purpose |
| `invalid_registration` | 400 | The registration response did not verify |
| `invalid_passkey` | 401 | The sign-in did not verify (one message for every reason) |
| `already_registered` | 409 | This credential is already stored |
| `too_many_passkeys` | 409 | The account has the maximum number of passkeys |
| `not_found` | 404 | The account has no such passkey |
| `invalid_handoff` | 400 | The handoff code or verifier is wrong, used or expired |

`message` is English and written for people, but applications with another interface language
should show their own text per `code`.

## Registration (signed in)

`POST register/options` → `200`

```json
{ "ceremony": "<id>", "publicKey": { "rp": {}, "user": {}, "challenge": "…", "…": "…" } }
```

`POST register/verify` with `{ "ceremony": "<id>", "credential": <RegistrationResponseJSON>, "name": "Laptop" }`
(`name` optional, 1–100 characters) → `201`

```json
{ "passkey": { "id": "<credential id>", "name": "Laptop", "createdAt": "2026-11-20T10:00:00Z",
               "lastUsedAt": null, "synced": true, "transports": ["internal", "hybrid"] } }
```

## Sign-in

`POST login/options` (no body) → `200` `{ "ceremony": "<id>", "publicKey": { … } }`.
For a guest, `allowCredentials` is empty (any discoverable passkey of the site may answer). For
someone already signed in, it lists that account's passkeys and only those are accepted.

`POST login/verify` with `{ "ceremony": "<id>", "credential": <AuthenticationResponseJSON> }` →
`200` with the application's own answer. The Laravel default signs the session in and answers
`{ "ok": true }`; an application may answer with a token or a next step instead.

## Managing passkeys (signed in)

- `GET passkeys` → `{ "passkeys": [ <summary>, … ] }`, oldest first
- `PATCH passkeys/{id}` with `{ "name": "…" }` → `{ "passkey": <summary> }`
- `DELETE passkeys/{id}` → `204`

`{id}` is the credential ID (base64url). Another account's passkey answers `404`.

## Desktop handoff

1. The desktop app listens on `127.0.0.1:<port>` and opens the system browser on a page of the site
   with `?challenge=<S256 challenge>&port=<port>&state=<state>` (each token 43 base64url characters).
2. The page makes sure the person is signed in, shows what is asked, and on approval calls
   `POST handoff/authorize` (signed in) with `{ "challenge": "…", "port": 51234, "state": "…" }` →
   `{ "redirect": "http://127.0.0.1:51234/callback?code=<code>&state=<state>" }`, then navigates there.
   On refusal it navigates to `http://127.0.0.1:<port>/callback?error=denied&state=<state>`.
3. The desktop app checks `state`, then calls `POST handoff/exchange` (no cookie, no CSRF token) with
   `{ "code": "…", "code_verifier": "…" }` → `200` with the application's own answer (its desktop
   session), `Cache-Control: no-store`.

The server builds the loopback address itself; a client cannot supply a redirect address. The code
is single-use (also after a failed exchange) and lives 60 seconds by default.

## Association files

- `GET /.well-known/assetlinks.json` — Android (Digital Asset Links), relations
  `delegate_permission/common.handle_all_urls` and `delegate_permission/common.get_login_creds`
- `GET /.well-known/apple-app-site-association` — iOS, `{ "webcredentials": { "apps": [ … ] } }`

Both must be served over HTTPS from the relying-party domain, as JSON, without a redirect.
