# THREATS.md

Format: **what an attacker tries -> what I did -> test -> status.** `Mitigated` means closed in code and covered by a test. `Accepted` means I knowingly left it and say why. Every `T-n` test id below is a real test in `tests/test_security.py`, and `scripts/mutation_check.py` deletes 21 individual controls one at a time and fails unless the test-suite goes red.

## A. Reaching a document you were not granted

| # | Attack | Defence | Test | Status |
|---|---|---|---|---|
| A1 | Call any document route without logging in | `@auth()` on every route; the only anonymous routes are `/login`, `/me` and the static shell | T1 | Mitigated |
| A2 | Hidden-button bypass: call the API directly (view, download, edit, delete, restore, grants, audit, suggestions, new version) | Every handler calls `authz.authorize()` **before any read or write**. It is the single decision point; there is no second code path | T2, T4, T5 | Mitigated |
| A3 | IDOR / id enumeration (`/documents/1..n`) | Same authorise call. No access and "does not exist" both return **404** with the same body, so ids leak nothing. Refusals are audited | T3 | Mitigated |
| A4 | Use document A's permission to fetch document B's file via `?version=N` | The version lookup is `WHERE doc_id=? AND version_no=?`, scoped to the already-authorised doc | T3b, T3c | Mitigated |
| A5 | Read the stored file directly (static path, guessable name, path traversal) | Files are in a data dir that is not a static folder; storage names are 128-bit random hex that never come from user input; `blob_path` rejects any key that is not 32 hex chars; routes for `/files`, `/instance`, `../` return 404 | T25, T27 | Mitigated |
| A6 | Another **owner** reading my documents ("owner" is a role, not a master key) | Ownership is per document (`documents.owner_id`), checked in `authorize` | T6 | Mitigated |
| A7 | A read-only grantee editing, replacing, deleting or re-sharing | Three levels, ranked: read < edit < owner. Editing needs `edit`; delete / restore / grants / audit view need `owner` | T4, T5 | Mitigated |
| A8 | Grant myself access (calling the grant API on a document I don't own, or granting to myself) | `permission.grant` needs `owner` on that document; owner cannot grant to self; target must be an active non-admin | T2b, T21 | Mitigated |
| A9 | Mass assignment: PATCH with `owner_id`, `deleted_at`, `id` | The handler reads only name/category/description | T8 | Mitigated |
| A10 | Admin or a demoted owner as a back door | **Admins have no document access at all.** They see metadata and the audit log, never content. `get_access` returns none for role `admin`, even for files they once owned | T15, T15b | Mitigated |
| A11 | Search or filter used as an oracle (LIKE wildcards, SQL injection, owner/category filters) | Search is a `JOIN` that already restricts to owned-or-granted rows; all values are bound parameters; `%`, `_`, `\` are escaped | T7 | Mitigated |
| A12 | Soft-deleted documents still readable (by grantees, or by the owner through the normal routes) | Deleted = invisible to everyone except the owner, and only the restore route accepts `allow_deleted` | T13, T13b | Mitigated |
| A13 | Viewer or admin uploads, or enumerates users | Role gate on upload and on `/users/lookup` (owner only) | T17 | Mitigated |
| A14 | Non-admin calls the admin API | `@auth("admin")`; the refusal is audited as `route.denied` | T16 | Mitigated |

## B. Taking access away must work immediately

| # | Attack | Defence | Test | Status |
|---|---|---|---|---|
| B1 | "Revoked, but my link / token / open session still works" | **There is nothing issued to a grantee that outlives the grant.** No signed URLs, no JWT carrying permissions, no cached ACL. Every request resolves session -> user -> `grants` row from the database. Revoke = `DELETE FROM grants`. Cost: one or two indexed queries per request, and no CDN-able download URLs | T9 | Mitigated |
| B2 | Expired access keeps working | Optional `expires_at` is evaluated in the same query; cannot create an already-expired grant | T10, T10b | Mitigated |
| B3 | Disabled / departed user keeps their session | `users.active` is joined into the session lookup on every request, and disabling also revokes sessions (two independent mechanisms, each tested) | T11, T11b | Mitigated |
| B4 | Stolen cookie after logout | Logout revokes the session server-side | T12 | Mitigated |
| B5 | Password reset / role change leaves old sessions alive | Both revoke all of that user's sessions | T14 | Mitigated |
| B6 | Revoke races with an in-flight download | The permission check and the file read are not one atomic step. A request that passed the check milliseconds before the revoke completes its response. After the revoke returns, nothing new works | - | **Accepted** (window is the length of one request; making it zero would need locking every download against every revoke) |

## C. The audit trail

| # | Attack | Defence | Test | Status |
|---|---|---|---|---|
| C1 | Refused attempts leave no trace | Refusals are written by the same function that decides. They record actor, document id (even non-existent ones), needed vs held level, IP | T28, T35 | Mitigated |
| C2 | Quietly edit or delete a record via the app/SQL | `BEFORE UPDATE/DELETE` triggers abort; the app has no code path that edits audit rows | T30 | Mitigated |
| C3 | Someone with DB write access drops the triggers and edits a row | Each record carries `HMAC-SHA256(key, prev_hash ‖ fields)`. `/admin/audit/verify` recomputes the chain and names the first bad record | T31 | Mitigated (detection, not prevention) |
| C4 | ...and recomputes the hashes to cover it | They need the HMAC key. Plain SHA-256 does not validate. In production the key is the `TV_AUDIT_KEY` env var, not on the data disk | T33 | Mitigated *if the key is kept off the DB host* |
| C5 | Delete a record from the middle | Hash link and contiguous sequence break | T32 | Mitigated |
| C6 | Delete the **last** records | A pure hash chain cannot see this by itself. Verify checks sequence contiguity (so any later event exposes the gap) and accepts an externally recorded **anchor** (`?anchor_seq=&anchor_hash=`). The admin should note the head hash somewhere else (email, ticket) | T32b, T32c | Mitigated only if someone records the anchor. See Accepted below |
| C7 | The action happens but the log write fails (or vice versa) | Action and audit row are in one SQL transaction; both commit or neither | - | Mitigated by design |
| C8 | AI suggestion widens access silently | Suggestions are advice rows; they create **no** grant. A grant requires an owner request. Both the `suggestion.create` event and the `permission.grant` (with `human_confirmed` and `suggestion_id`) are audited. A suggestion for user X cannot be replayed to grant user Y | T22, T23 | Mitigated |
| C9 | Log forging via user-controlled text | Detail is stored as canonical JSON; the UI renders with `textContent` | - | Mitigated |
| C10 | Attacker floods the audit table with failed logins | Login attempts are rate-limited (5 per user and 30 per IP per 15 min), but a distributed attacker can still grow the table | - | **Accepted** |

## D. Sessions, requests, input

| # | Attack | Defence | Test | Status |
|---|---|---|---|---|
| D1 | CSRF against a logged-in user | Per-session CSRF token header on every state-changing request, plus `Origin` must equal `Host`, plus `SameSite=Lax` cookie | T18 | Mitigated |
| D2 | Session theft via XSS | `HttpOnly` cookie; strict CSP (`script-src 'self'`, no inline); UI uses `textContent` only; downloads are always `attachment` + `nosniff` | T20, T25 | Mitigated |
| D3 | Stored XSS through document names, filenames, categories | As above | T25 | Mitigated |
| D4 | Brute force / credential stuffing | Per-user and per-IP lockout, scrypt hashes, identical error and equalised hashing work for unknown users | T19 | Mitigated (but see D8) |
| D5 | Upload malware / polyglots / wrong types | Extension allow-list; magic-byte sniff must agree with the extension; Office files must be real OOXML zips and macro containers are rejected; 10 MB cap; refusals audited | T24 | Mitigated for type confusion. No antivirus: **Accepted** |
| D6 | Path traversal and header injection through filenames | Basename-only, control characters removed, original name used only as the download name | T25 | Mitigated |
| D7 | Tampered blob on disk | SHA-256 stored per version and verified on every download; mismatch refuses and audits | T26 | Mitigated |
| D8 | Lock a victim out by deliberately failing logins for their username | Lockout is per-username | - | **Accepted** (lockout of 15 minutes beats guessing; per-IP would be weaker) |
| D9 | `X-Forwarded-For` spoofing defeats IP limits / forges audit IPs | Proxy headers are trusted only when `TV_TRUST_PROXY=1` (exactly one proxy) | - | Accepted: operator must configure correctly |

## E. Things I knowingly did not solve

1. **Admin can reset a user's password and then sign in as them**, which reaches that user's documents. I removed content access from the admin *role*, but account control is still a path to it. Mitigation is visibility, not prevention: the reset is audited, raises a *high* alert, revokes the user's sessions (they notice), and the later login is audited. A real fix is a separate "break-glass" approval by a second admin, or invite-only password setting.
2. **The audit key and DB share a host.** Someone with full control of the server can forge a consistent log. Defence in depth is the external anchor and a key kept in the platform's secret store. A real fix is shipping each record to a separate write-once store.
3. **No encryption at rest.** A stolen disk or backup exposes file contents. Not done because proper key management matters more than a decorative AES call.
4. **Grantees can copy what they read.** A person allowed to read a file can forward it. There is no DRM; the audit trail proves *who downloaded it*, not where it went.
5. **No MFA, no self-service password reset, no password-breach check.**
6. **Sequential integer document ids.** Harmless given A3 but they reveal volume.
7. **Owners can list usernames** to pick grantees (company-directory model).
8. **SQLite, single process.** Chosen so that a transactional audit append and a clean-clone setup are trivial. Does not scale horizontally. On a free host the disk is ephemeral (data loss, not a confidentiality issue).
9. **No purge/retention.** Delete is soft; nothing ever physically removes a file.
10. **A demoted ex-owner** (role `viewer`) still owns, and can still share, documents they already own. Their sessions are revoked at demotion; admins should also disable the account if that is not intended.
11. **External (outside-company) sharing** is not built. See WRITEUP.md.
