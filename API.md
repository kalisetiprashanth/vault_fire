# API reference

All routes are JSON under `/api`, except uploads (multipart) and downloads (binary).
Every state-changing request needs the header `X-CSRF-Token` (returned by `/login` and `/me`) and the session cookie.
"Document check" = `authz.authorize()` is called before anything else; failure is audited. No-access users get **404**, users with some-but-not-enough access get **403**.

| Method & path | Who may call | Notes |
|---|---|---|
| `POST /login` | anyone | rate-limited (429), audited incl. failures |
| `POST /logout` | any signed-in user | revokes session |
| `GET /me` | anyone | returns user + CSRF token, or `user:null` |
| `GET /documents` | owner, viewer (admin gets `[]`) | only owned or granted docs. Query: `q, owner, category, from, to, scope=mine\|shared\|trash` |
| `POST /documents` | **role owner** | multipart `file, name, category, description`; validated |
| `GET /documents/{id}` | doc **read** | metadata + versions |
| `PATCH /documents/{id}` | doc **edit** | name/category/description only |
| `POST /documents/{id}/versions` | doc **edit** | multipart `file` |
| `GET /documents/{id}/download?version=N` | doc **read** | attachment, audited, integrity-checked |
| `DELETE /documents/{id}` | doc **owner** | soft delete |
| `POST /documents/{id}/restore` | doc **owner** | works on deleted docs |
| `GET /documents/{id}/grants` | doc **owner** | |
| `PUT /documents/{id}/grants` | doc **owner** | `{username, level: read\|edit, expires_at?, suggestion_id?}` |
| `DELETE /documents/{id}/grants/{user_id}` | doc **owner** | effective at once |
| `GET /documents/{id}/suggestions` | doc **owner** | heuristic advice; grants nothing; audited |
| `GET /documents/{id}/audit` | doc **owner** | activity incl. refused attempts |
| `GET /users/lookup?q=` | role owner | active non-admin users |
| `GET /admin/users` | admin | |
| `POST /admin/users` | admin | `{username, display_name, password(10+), role}` |
| `POST /admin/users/{id}/disable \| enable` | admin | disable revokes sessions; cannot disable self |
| `POST /admin/users/{id}/role` | admin | revokes target's sessions; cannot change own role |
| `POST /admin/users/{id}/password` | admin | revokes target's sessions; raises alert |
| `GET /admin/documents` | admin | **metadata only** |
| `GET /admin/audit` | admin | filters `action, prefix, outcome, actor, doc_id, limit` (`prefix=permission.` = permission changes) |
| `GET /admin/audit/verify` | admin | recomputes HMAC chain; optional `anchor_seq`, `anchor_hash` |
| `GET /admin/alerts` | admin | repeated refusals, login failures, download bursts, edit-grant bursts, role changes, password resets |

Audited actions: `auth.login auth.logout document.upload document.view document.edit document.version.add document.download document.delete document.restore permission.grant permission.revoke permission.list suggestion.create audit.view user.create user.disable user.enable user.role user.password_reset route.denied`; refusals have `outcome=denied`.
