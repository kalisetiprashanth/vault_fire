# Write-up

## What I built
A Flask + SQLite document platform with three roles, per-document read/edit grants (with optional expiry), versioned uploads, soft delete/restore, search by name/owner/category/date, upload validation, an HMAC-chained append-only audit trail (including refused attempts), an admin console (users, document metadata, audit with permission-change filter, integrity verification, alerts), and 45 security tests plus a mutation script that proves the tests notice a removed control.

## Permission model, in my own words
There are two separate layers.
1. **Account role** (`admin`, `owner`, `viewer`): what kind of person you are. Only owners upload. Only admins manage accounts. It never gives access to any particular document.
2. **Per-document access**, decided in one function (`authz.authorize`): you are the document's owner, *or* there is a live row in `grants` (read or edit, optionally expiring) for you on it. Levels are ordered read < edit < owner. Owner alone can delete, restore and change who has access. **Admins deliberately get no document access.** I chose per-document grants over folders/groups because the brief's first failure ("given a folder to see one file, now you see forty") is a folder-inheritance problem; a flat model cannot over-grant by inheritance.

**Taking access away immediately** is achieved by *never issuing anything that outlives the grant*: no signed links, no permission-bearing tokens, no cache. Every request re-reads session, user and grant from the database. Cost: a couple of indexed queries per request, and downloads cannot be offloaded to a CDN.

**Audit protection:** triggers block UPDATE/DELETE; each record is `HMAC(key, previous hash + fields)`, contiguous in sequence; the admin can verify the chain at any time and compare it with a head recorded elsewhere (needed to catch deletion of the very last records). Honest limit: someone with the server *and* the key can rewrite everything. Keep the key in the platform's secret store.

## Deliberately not built
- **Sharing with people outside the company.** It needs expiring identity-verified links, which are exactly the "token that outlives revocation" I avoided. Better absent than weak.
- Groups / folder inheritance, encryption at rest, MFA, antivirus, hard-delete/retention, email notifications, an LLM. The "AI suggestion" is a transparent heuristic (people already given access to your other documents in the same category); it is advice only, requires a human to press Grant, and both the suggestion and the decision are audited.

## How AI was used, and where it was wrong
See PROMPTS.md. In short: this entire codebase was produced by an AI assistant (Claude) from the brief, and the checks that mattered (mutation testing, the tail-truncation hole in the audit chain) came from running adversarial checks against it rather than trusting it.

## Unfinished / known gaps
No live URL or video included. Free-tier hosting loses data on restart. Everything under "Accepted" in THREATS.md. UI is functional, not polished; I did not test it in a real browser here (API behaviour is covered by tests).
