"""Security tests. Each test names the THREATS.md entry (T-n) it proves.
Seed data: doc1 alice->carol(read) | doc2 alice (nobody) | doc3 alice->dave(read) | doc4 bob->dave(edit)"""
import io
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import create_app
from scripts.seed import DEFAULTS, _pdf, seed_if_empty

PW = {u: v[2] for u, v in DEFAULTS.items()}


class Client:
    def __init__(self, app, user=None):
        self.c = app.test_client()
        self.csrf = None
        if user:
            r = self.c.post("/api/login", json={"username": user, "password": PW[user]})
            assert r.status_code == 200, r.json
            self.csrf = r.json["csrf"]

    def req(self, method, path, token=True, **kw):
        h = kw.pop("headers", {})
        if token and self.csrf:
            h["X-CSRF-Token"] = self.csrf
        return self.c.open(path, method=method, headers=h, **kw)

    def get(self, p, **kw): return self.req("GET", p, **kw)
    def post(self, p, **kw): return self.req("POST", p, **kw)
    def put(self, p, **kw): return self.req("PUT", p, **kw)
    def patch(self, p, **kw): return self.req("PATCH", p, **kw)
    def delete(self, p, **kw): return self.req("DELETE", p, **kw)

    def upload(self, fname, data, path="/api/documents", **form):
        return self.post(path, data={"file": (io.BytesIO(data), fname), **form}, content_type="multipart/form-data")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = create_app({"DATA_DIR": self.tmp, "TESTING": True, "PW_HASH_METHOD": "pbkdf2:sha256:1000"})
        with self.app.app_context():
            seed_if_empty(self.app)
        self.alice, self.bob, self.carol, self.dave, self.admin = (Client(self.app, u) for u in ("alice", "bob", "carol", "dave", "admin"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def raw(self):
        c = sqlite3.connect(self.app.config["DB_PATH"]); c.row_factory = sqlite3.Row
        return c

    def audit(self, **where):
        q = " AND ".join(f"{k}=?" for k in where) or "1"
        c = self.raw(); rows = c.execute(f"SELECT * FROM audit WHERE {q} ORDER BY seq", tuple(where.values())).fetchall(); c.close()
        return rows

    def verify(self):
        return self.admin.get("/api/admin/audit/verify").json


class TestIsolation(Base):
    def test_T1_anonymous_reaches_nothing(self):
        anon = Client(self.app)
        for m, p in (("GET", "/api/documents"), ("GET", "/api/documents/1"), ("GET", "/api/documents/1/download"),
                     ("PATCH", "/api/documents/1"), ("DELETE", "/api/documents/1"), ("GET", "/api/documents/1/grants"),
                     ("GET", "/api/admin/audit"), ("GET", "/api/documents/1/audit")):
            self.assertEqual(anon.req(m, p, json={}).status_code, 401, (m, p))

    def test_T2_ungranted_user_cannot_read_download_change_delete_or_share(self):
        # carol has NO grant on doc2 (alice's contract)
        for m, p, kw in (("GET", "/api/documents/2", {}), ("GET", "/api/documents/2/download", {}),
                         ("PATCH", "/api/documents/2", {"json": {"name": "x"}}), ("DELETE", "/api/documents/2", {}),
                         ("POST", "/api/documents/2/restore", {}), ("GET", "/api/documents/2/grants", {}),
                         ("PUT", "/api/documents/2/grants", {"json": {"username": "carol", "level": "edit"}}),
                         ("DELETE", "/api/documents/2/grants/3", {}), ("GET", "/api/documents/2/audit", {}),
                         ("GET", "/api/documents/2/suggestions", {}),
                         ("POST", "/api/documents/2/versions", {"data": {"file": (io.BytesIO(_pdf("x")), "x.pdf")}, "content_type": "multipart/form-data"})):
            r = self.carol.req(m, p, **kw)
            self.assertEqual(r.status_code, 404, (m, p, r.status_code))
        self.assertEqual(self.alice.get("/api/documents/2").json["name"], "Acme master contract")   # untouched
        self.assertEqual(self.alice.get("/api/documents/2").json["current_version"], 1)

    def test_T2b_carol_cannot_grant_herself_access_even_via_owner_endpoints(self):
        r = self.carol.put("/api/documents/1/grants", json={"username": "carol", "level": "edit"})
        self.assertIn(r.status_code, (403, 404))
        self.assertEqual(self.carol.patch("/api/documents/1", json={"name": "pwn"}).status_code, 403)

    def test_T3_id_enumeration_only_yields_granted_documents(self):
        ok = [i for i in range(1, 60) if self.dave.get(f"/api/documents/{i}").status_code == 200]
        self.assertEqual(ok, [3, 4])
        ok = [i for i in range(1, 60) if self.dave.get(f"/api/documents/{i}/download").status_code == 200]
        self.assertEqual(ok, [3, 4])

    def test_T3b_version_number_cannot_reach_another_documents_file(self):
        self.assertEqual(self.carol.get("/api/documents/1/download?version=2").status_code, 404)
        self.assertEqual(self.carol.get("/api/documents/1/download?version=abc").status_code, 400)

    def test_T4_read_grant_cannot_edit_delete_replace_or_share(self):
        self.assertEqual(self.carol.get("/api/documents/1/download").status_code, 200)
        self.assertEqual(self.carol.patch("/api/documents/1", json={"name": "x"}).status_code, 403)
        self.assertEqual(self.carol.delete("/api/documents/1").status_code, 403)
        self.assertEqual(self.carol.upload("a.pdf", _pdf("a"), "/api/documents/1/versions").status_code, 403)
        self.assertEqual(self.carol.get("/api/documents/1/grants").status_code, 403)
        self.assertEqual(self.alice.get("/api/documents/1").json["name"], "Salary letter - Carol")

    def test_T5_edit_grant_can_edit_but_not_delete_or_manage_access(self):
        self.assertEqual(self.dave.patch("/api/documents/4", json={"name": "Drawings rev B"}).status_code, 200)
        self.assertEqual(self.dave.upload("d.txt", b"v2\n", "/api/documents/4/versions").status_code, 201)
        self.assertEqual(self.dave.delete("/api/documents/4").status_code, 403)
        self.assertEqual(self.dave.put("/api/documents/4/grants", json={"username": "carol", "level": "read"}).status_code, 403)
        self.assertEqual(self.carol.get("/api/documents/4").status_code, 404)

    def test_T6_cross_owner(self):
        self.assertEqual(self.bob.get("/api/documents/1").status_code, 404)       # another OWNER is not special
        self.assertEqual(self.bob.delete("/api/documents/1").status_code, 404)
        self.assertEqual(self.alice.get("/api/documents/4").status_code, 404)

    def test_T7_search_never_leaks(self):
        r = self.carol.get("/api/documents?q=contract").json["documents"]
        self.assertEqual(r, [])
        names = {d["name"] for d in self.carol.get("/api/documents?owner=alice").json["documents"]}
        self.assertEqual(names, {"Salary letter - Carol"})
        for q in ("%", "_", "' OR 1=1 --", "\\"):
            r = self.carol.get("/api/documents", query_string={"q": q, "owner": q, "category": q})
            self.assertEqual(r.status_code, 200)
            self.assertTrue(all(d["id"] == 1 for d in r.json["documents"]))
        self.assertEqual({d["id"] for d in self.carol.get("/api/documents").json["documents"]}, {1})

    def test_T8_mass_assignment_ignored(self):
        self.assertEqual(self.dave.patch("/api/documents/4", json={"name": "n", "owner_id": 5, "deleted_at": "x", "id": 99}).status_code, 200)
        d = self.bob.get("/api/documents/4").json
        self.assertEqual(d["owner"]["username"], "bob")
        self.assertIsNone(d["deleted_at"])


class TestRevocation(Base):
    def test_T9_revoke_is_immediate_for_an_already_logged_in_session(self):
        self.assertEqual(self.carol.get("/api/documents/1/download").status_code, 200)
        self.assertEqual(self.alice.delete("/api/documents/1/grants/4").status_code, 200)  # carol is id 4
        self.assertEqual(self.carol.get("/api/documents/1/download").status_code, 404)
        self.assertEqual(self.carol.get("/api/documents/1").status_code, 404)
        self.assertEqual(self.carol.get("/api/documents").json["documents"], [])

    def test_T10_expired_grant_stops_working(self):
        c = self.raw(); c.execute("UPDATE grants SET expires_at='2000-01-01T00:00:00Z' WHERE doc_id=1"); c.commit(); c.close()
        self.assertEqual(self.carol.get("/api/documents/1/download").status_code, 404)

    def test_T10b_cannot_create_grant_already_expired(self):
        r = self.alice.put("/api/documents/2/grants", json={"username": "carol", "level": "read", "expires_at": "2000-01-01T00:00:00Z"})
        self.assertEqual(r.status_code, 400)

    def test_T11_disabling_user_kills_existing_session_at_once(self):
        self.assertEqual(self.carol.get("/api/documents").status_code, 200)
        self.assertEqual(self.admin.post("/api/admin/users/4/disable").status_code, 200)
        self.assertEqual(self.carol.get("/api/documents").status_code, 401)
        self.assertEqual(Client(self.app).c.post("/api/login", json={"username": "carol", "password": PW["carol"]}).status_code, 401)

    def test_T12_logout_invalidates_the_cookie_server_side(self):
        cookie = self.carol.c.get_cookie("tv_session").value
        self.carol.post("/api/logout")
        other = self.app.test_client(); other.set_cookie("tv_session", cookie)
        self.assertEqual(other.get("/api/documents").status_code, 401)

    def test_T13_deleted_document_vanishes_for_grantees_and_can_be_restored_by_owner_only(self):
        self.assertEqual(self.alice.delete("/api/documents/1").status_code, 200)
        self.assertEqual(self.carol.get("/api/documents/1/download").status_code, 404)
        self.assertEqual(self.carol.post("/api/documents/1/restore").status_code, 404)
        self.assertEqual(self.alice.get("/api/documents?scope=trash").json["documents"][0]["id"], 1)
        self.assertEqual(self.alice.post("/api/documents/1/restore").status_code, 200)
        self.assertEqual(self.carol.get("/api/documents/1/download").status_code, 200)

    def test_T13b_even_the_owner_cannot_read_a_deleted_document_until_restored(self):
        self.alice.delete("/api/documents/2")
        self.assertEqual(self.alice.get("/api/documents/2").status_code, 404)
        self.assertEqual(self.alice.get("/api/documents/2/download").status_code, 404)
        self.assertEqual(self.alice.patch("/api/documents/2", json={"name": "x"}).status_code, 404)

    def test_T11b_active_flag_is_checked_on_every_request_not_only_at_disable_time(self):
        c = self.raw(); c.execute("UPDATE users SET active=0 WHERE username='carol'"); c.commit(); c.close()   # no session revoke
        self.assertEqual(self.carol.get("/api/documents").status_code, 401)

    def test_T3c_version_number_of_ANOTHER_document_cannot_be_used(self):
        self.assertEqual(self.dave.upload("d.txt", b"v2 of drawings\n", "/api/documents/4/versions").status_code, 201)
        self.assertEqual(self.dave.get("/api/documents/4/download?version=2").status_code, 200)
        self.assertEqual(self.carol.get("/api/documents/1/download?version=2").status_code, 404)   # doc4's v2 must not leak via doc1
        self.assertEqual(self.dave.get("/api/documents/3/download?version=2").status_code, 404)

    def test_T14_password_reset_and_role_change_revoke_sessions(self):
        self.admin.post("/api/admin/users/5/password", json={"password": "A-brand-new-pass-1"})
        self.assertEqual(self.dave.get("/api/documents").status_code, 401)
        self.admin.post("/api/admin/users/4/role", json={"role": "owner"})
        self.assertEqual(self.carol.get("/api/documents").status_code, 401)


class TestRolesAndRequests(Base):
    def test_T15_admin_cannot_read_content_but_sees_metadata(self):
        for i in (1, 2, 4):
            self.assertEqual(self.admin.get(f"/api/documents/{i}").status_code, 404)
            self.assertEqual(self.admin.get(f"/api/documents/{i}/download").status_code, 404)
            self.assertEqual(self.admin.delete(f"/api/documents/{i}").status_code, 404)
        self.assertEqual(len(self.admin.get("/api/admin/documents").json["documents"]), 4)
        self.assertEqual(self.admin.get("/api/documents").json["documents"], [])

    def test_T15b_admin_demoted_from_owner_does_not_keep_access_to_own_files(self):
        self.admin.post("/api/admin/users/2/role", json={"role": "admin"})          # alice -> admin
        alice = Client(self.app, "alice")
        self.assertEqual(alice.get("/api/documents/2/download").status_code, 404)

    def test_T16_non_admins_cannot_use_admin_api(self):
        for c in (self.alice, self.carol):
            for m, p in (("GET", "/api/admin/users"), ("GET", "/api/admin/audit"), ("GET", "/api/admin/audit/verify"),
                         ("GET", "/api/admin/alerts"), ("GET", "/api/admin/documents"), ("POST", "/api/admin/users/4/disable")):
                self.assertEqual(c.req(m, p).status_code, 403, (m, p))
        self.assertEqual(self.carol.get("/api/documents").status_code, 200)         # carol still active

    def test_T17_viewers_and_admins_cannot_upload_or_look_up_users(self):
        self.assertEqual(self.carol.upload("a.pdf", _pdf("a")).status_code, 403)
        self.assertEqual(self.admin.upload("a.pdf", _pdf("a")).status_code, 403)
        self.assertEqual(self.carol.get("/api/users/lookup?q=a").status_code, 403)

    def test_T18_csrf_token_and_origin_are_enforced(self):
        r = self.alice.req("PATCH", "/api/documents/2", token=False, json={"name": "csrf"})
        self.assertEqual(r.status_code, 403)
        r = self.alice.req("PATCH", "/api/documents/2", headers={"Origin": "https://evil.example"}, json={"name": "csrf"})
        self.assertEqual(r.status_code, 403)
        r = self.alice.req("PATCH", "/api/documents/2", headers={"X-CSRF-Token": "wrong"}, token=False, json={"name": "csrf"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.alice.get("/api/documents/2").json["name"], "Acme master contract")

    def test_T19_login_rate_limit_and_no_user_enumeration(self):
        c = Client(self.app).c
        a = c.post("/api/login", json={"username": "carol", "password": "nope"}).json
        b = c.post("/api/login", json={"username": "nobody", "password": "nope"}).json
        self.assertEqual(a, b)
        for _ in range(4):
            c.post("/api/login", json={"username": "carol", "password": "nope"})
        self.assertEqual(c.post("/api/login", json={"username": "carol", "password": PW["carol"]}).status_code, 429)

    def test_T20_session_cookie_flags(self):
        r = self.app.test_client().post("/api/login", json={"username": "carol", "password": PW["carol"]})
        sc = r.headers["Set-Cookie"].lower()
        self.assertIn("httponly", sc); self.assertIn("samesite=lax", sc)


class TestSharingRules(Base):
    def test_T21_grant_target_validation(self):
        for body in ({"username": "admin", "level": "read"}, {"username": "ghost", "level": "read"},
                     {"username": "alice", "level": "read"}, {"username": "carol", "level": "owner"}):
            self.assertEqual(self.alice.put("/api/documents/2/grants", json=body).status_code, 400, body)

    def test_T22_suggestions_never_grant_and_grants_record_human_confirmation(self):
        # make a pattern: alice's HR docs go to carol AND dave; a new HR doc should suggest both
        self.alice.upload("hr.txt", b"hello\n", category="HR", name="HR note")
        new_id = self.alice.get("/api/documents?q=HR note").json["documents"][0]["id"]
        sug = self.alice.get(f"/api/documents/{new_id}/suggestions").json["suggestions"]
        self.assertTrue({s["username"] for s in sug} >= {"carol", "dave"})
        self.assertEqual(self.carol.get(f"/api/documents/{new_id}").status_code, 404)  # suggestion alone granted nothing
        self.assertEqual(self.alice.get(f"/api/documents/{new_id}/grants").json["grants"], [])
        s = next(x for x in sug if x["username"] == "carol")
        # a suggestion for carol cannot be replayed to grant dave
        self.assertEqual(self.alice.put(f"/api/documents/{new_id}/grants", json={"username": "dave", "level": "read", "suggestion_id": s["suggestion_id"]}).status_code, 400)
        self.assertEqual(self.alice.put(f"/api/documents/{new_id}/grants", json={"username": "carol", "level": "read", "suggestion_id": s["suggestion_id"]}).status_code, 200)
        rows = self.audit(action="permission.grant", doc_id=new_id)
        self.assertIn('"human_confirmed":true', rows[-1]["detail"]); self.assertIn(f'"suggestion_id":{s["suggestion_id"]}', rows[-1]["detail"])
        self.assertTrue(self.audit(action="suggestion.create", doc_id=new_id))
        self.assertEqual(self.carol.get(f"/api/documents/{new_id}").status_code, 200)

    def test_T23_suggestion_for_someone_elses_document_is_refused(self):
        self.assertEqual(self.bob.get("/api/documents/1/suggestions").status_code, 404)


class TestUploads(Base):
    def test_T24_validation(self):
        bad = [("evil.exe", b"MZ\x90\x00"), ("x.html", b"<script>alert(1)</script>"), ("x.svg", b"<svg/>"), ("noext", b"abc"),
               ("fake.pdf", b"<html>not a pdf"), ("fake.png", b"%PDF-1.4"), ("fake.docx", b"just text"), ("x.pdf", b""),
               ("bin.txt", b"abc\x00def"), ("m.docx", b"PK\x03\x04")]
        for name, data in bad:
            self.assertEqual(self.alice.upload(name, data).status_code, 400, name)
        self.assertEqual(self.alice.upload("big.txt", b"a" * (10 * 1024 * 1024 + 1)).status_code, 400)
        self.assertEqual(self.alice.upload("ok.pdf", _pdf("ok")).status_code, 201)
        self.assertTrue(self.audit(action="document.upload", outcome="denied"))      # refusals are audited

    def test_T25_filename_is_sanitised_and_download_cannot_run_as_html(self):
        r = self.alice.upload("../../etc/<script>x.txt", b"hi\n", name="t")
        self.assertEqual(r.status_code, 201)
        d = self.alice.get(f"/api/documents/{r.json['id']}").json
        fn = d["versions"][0]["original_filename"]
        self.assertNotIn("/", fn); self.assertNotIn("<", fn); self.assertNotIn("..", fn.replace("...", ""))
        dl = self.alice.get(f"/api/documents/{r.json['id']}/download")
        self.assertTrue(dl.headers["Content-Disposition"].startswith("attachment"))
        self.assertEqual(dl.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("default-src 'self'", dl.headers["Content-Security-Policy"])
        files = [p for p in Path(self.app.config["FILES_DIR"]).rglob("*") if p.is_file()]
        self.assertTrue(all(len(p.name) == 32 for p in files))                      # storage names are random, not user input

    def test_T26_tampered_file_on_disk_is_refused_and_logged(self):
        c = self.raw(); key = c.execute("SELECT storage_key FROM versions WHERE doc_id=1").fetchone()[0]; c.close()
        (Path(self.app.config["FILES_DIR"]) / key[:2] / key).write_bytes(b"%PDF-1.4 swapped")
        self.assertEqual(self.carol.get("/api/documents/1/download").status_code, 500)
        self.assertTrue(self.audit(action="document.download", outcome="failed"))

    def test_T27_files_are_not_served_statically(self):
        for p in ("/static/../instance/trustvault.db", "/files/1", "/instance/audit.key", "/static/trustvault.db"):
            self.assertEqual(self.carol.get(p).status_code, 404, p)


class TestAudit(Base):
    def test_T28_everything_required_is_recorded_including_refusals(self):
        self.carol.get("/api/documents/1/download")                                 # ok
        self.carol.get("/api/documents/2/download")                                 # refused
        self.carol.patch("/api/documents/1", json={"name": "x"})                    # refused (read only)
        self.dave.patch("/api/documents/4", json={"category": "Eng2"})              # ok edit
        self.alice.delete("/api/documents/1/grants/4")                              # revoke
        self.alice.delete("/api/documents/3")                                       # delete
        got = {(r["action"], r["outcome"]) for r in self.audit()}
        for want in (("document.upload", "ok"), ("document.download", "ok"), ("document.download", "denied"),
                     ("document.edit", "denied"), ("document.edit", "ok"), ("permission.grant", "ok"),
                     ("permission.revoke", "ok"), ("document.delete", "ok"), ("auth.login", "ok")):
            self.assertIn(want, got)
        denied = self.audit(action="document.download", outcome="denied")[0]
        self.assertEqual((denied["actor_name"], denied["doc_id"]), ("carol", 2))
        self.assertEqual(self.verify()["ok"], True)

    def test_T29_failed_logins_are_recorded(self):
        Client(self.app).c.post("/api/login", json={"username": "carol", "password": "wrong"})
        self.assertTrue(self.audit(action="auth.login", outcome="failed"))

    def test_T30_audit_rows_cannot_be_updated_or_deleted_through_sql(self):
        c = self.raw()
        for sql in ("UPDATE audit SET actor_name='x' WHERE seq=1", "DELETE FROM audit WHERE seq=1", "DELETE FROM audit"):
            with self.assertRaises(sqlite3.DatabaseError):
                c.execute(sql); c.commit()
        c.close()

    def test_T31_tampering_is_detected_even_if_the_triggers_are_dropped(self):
        self.carol.get("/api/documents/2/download")
        c = self.raw()
        c.execute("DROP TRIGGER audit_no_update"); c.execute("DROP TRIGGER audit_no_delete"); c.commit()
        self.assertTrue(self.verify()["ok"])
        c.execute("UPDATE audit SET actor_name='nobody' WHERE action='document.download' AND outcome='denied'"); c.commit()
        v = self.verify(); self.assertFalse(v["ok"]); self.assertIsNotNone(v["first_bad_seq"])

    def test_T32_deleting_a_record_is_detected(self):
        self.carol.get("/api/documents/2/download")
        c = self.raw(); c.execute("DROP TRIGGER audit_no_delete"); c.commit()
        c.execute("DELETE FROM audit WHERE seq=(SELECT MIN(seq) FROM audit WHERE action='auth.login')"); c.commit(); c.close()
        self.assertFalse(self.verify()["ok"])

    def test_T32b_tail_truncation_is_caught_by_sequence_gap_or_external_anchor(self):
        head = self.verify()["head"]                                                # admin records this offsite
        self.carol.get("/api/documents/2/download")
        c = self.raw(); c.execute("DROP TRIGGER audit_no_delete"); c.commit()
        c.execute("DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)"); c.commit()
        head2 = self.admin.get("/api/admin/audit/verify").json["head"]
        self.assertIsNotNone(head2)
        v = self.admin.get(f"/api/admin/audit/verify?anchor_seq={head['seq']+1}&anchor_hash=" + "0" * 64).json
        self.assertFalse(v["ok"])                                                   # anchored later head no longer present
        c.close()

    def test_T32c_truncation_followed_by_any_new_event_leaves_a_sequence_gap(self):
        self.carol.get("/api/documents/2/download")
        c = self.raw(); c.execute("DROP TRIGGER audit_no_delete"); c.commit()
        c.execute("DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)"); c.commit(); c.close()
        self.carol.get("/api/documents/2/download")
        self.assertFalse(self.verify()["ok"])

    def test_T33_a_forger_without_the_key_cannot_recompute_a_valid_chain(self):
        import hashlib, json
        c = self.raw(); c.execute("DROP TRIGGER audit_no_update"); c.commit()
        c.execute("UPDATE audit SET actor_name='mallory' WHERE seq=1")
        r = c.execute("SELECT * FROM audit WHERE seq=1").fetchone()
        forged = hashlib.sha256(json.dumps([r["prev_hash"], r["ts"], r["actor_id"], "mallory", r["action"], r["outcome"], r["doc_id"], r["target_user_id"], r["ip"], r["detail"]], separators=(",", ":")).encode()).hexdigest()
        c.execute("UPDATE audit SET hash=? WHERE seq=1", (forged,)); c.commit(); c.close()
        self.assertFalse(self.verify()["ok"])

    def test_T34_alerts_surface_probing(self):
        for i in range(3):
            self.carol.get(f"/api/documents/{2}/download")
        kinds = [a["kind"] for a in self.admin.get("/api/admin/alerts").json["alerts"]]
        self.assertIn("repeated_denials", kinds)

    def test_T34b_admin_password_reset_of_another_user_raises_an_alert(self):
        self.admin.post("/api/admin/users/2/password", json={"password": "Another-long-pass-9"})
        self.assertIn("password_reset", [a["kind"] for a in self.admin.get("/api/admin/alerts").json["alerts"]])
        self.assertTrue(self.audit(action="user.password_reset"))

    def test_T35_owner_sees_refused_attempts_on_their_document(self):
        self.carol.get("/api/documents/2/download")
        ev = self.alice.get("/api/documents/2/audit").json["events"]
        self.assertTrue(any(e["outcome"] == "denied" and e["actor_name"] == "carol" for e in ev))


if __name__ == "__main__":
    unittest.main()
