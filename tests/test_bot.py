"""Unit tests for bot.py with a fake Telegram API and a fake `vpn` CLI (no network, no root)."""
import ast
import importlib
import os
import re
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.environ.get("ROOT") or os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ADMIN = 4242
GOODPW = "Str0ng-Passw0rd.x1"


class FakeTG:
    def __init__(self):
        self.calls, self.docs, self.next_id = [], [], 100
        self.delete_result = None

    def call(self, method, data=None, timeout=40):
        self.calls.append((method, data))
        if method == "sendMessage":
            self.next_id += 1
            return {"ok": True, "result": {"message_id": self.next_id}}
        if method == "deleteMessage" and self.delete_result is not None:
            return self.delete_result
        return {"ok": True, "result": True}

    def send_document(self, chat_id, path, caption=None):
        self.next_id += 1
        self.docs.append((os.path.basename(path), caption))
        return {"ok": True, "result": {"message_id": self.next_id}}

    def methods(self, name):
        return [d for m, d in self.calls if m == name]


class FakeVpn:
    def __init__(self):
        self.calls = []
        self.kv = {"backup_key": "no", "version": "9.9.9", "server": "203.0.113.7", "cert_days": "100", "cert_state": "ok"}
        self.on_backup = None

    def __call__(self, *args, timeout=180, input_text=None):
        self.calls.append((args, input_text))
        if args[:2] == ("status", "--kv"):
            return 0, "\n".join(f"{k}={v}" for k, v in self.kv.items())
        if args[:2] == ("user", "show"):
            return 0, f"Username: {args[2]}\nPassword: {GOODPW}"
        if args[:1] == ("profile",):
            for n in (f"{args[1]}.sswan", f"{args[1]}.mobileconfig", f"zedsecure-{args[1]}.txt", "ca.crt"):
                open(os.path.join(args[2], n), "w").write("x")
            return 0, ""
        if args[:1] == ("zed",):
            return 0, "zedsecure://abc"
        if args[:1] == ("backup",) and self.on_backup:
            return self.on_backup(args)
        return 0, ""


class BotCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="botT.")
        for d in ("etc", "var", "bak"):
            os.makedirs(os.path.join(self.tmp, d))
        os.environ.update(IKEV2_ETC=f"{self.tmp}/etc", IKEV2_VAR=f"{self.tmp}/var", IKEV2_BACKUPS=f"{self.tmp}/bak",
                          IKEV2_VPN="/nonexistent/vpn")
        sys.path.insert(0, ROOT)
        import bot
        self.bot = importlib.reload(bot)
        self.bot.tg, self.bot.ADMIN = FakeTG(), ADMIN
        self.vpn = FakeVpn()
        self.bot.vpn = self.vpn
        self.tg = self.bot.tg
        self.bot.update_state(lambda st: st.__setitem__("lang", "en"))     # the bot defaults to Persian

    def msg(self, text, mid=7):
        return {"text": text, "message_id": mid, "chat": {"id": ADMIN, "type": "private"}, "from": {"id": ADMIN}}


class Authorisation(BotCase):
    def test_only_the_admin_in_a_private_chat_is_served(self):
        seen = []
        self.bot.on_message = lambda m: seen.append("m")
        self.bot.on_callback = lambda c: seen.append("c")
        h = self.bot.handle
        h({"message": {"from": {"id": 1}, "chat": {"id": 1, "type": "private"}, "text": "x"}})
        h({"message": {"from": {"id": ADMIN}, "chat": {"id": -5, "type": "group"}, "text": "x"}})
        h({"message": {"from": {"id": ADMIN}, "chat": {"id": -5, "type": "supergroup"}, "text": "x"}})
        h({"callback_query": {"id": "1", "from": {"id": 1}, "message": {"chat": {"type": "private"}}, "data": "u:l"}})
        h({"callback_query": {"id": "1", "from": {"id": ADMIN}, "message": {"chat": {"type": "group"}}, "data": "u:l"}})
        h({"callback_query": {"id": "1", "from": {"id": ADMIN}, "data": "u:l"}})
        self.assertEqual(seen, [])
        h({"message": {"from": {"id": ADMIN}, "chat": {"id": ADMIN, "type": "private"}, "text": "x"}})
        h({"callback_query": {"id": "1", "from": {"id": ADMIN}, "message": {"chat": {"type": "private"}}, "data": "u:l"}})
        self.assertEqual(seen, ["m", "c"])


class Passwords(BotCase):
    def test_policy_regex(self):
        self.assertIsNone(self.bot.PASS_RE.match("short12345!"))          # 11
        self.assertIsNotNone(self.bot.PASS_RE.match("Abcdefghij1!"))      # 12
        self.assertIsNone(self.bot.PASS_RE.match('has"quote123456'))
        self.assertIsNone(self.bot.PASS_RE.match("with space 12345"))

    def test_new_password_goes_through_stdin_and_the_message_is_deleted(self):
        self.bot.awaiting[ADMIN] = {"kind": "passwd", "user": "alice"}
        self.bot.on_message(self.msg(GOODPW, mid=55))
        call = [c for c in self.vpn.calls if c[0][:2] == ("user", "passwd")][0]
        self.assertNotIn(GOODPW, " ".join(call[0]), "the password must never be an argument")
        self.assertIn("--stdin", call[0])
        self.assertEqual(call[1], GOODPW + "\n")
        self.assertEqual(self.tg.methods("deleteMessage")[0], {"chat_id": ADMIN, "message_id": 55})

    def test_invalid_password_is_rejected_and_still_deleted(self):
        self.bot.awaiting[ADMIN] = {"kind": "passwd", "user": "alice"}
        self.bot.on_message(self.msg("short", mid=56))
        self.assertFalse([c for c in self.vpn.calls if c[0][:2] == ("user", "passwd")])
        self.assertEqual(len(self.tg.methods("deleteMessage")), 1)
        self.assertIn(ADMIN, self.bot.awaiting)          # still waiting for a valid password

    def test_auto_password(self):
        self.bot.awaiting[ADMIN] = {"kind": "passwd", "user": "alice"}
        self.bot.on_message(self.msg("auto"))
        call = [c for c in self.vpn.calls if c[0][:2] == ("user", "passwd")][0]
        self.assertEqual(call[0][:4], ("user", "passwd", "alice", "auto"))
        self.assertEqual(self.tg.methods("deleteMessage"), [])

    def test_no_secret_ever_reaches_a_vpn_argument(self):
        self.bot.send_profiles("alice")
        for args, _ in self.vpn.calls:
            self.assertNotIn(GOODPW, " ".join(args))


class Wipe(BotCase):
    def pending(self):
        return self.bot.load_state()["wipe"]["pending"]

    def test_credentials_are_tracked_for_deletion(self):
        self.bot.send_profiles("alice")
        # conn_info + zed link + 4 documents (sswan, mobileconfig, zed txt, ca.crt)
        self.assertEqual(len(self.pending()), 6)
        for chat, mid, due in self.pending():
            self.assertEqual(chat, ADMIN)
            self.assertAlmostEqual(due, time.time() + self.bot.WIPE_MINUTES * 60, delta=5)
        self.assertTrue(any("30" in (m or {}).get("text", "") for m in self.tg.methods("sendMessage")), "the admin is told about the deletion")

    def test_nothing_tracked_when_switched_off(self):
        self.bot.update_state(lambda st: st["wipe"].__setitem__("on", False))
        self.bot.send_profiles("alice")
        self.assertEqual(self.pending(), [])

    def test_due_items_are_deleted_future_ones_kept(self):
        now = time.time()
        self.bot.update_state(lambda st: st["wipe"]["pending"].extend([[ADMIN, 1, now - 5], [ADMIN, 2, now + 600]]))
        self.bot.wipe_due()
        self.assertEqual(self.tg.methods("deleteMessage"), [{"chat_id": ADMIN, "message_id": 1}])
        self.assertEqual([p[1] for p in self.pending()], [2])

    def test_network_errors_are_retried_telegram_errors_are_final(self):
        now = time.time()
        self.bot.update_state(lambda st: st["wipe"]["pending"].append([ADMIN, 1, now - 5]))
        self.tg.delete_result = {"ok": False, "description": "timed out"}          # no error_code = network problem
        self.bot.wipe_due()
        self.assertEqual(len(self.pending()), 1, "retry later")
        self.tg.delete_result = {"ok": False, "error_code": 400, "description": "message to delete not found"}
        self.bot.wipe_due()
        self.assertEqual(self.pending(), [], "Telegram answered: stop trying")
        self.bot.update_state(lambda st: st["wipe"]["pending"].append([ADMIN, 9, now - 7 * 3600]))
        self.tg.delete_result = {"ok": False, "description": "timed out"}
        self.bot.wipe_due()
        self.assertEqual(self.pending(), [], "gives up after 6 hours")

    def test_pending_deletions_survive_a_restart(self):
        self.bot.send_profiles("alice")
        n = len(self.pending())
        self.bot = importlib.reload(self.bot)          # a new process reads the state file again
        self.assertEqual(len(self.bot.load_state()["wipe"]["pending"]), n)

    def test_toggle_off_cancels_pending_and_unknown_keys_are_ignored(self):
        self.bot.send_profiles("alice")
        self.bot.tg.calls.clear()
        cq = lambda d: {"id": "1", "from": {"id": ADMIN}, "message": {"chat": {"id": ADMIN, "type": "private"}, "message_id": 1}, "data": d}
        self.bot.handle({"callback_query": cq("n:t:wipe")})
        st = self.bot.load_state()
        self.assertFalse(st["wipe"]["on"])
        self.assertEqual(st["wipe"]["pending"], [])
        self.bot.handle({"callback_query": cq("n:t:bogus")})
        self.assertNotIn("bogus", self.bot.load_state()["notify"])
        self.bot.handle({"callback_query": cq("n:t:wipe")})
        self.assertTrue(self.bot.load_state()["wipe"]["on"])

    def test_state_updates_from_many_threads_are_not_lost(self):
        ts = [threading.Thread(target=lambda: self.bot.update_state(lambda st: st["notify"].__setitem__("conn", not st["notify"]["conn"]))) for _ in range(60)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertFalse(self.bot.load_state()["notify"]["conn"])       # 60 flips from False


class Backups(BotCase):
    def touch(self, name, age=0):
        p = os.path.join(self.tmp, "bak", name)
        open(p, "w").write("x")
        os.utime(p, (time.time() - age, time.time() - age))
        return p

    def test_without_a_key_nothing_is_ever_sent(self):
        self.touch("ikev2-backup-1.tar.gz")
        self.bot.job_send_backup({"chat": {"id": ADMIN}, "message_id": 1})
        self.assertEqual(self.tg.docs, [])
        self.assertFalse([c for c in self.vpn.calls if c[0][:1] == ("backup",)], "no backup is even created")
        self.assertIn("backup key init", str(self.tg.methods("editMessageText")))

    def test_with_a_key_only_the_encrypted_file_is_sent(self):
        self.vpn.kv["backup_key"] = "yes"
        self.touch("ikev2-backup-1.tar.gz", age=100)

        def make(args):
            self.assertEqual(args, ("backup", "--encrypt"))
            self.touch("ikev2-backup-2.tar.gz")
            self.touch("ikev2-backup-2.tar.gz.enc")
            return 0, "ok"
        self.vpn.on_backup = make
        self.bot.job_send_backup({"chat": {"id": ADMIN}, "message_id": 1})
        self.assertEqual([d[0] for d in self.tg.docs], ["ikev2-backup-2.tar.gz.enc"])
        self.assertIn("openssl cms -decrypt", self.tg.docs[0][1])

    def test_a_failed_encryption_never_falls_back_to_the_plain_archive(self):
        self.vpn.kv["backup_key"] = "yes"
        self.touch("ikev2-backup-1.tar.gz")
        self.vpn.on_backup = lambda args: (1, "boom")
        self.bot.job_send_backup({"chat": {"id": ADMIN}, "message_id": 1})
        self.assertEqual(self.tg.docs, [])

    def test_latest_backup_helper_separates_plain_and_encrypted(self):
        self.touch("ikev2-backup-1.tar.gz", age=50)
        self.touch("ikev2-backup-2.tar.gz")
        self.touch("ikev2-backup-1.tar.gz.enc", age=30)
        self.touch("ikev2-prerestore-1.tar.gz")
        self.assertTrue(self.bot.latest_backup().endswith("backup-2.tar.gz"))
        self.assertTrue(self.bot.latest_backup(encrypted=True).endswith("backup-1.tar.gz.enc"))

    def test_make_backup_encrypts_when_a_key_exists(self):
        self.vpn.kv["backup_key"] = "yes"
        self.vpn.on_backup = lambda a: (0, "Backup created: /var/backups/ikev2/ikev2-backup-1.tar.gz")
        self.bot.job_backup()
        self.assertIn(("backup", "--encrypt"), [c[0] for c in self.vpn.calls])
        self.vpn.kv["backup_key"] = "no"
        self.bot.job_backup()
        self.assertIn(("backup",), [c[0] for c in self.vpn.calls])


class CertAlerts(BotCase):
    def test_alert_levels(self):
        a = self.bot.cert_alert
        self.assertIsNone(a({"cert_state": "ok", "cert_days": "100"}))
        self.assertIn("5", a({"cert_state": "expiring", "cert_days": "5"}))
        self.assertIn("14", a({"cert_days": "14"}))
        self.assertIsNone(a({"cert_days": "15"}))
        self.assertIn("EXPIRED", a({"cert_state": "expired", "cert_days": "-3"}))
        self.assertIn("EXPIRED", a({"cert_days": "-30"}), "older vpn without cert_state: negative days still alert")
        self.assertIn("missing", a({"cert_state": "missing", "cert_days": "none"}))
        self.assertIsNone(a({}))

    def test_status_text(self):
        t = self.bot.cert_text
        self.assertIn("100", t({"cert_state": "ok", "cert_days": "100"}))
        self.assertIn("EXPIRED 3", t({"cert_state": "expired", "cert_days": "-3"}))
        self.assertIn("missing", t({"cert_state": "missing", "cert_days": "none"}))


class Texts(BotCase):
    def test_languages_have_identical_keys_and_placeholders(self):
        en, fa = self.bot.T["en"], self.bot.T["fa"]
        self.assertEqual(sorted(set(en) ^ set(fa)), [])
        for k in en:
            self.assertEqual(sorted(re.findall(r"\{(\w+)\}", en[k])), sorted(re.findall(r"\{(\w+)\}", fa[k])), k)

    def test_no_duplicate_keys_in_the_text_tables(self):
        tree = ast.parse(open(os.path.join(ROOT, "bot.py"), encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                keys = [k.value for k in node.keys if isinstance(k, ast.Constant)]
                dups = {k for k in keys if keys.count(k) > 1}
                self.assertFalse(dups, f"duplicate dict keys at line {node.lineno}: {dups}")

    def test_dead_code_is_gone(self):
        self.assertFalse(hasattr(self.bot, "INCOMING"))
        self.assertFalse(hasattr(self.bot.TG, "download"))
        src = open(os.path.join(ROOT, "bot.py"), encoding="utf-8").read()
        self.assertNotIn("api.telegram.org/file/", src)

    def test_html_is_escaped_in_user_facing_text(self):
        out = self.bot.tr("conn_info", server=self.bot.esc("a<b>"), user=self.bot.esc("x&y"), pw=self.bot.esc("<i>"))
        self.assertNotIn("<b>", out.replace("<b>Connection", "").replace("<b>اطلاعات", ""))
        self.assertIn("&lt;", out)

    def test_every_text_can_be_formatted(self):
        samples = dict(ver="1", server="s", user="u", pw="p", link="l", n=1, state="s", online="o", d=3, ip="1.1.1.1", err="e", path="p",
                       last="l", enc="e", cur="a", new="b", log="l", dns="d", svc="s", users=1, enabled=1, cert="c", sw="s", fw="f",
                       mode="m", pool="p", m=30)
        for lang in ("en", "fa"):
            for k, v in self.bot.T[lang].items():
                names = set(re.findall(r"\{(\w+)\}", v))
                v.format(**{n: samples[n] for n in names})


class ParsingHelpers(BotCase):
    def test_kv_status_and_users(self):
        self.assertEqual(self.bot.kv_status()["version"], "9.9.9")
        orig = self.vpn.__call__

        def users(*a, **k):
            return (0, "alice|enabled|1\nbob|disabled|2") if a[:2] == ("user", "list") else orig(*a, **k)
        self.bot.vpn = users
        self.assertEqual(self.bot.list_users(), [("alice", "enabled"), ("bob", "disabled")])


if __name__ == "__main__":
    unittest.main(verbosity=1)
