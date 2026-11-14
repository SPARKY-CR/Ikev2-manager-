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
        if args == ("get",):
            return 0, "SETTING            VALUE\nDNS                1.1.1.1  [default]\nMOBIKE             yes  [default]\nQUOTA_ACTION       disable  [default]"
        if args[:1] == ("get",):
            return 0, f"{args[1]} = x\n  accepts: yes | no"
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
        self.bot.run_thread = lambda fn, *a: fn(*a)   # run the worker threads inline: deterministic
        self.bot.update_state(lambda st: st.__setitem__("lang", "en"))     # the bot defaults to Persian

    def shown(self):
        return [d for m, d in self.tg.calls if m in ("sendMessage", "editMessageText")][-1]

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
        for table in (self.bot.TX, self.bot.TX_FA):       # the 1.4.0 tables: placeholders are free-form
            for k, v in table.items():
                v.format(**{n: "x" for n in re.findall(r"\{(\w+)\}", v)})


class ParsingHelpers(BotCase):
    def test_kv_status_and_users(self):
        self.assertEqual(self.bot.kv_status()["version"], "9.9.9")
        orig = self.vpn.__call__

        def users(*a, **k):
            return (0, "alice|enabled|1\nbob|disabled|2") if a[:2] == ("user", "list") else orig(*a, **k)
        self.bot.vpn = users
        self.assertEqual(self.bot.list_users(), [("alice", "enabled"), ("bob", "disabled")])


def cq(data):
    return {"id": "1", "from": {"id": ADMIN}, "data": data,
            "message": {"chat": {"id": ADMIN, "type": "private"}, "message_id": 9}}


class Markdown(BotCase):
    def test_basic_entities_and_escaping(self):
        c = self.bot.to_mdv2
        self.assertEqual(c("<b>Users</b> (3)"), r"*Users* \(3\)")
        self.assertEqual(c("a_b.c-d!"), r"a\_b\.c\-d\!")
        self.assertEqual(c("<code>x_y.z</code>"), "`x_y.z`")
        self.assertEqual(c("<code>a`b\\c</code>"), "`a\\`b\\\\c`")
        self.assertEqual(c("<pre>l1\nl2 (x)</pre>"), "```\nl1\nl2 (x)\n```")
        self.assertEqual(c("1 &lt; 2 &amp; 3"), r"1 < 2 & 3")
        self.assertEqual(c('<a href="https://x.y/a(b)">link</a>'), r"[link](https://x.y/a(b\))")
        self.assertEqual(c("<i>it</i> <tg-spoiler>s</tg-spoiler>"), "_it_ ||s||")

    def test_blockquotes(self):
        c = self.bot.to_mdv2
        self.assertEqual(c("<blockquote>a\nb</blockquote>"), ">a\n>b")
        self.assertEqual(c("<blockquote expandable>a\nb</blockquote>"), "**>a\n>b||")

    def test_unclosed_and_stray_tags_never_raise(self):
        self.assertEqual(self.bot.to_mdv2("<b>open"), "*open*")
        self.assertEqual(self.bot.to_mdv2("close</b>"), "close")

    def test_no_reserved_character_is_left_unescaped(self):
        """Every text of both languages, rendered with awkward values, must be valid MarkdownV2."""
        reserved = re.compile(r"[\[\]()~#+\-=|{}.!]")
        evil = "a_b*c[d](e)~f`g>h#i+j-k=l|m{n}o.p!q"
        texts = list(self.bot.T["en"].values()) + list(self.bot.T["fa"].values()) + list(self.bot.TX.values()) + list(self.bot.TX_FA.values())
        for t in texts:
            names = re.findall(r"\{(\w+)\}", t)
            out = self.bot.to_mdv2(t.format(**{n: self.bot.esc(evil) for n in names}))
            out = re.sub(r"```.*?```", "", out, flags=re.S)
            out = re.sub(r"\\.", "", out)
            out = re.sub(r"`[^`]*`", "", out)
            out = out.replace("**>", "").replace("||", "")
            out = re.sub(r"(?m)^>", "", out)
            self.assertIsNone(reserved.search(out), f"unescaped character in: {t[:60]!r} -> {out[:120]!r}")

    def test_messages_are_sent_as_markdownv2(self):
        self.bot.send("<b>x</b> a.b")
        d = self.tg.methods("sendMessage")[-1]
        self.assertEqual(d["parse_mode"], "MarkdownV2")
        self.assertEqual(d["text"], r"*x* a\.b")

    def test_a_formatting_error_falls_back_to_plain_text(self):
        calls = []

        def call(method, data=None, timeout=40):
            calls.append((method, dict(data or {})))
            if len(calls) == 1:
                return {"ok": False, "error_code": 400, "description": "Bad Request: can't parse entities: ..."}
            return {"ok": True, "result": {"message_id": 1}}
        self.tg.call = call
        self.bot.send("<b>Hello</b> &lt;x&gt;")
        self.assertEqual(len(calls), 2)
        self.assertNotIn("parse_mode", calls[1][1])
        self.assertEqual(calls[1][1]["text"], "Hello <x>")

    def test_new_texts_exist_in_both_languages_with_the_same_placeholders(self):
        self.assertEqual(sorted(set(self.bot.TX) ^ set(self.bot.TX_FA)), [])
        for k, v in self.bot.TX.items():
            self.assertEqual(sorted(re.findall(r"\{(\w+)\}", v)), sorted(re.findall(r"\{(\w+)\}", self.bot.TX_FA[k])), k)

    def test_persian_mode_uses_the_persian_texts(self):
        self.bot.update_state(lambda st: st.__setitem__("lang", "fa"))
        self.assertEqual(self.bot.tr("b_quota"), self.bot.TX_FA["b_quota"])
        self.assertIn("\u062d", self.bot.quota_block(self.bot.qrec("alice")))
        self.assertIn("\u0647\u0631\u06af\u0632", self.bot.exp_text(0))
        self.bot.update_state(lambda st: st.__setitem__("lang", "en"))
        self.assertEqual(self.bot.tr("b_quota"), self.bot.TX["b_quota"])


class Quota(BotCase):
    def setUp(self):
        super().setUp()
        self.bot.run_thread = lambda fn, *a: fn(*a)          # run the worker threads inline
        open(os.path.join(self.tmp, "etc", "users.db"), "w").write("alice:Pw:enabled:1\nbob:Pw:disabled:2\n")
        orig = self.vpn.__call__

        def users(*a, **k):
            if a[:2] == ("user", "list"):
                return 0, "alice|enabled|1\nbob|disabled|2"
            return orig(*a, **k)
        self.bot.vpn = users
        self.calls = lambda: [c[0] for c in self.vpn.calls]

    def q(self, name, **kw):
        import ikev2lib as L
        qs = L.load_quotas()
        r = qs.get(name) or L.new_record(name)
        r.update(kw)
        qs[name] = r
        L.save_quotas(qs)

    def test_user_view_shows_usage_and_expiry(self):
        import time as _t
        self.q("alice", limit=10 * 1024 ** 3, used=3 * 1024 ** 3, expires=int(_t.time()) + 5 * 86400)
        self.bot.show_user(None, "alice")
        text = self.tg.methods("sendMessage")[-1]["text"]
        self.assertIn("30%", text)
        self.assertIn("3\\.0 GB", text)
        self.assertIn("5d left", text.replace("\\", ""))
        buttons = [b["callback_data"] for row in self.tg.methods("sendMessage")[-1]["reply_markup"]["inline_keyboard"] for b in row]
        self.assertIn("q:v:alice", buttons)
        self.assertIn("u:k:alice", buttons)

    def test_overview_lists_users_most_used_first(self):
        self.q("bob", limit=1024 ** 3, used=900 * 1024 ** 2)
        self.q("alice", limit=1024 ** 3, used=100 * 1024 ** 2)
        self.bot.show_quotas(None)
        text = self.tg.methods("sendMessage")[-1]["text"]
        self.assertLess(text.index("bob"), text.index("alice"))
        self.assertTrue(text.count("**>") == 1, "the list is one expandable quote")

    def test_quick_buttons_call_the_cli(self):
        self.bot.handle({"callback_query": cq("q:g:alice:10G")})
        self.assertIn(("quota", "add", "alice", "--limit", "10G"), self.calls())
        self.bot.handle({"callback_query": cq("q:y:alice:30")})
        self.assertIn(("quota", "add", "alice", "--days", "30"), self.calls())
        self.bot.handle({"callback_query": cq("q:g0:alice")})
        self.assertIn(("quota", "set", "alice", "--limit", "unlimited"), self.calls())
        self.bot.handle({"callback_query": cq("q:y0:alice")})
        self.assertIn(("quota", "set", "alice", "--days", "never"), self.calls())
        self.bot.handle({"callback_query": cq("q:r:alice")})
        self.assertIn(("quota", "reset", "alice"), self.calls())

    def test_action_button_cycles(self):
        self.bot.handle({"callback_query": cq("q:a:alice")})
        self.assertIn(("quota", "set", "alice", "--action", "disable"), self.calls())
        self.q("alice", action="notify")
        self.bot.handle({"callback_query": cq("q:a:alice")})
        self.assertIn(("quota", "set", "alice", "--action", "default"), self.calls())

    def test_typed_limit_and_expiry(self):
        self.bot.handle({"callback_query": cq("q:sl:alice")})
        self.assertEqual(self.bot.awaiting[ADMIN], {"kind": "q_limit", "user": "alice"})
        self.bot.on_message(self.msg("1.5T"))
        self.assertIn(("quota", "set", "alice", "--limit", "1.5T"), self.calls())
        self.bot.handle({"callback_query": cq("q:se:alice")})
        self.bot.on_message(self.msg("2026-12-31"))
        self.assertIn(("quota", "set", "alice", "--expires", "2026-12-31"), self.calls())

    def test_bad_names_in_callbacks_are_ignored(self):
        for d in ("q:g:../etc:5G", "q:r:a b", "u:k:x;y", "q:v:"):
            self.bot.handle({"callback_query": cq(d)})
        self.assertFalse([c for c in self.calls() if c[:1] == ("quota",) and len(c) > 1 and c[1] in ("add", "set", "reset")])

    def test_wizard_creates_a_user_with_limits(self):
        self.bot.handle({"callback_query": cq("a:add")})
        self.bot.on_message(self.msg("carol"))
        self.assertEqual(self.bot.wizard[ADMIN]["name"], "carol")
        self.bot.handle({"callback_query": cq("w:l:20G")})
        self.bot.handle({"callback_query": cq("w:d:30")})
        self.bot.handle({"callback_query": cq("w:a")})            # default -> disable
        self.bot.handle({"callback_query": cq("w:a")})            # -> delete
        self.bot.handle({"callback_query": cq("w:go")})
        add = [c for c in self.calls() if c[:2] == ("user", "add")][0]
        self.assertEqual(add, ("user", "add", "carol", "--plain", "--limit", "20G", "--days", "30", "--action", "delete"))
        self.assertNotIn(ADMIN, self.bot.wizard)

    def test_wizard_custom_values_are_validated(self):
        self.bot.handle({"callback_query": cq("a:add")})
        self.bot.on_message(self.msg("carol"))
        self.bot.handle({"callback_query": cq("w:l:c")})
        self.bot.on_message(self.msg("lots"))
        self.assertEqual(self.bot.wizard[ADMIN]["limit"], "unlimited", "the bad value was not taken")
        self.assertIn(ADMIN, self.bot.awaiting, "still waiting for a valid value")
        self.bot.on_message(self.msg("750M"))
        self.assertEqual(self.bot.wizard[ADMIN]["limit"], "750m")
        self.bot.handle({"callback_query": cq("w:d:c")})
        self.bot.on_message(self.msg("2031-01-31"))
        self.assertEqual(self.bot.wizard[ADMIN]["days"], "2031-01-31")

    def test_wizard_starts_from_the_servers_defaults(self):
        self.vpn.kv.update(default_limit="20G", default_days="30")
        self.bot.handle({"callback_query": cq("a:add")})
        self.bot.on_message(self.msg("carol"))
        self.assertEqual((self.bot.wizard[ADMIN]["limit"], self.bot.wizard[ADMIN]["days"]), ("20G", "30"))

    def test_invalid_or_existing_names_never_start_the_wizard(self):
        self.bot.handle({"callback_query": cq("a:add")})
        self.bot.on_message(self.msg("bad name!"))
        self.assertNotIn(ADMIN, self.bot.wizard)
        self.bot.handle({"callback_query": cq("a:add")})
        self.bot.on_message(self.msg("alice"))
        self.assertNotIn(ADMIN, self.bot.wizard)

    def test_disconnect_button(self):
        import ikev2lib as L
        killed = []
        orig = L.kick
        L.kick = lambda n: killed.append(n) or 2
        try:
            self.bot.handle({"callback_query": cq("u:k:alice")})
        finally:
            L.kick = orig
        self.assertEqual(killed, ["alice"])

    def test_every_callback_fits_telegrams_64_byte_limit(self):
        long = "a" * 32
        open(os.path.join(self.tmp, "etc", "users.db"), "w").write(f"{long}:Pw:enabled:1\n")
        self.bot.vpn = lambda *a, **k: (0, f"{long}|enabled|1") if a[:2] == ("user", "list") else self.vpn(*a, **k)
        self.bot.show_users(None); self.bot.show_user(None, long); self.bot.show_quota_user(None, long); self.bot.show_quotas(None)
        self.bot.start_wizard(long); self.bot.show_settings(None); self.bot.show_security(None); self.bot.show_server(None)
        n = 0
        for m in self.tg.methods("sendMessage"):
            for row in (m.get("reply_markup") or {}).get("inline_keyboard", []):
                for b in row:
                    n += 1
                    self.assertLessEqual(len(b["callback_data"].encode()), 64, b["callback_data"])
        self.assertGreater(n, 30)

    def test_alert_texts_and_buttons(self):
        ev = self.bot.send_quota_event
        ev({"kind": "warn_limit", "user": "alice", "used": 8 * 1024 ** 3, "limit": 10 * 1024 ** 3})
        self.assertIn("80%", self.tg.methods("sendMessage")[-1]["text"])
        ev({"kind": "limit", "user": "alice", "action": "disable", "used": 11, "limit": 10})
        t = self.tg.methods("sendMessage")[-1]
        self.assertIn("disabled", t["text"]); self.assertIn("q:v:alice", str(t["reply_markup"]))
        ev({"kind": "expired", "user": "bob", "action": "delete"})
        t = self.tg.methods("sendMessage")[-1]
        self.assertIn("deleted", t["text"]); self.assertNotIn("reply_markup", t, "nothing to open for a deleted user")
        ev({"kind": "limit", "user": "alice", "action": "notify", "used": 11, "limit": 10})
        self.assertIn("notify only", self.tg.methods("sendMessage")[-1]["text"].replace("\\", ""))
        n = len(self.tg.methods("sendMessage"))
        ev({"kind": "nonsense", "user": "x"})
        self.assertEqual(len(self.tg.methods("sendMessage")), n)

    def test_quota_alerts_can_be_switched_off(self):
        self.assertTrue(self.bot.load_state()["notify"]["quota"])
        self.bot.handle({"callback_query": cq("n:t:quota")})
        self.assertFalse(self.bot.load_state()["notify"]["quota"])


class ServerTools(BotCase):
    def setUp(self):
        super().setUp()
        self.bot.run_thread = lambda fn, *a: fn(*a)
        self.calls = lambda: [c[0] for c in self.vpn.calls]
        self.cb = lambda d: self.bot.handle({"callback_query": cq(d)})

    def test_dangerous_actions_need_a_second_tap(self):
        for first, then, cmd in (("se:fon", "se:fongo", ("fw", "on")), ("se:f2b", "se:f2bgo", ("security", "fail2ban")),
                                 ("se:au", "se:augo", ("security", "autoupdate")), ("st:reset", "st:resetgo", ("reset", "--yes")),
                                 ("sv:du", "sv:dugo", ("domain", "unset")), ("rw:c:extra", "rw:cgo:extra", ("raw", "clear", "extra"))):
            self.cb(first)
            self.assertNotIn(cmd, self.calls(), f"{first} must only ask")
            self.cb(then)
            self.assertIn(cmd, self.calls(), f"{then} must run it")

    def test_simple_actions_map_to_cli_commands(self):
        for d, cmd in (("se:foff", ("fw", "off")), ("se:fs", ("fw", "status")), ("sv:cr", ("cert", "renew")),
                       ("sv:cf", ("cert", "renew", "--force")), ("sv:ir", ("ip", "refresh")), ("st:apply", ("conf", "apply")),
                       ("st:pi:strict-sha2", ("preset", "ike", "strict-sha2")), ("sv:st", ("selftest",))):
            self.cb(d)
            self.assertIn(cmd, self.calls(), d)

    def test_settings_roundtrip(self):
        self.cb("st:m")
        self.assertIn("DNS", str(self.shown()))
        self.cb("st:v:MOBIKE:no")
        self.assertIn(("set", "MOBIKE", "no"), self.calls())
        self.cb("st:d:DNS")
        self.assertIn(("set", "DNS", "default"), self.calls())
        self.cb("st:e:DNS")
        self.assertEqual(self.bot.awaiting[ADMIN], {"kind": "set", "key": "DNS"})
        self.bot.on_message(self.msg("9.9.9.9"))
        self.assertIn(("set", "DNS", "9.9.9.9"), self.calls())

    def test_unknown_setting_keys_are_ignored(self):
        self.cb("st:v:EVIL:x"); self.cb("st:d:EVIL"); self.cb("st:e:EVIL")
        self.assertFalse([c for c in self.calls() if c[:1] == ("set",)])

    def test_a_typed_value_is_a_single_argument(self):
        self.cb("st:e:DNS")
        self.bot.on_message(self.msg("1.1.1.1 ; reboot"))
        call = [c for c in self.calls() if c[:2] == ("set", "DNS")][0]
        self.assertEqual(call, ("set", "DNS", "1.1.1.1 ; reboot"))

    def test_domain_flow_asks_before_switching(self):
        self.cb("sv:ds")
        self.bot.on_message(self.msg("vpn.example.com me@example.com"))
        self.assertNotIn(("domain", "set", "vpn.example.com", "me@example.com"), self.calls())
        self.cb("sv:dgo")
        self.assertIn(("domain", "set", "vpn.example.com", "me@example.com"), self.calls())
        self.cb("sv:ds")
        self.bot.on_message(self.msg("not a domain"))
        self.assertNotIn(ADMIN, self.bot.pending)

    def test_firewall_ports_and_raw_snippets(self):
        self.cb("se:fp")
        self.bot.on_message(self.msg("22 2222"))
        self.assertIn(("fw", "ports", "22 2222"), self.calls())
        self.cb("rw:e:connection")
        self.bot.on_message(self.msg("reauth_time = 24h"))
        call = [c for c in self.vpn.calls if c[0] == ("raw", "set", "connection")][0]
        self.assertEqual(call[1], "reauth_time = 24h\n", "the snippet goes through stdin")
        self.cb("rw:v:../../etc"); self.cb("rw:cgo:bogus")
        self.assertFalse([c for c in self.calls() if c[:2] in (("raw", "clear"),) and c[2] == "bogus"])

    def test_restore_lists_only_plain_archives_and_confirms(self):
        d = os.path.join(self.tmp, "bak")
        for n in ("ikev2-backup-1.tar.gz", "ikev2-backup-2.tar.gz.enc"):
            open(os.path.join(d, n), "w").write("x")
        self.cb("b:rs")
        text = str(self.shown()["reply_markup"])
        self.assertIn("b:r:0", text); self.assertNotIn("b:r:1", text); self.assertNotIn("enc", text)
        self.cb("b:r:0")
        self.assertFalse([c for c in self.calls() if c[:1] == ("restore",)], "needs the second tap")
        self.cb("b:rgo:0")
        self.assertEqual([c for c in self.calls() if c[:1] == ("restore",)], [("restore", os.path.join(d, "ikev2-backup-1.tar.gz"))])
        self.cb("b:rgo:7")
        self.assertEqual(len([c for c in self.calls() if c[:1] == ("restore",)]), 1)

    def test_nothing_in_the_new_menus_can_uninstall_or_expose_the_backup_key(self):
        src = open(os.path.join(ROOT, "bot.py"), encoding="utf-8").read()
        for bad in ('"uninstall"', '"backup", "key"', "'uninstall'"):
            self.assertNotIn(bad, src)

    def test_logs_and_certificate_views(self):
        self.cb("sv:lg"); self.cb("sv:bl"); self.cb("sv:ce"); self.cb("sv:m"); self.cb("se:m"); self.cb("sv:dm")
        self.assertIn(("logs", "40"), self.calls()); self.assertIn(("bot", "logs", "40"), self.calls())
        self.assertIn(("cert", "info"), self.calls())


class PersianScreens(BotCase):
    def test_every_screen_renders_in_both_languages(self):
        self.bot.run_thread = lambda fn, *a: fn(*a)
        open(os.path.join(self.tmp, "etc", "users.db"), "w").write("alice:Pw:enabled:1\n")
        self.bot.vpn = lambda *a, **k: (0, "alice|enabled|1") if a[:2] == ("user", "list") else self.vpn(*a, **k)
        for lang in ("fa", "en"):
            self.bot.update_state(lambda st, lang=lang: st.__setitem__("lang", lang))
            self.tg.calls.clear()
            for fn in (self.bot.show_main, self.bot.show_users, self.bot.show_quotas, self.bot.show_server, self.bot.show_security,
                       self.bot.show_settings, self.bot.show_notify, self.bot.show_address, self.bot.show_cert):
                fn(None)
            self.bot.show_user(None, "alice"); self.bot.show_quota_user(None, "alice"); self.bot.start_wizard("carol")
            for d in ("sv:lg", "sv:st", "se:fon", "st:reset", "st:ike", "rw:m", "rw:v:extra", "b:rs", "w:a", "q:a:alice"):
                self.bot.handle({"callback_query": cq(d)})
            for ev in ({"kind": "warn_limit", "user": "alice", "used": 8, "limit": 10}, {"kind": "warn_expiry", "user": "alice", "expires": 1},
                       {"kind": "limit", "user": "alice", "action": "delete"}, {"kind": "expired", "user": "alice", "action": "notify"}):
                self.bot.send_quota_event(ev)
            self.assertGreater(len(self.tg.calls), 20, lang)
            persian = sum(1 for ch in str(self.tg.calls) if "\u0600" <= ch <= "\u06ff")
            if lang == "fa":
                self.assertGreater(persian, 500)
            else:
                self.assertLess(persian, 20, "English mode: only the language-switch button is Persian")


class Speed(BotCase):
    def _status_calls(self):
        return [c for c in self.vpn.calls if c[0][:2] == ("status", "--kv")]

    def test_status_is_cached_for_a_while_and_force_refreshes(self):
        self.assertEqual(self.bot.kv_status()["version"], "9.9.9")
        self.assertEqual(self.bot.kv_status()["version"], "9.9.9")
        self.assertEqual(len(self._status_calls()), 1, "the second read comes from the cache")
        d = self.bot.kv_status()
        d["version"] = "tampered"
        self.assertEqual(self.bot.kv_status()["version"], "9.9.9", "callers cannot poison the cache")
        self.vpn.kv["version"] = "1.2.3"
        self.assertEqual(self.bot.kv_status()["version"], "9.9.9", "still cached")
        self.assertEqual(self.bot.kv_status(force=True)["version"], "1.2.3")
        self.assertEqual(len(self._status_calls()), 2)

    def test_a_failed_status_read_is_not_cached(self):
        self.bot.vpn = lambda *a, **k: (1, "boom")
        self.assertEqual(self.bot.kv_status(), {})
        self.assertEqual(self.bot.kv_status(), {})
        # no cache entry was kept: a fixed CLI is picked up right away
        self.bot.vpn = self.vpn
        self.assertEqual(self.bot.kv_status()["version"], "9.9.9")

    def test_online_sessions_are_cached_and_dropped(self):
        seen = []
        orig = self.bot.L.online
        try:
            self.bot.L.online = lambda: seen.append(1) or [{"user": "alice", "id": 7}]
            self.assertEqual(len(self.bot.online_cached()), 1)
            self.assertEqual(len(self.bot.online_cached()), 1)
            self.assertEqual(len(seen), 1, "the second read comes from the cache")
            self.bot.drop_caches()
            self.assertEqual(len(self.bot.online_cached()), 1)
            self.assertEqual(len(seen), 2)
            self.bot._online_cache["at"] = 0      # pretend the TTL expired
            self.assertEqual(len(self.bot.online_cached()), 1)
            self.assertEqual(len(seen), 3)
        finally:
            self.bot.L.online = orig

    def _local_tg(self, close_first=False):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        connections, state = [], {"close_first": close_first}

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self):
                super().setup()
                connections.append(1)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                body = b'{"ok": true, "result": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if state["close_first"]:
                    state["close_first"] = False
                    self.send_header("Connection", "close")
                    self.close_connection = True
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        self.addCleanup(srv.server_close)
        tg = self.bot.TG("TOKEN", base=f"http://127.0.0.1:{srv.server_address[1]}/botTOKEN/")
        return tg, connections

    def test_telegram_calls_share_one_connection(self):
        tg, connections = self._local_tg()
        self.assertTrue(tg.call("sendMessage", {"chat_id": 1, "text": "hi"})["ok"])
        self.assertTrue(tg.call("sendMessage", {"chat_id": 1, "text": "hi"})["ok"])
        self.assertEqual(len(connections), 1, "both calls reuse one keep-alive connection")

    def test_a_closed_connection_is_retried_once(self):
        tg, connections = self._local_tg(close_first=True)
        self.assertTrue(tg.call("sendMessage", {"chat_id": 1, "text": "hi"})["ok"])
        self.assertTrue(tg.call("sendMessage", {"chat_id": 1, "text": "hi"})["ok"],
                        "the server closed the idle connection; the call must still go through")
        self.assertEqual(len(connections), 2, "one retry on a fresh connection")


if __name__ == "__main__":
    unittest.main(verbosity=1)
