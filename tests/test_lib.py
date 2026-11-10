"""Unit tests for ikev2lib.py (SA parsing, ZedSecure links, backup archive validation)."""
import base64
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = os.environ.get("ROOT") or os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
import ikev2lib as L  # noqa: E402

SAS = """\
rw: #3, ESTABLISHED, IKEv2, 1c2d3e4f5a6b7c8d_i 8d7c6b5a4f3e2d1c_r*
  local  '203.0.113.7' @ 10.0.0.5[4500]
  remote 'alice-phone' @ 198.51.100.20[40001] EAP: 'alice' [10.30.0.1]
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
  established 125s ago, rekeying in 13300s
  net: #3, reqid 1, INSTALLED, TUNNEL-in-UDP, ESP:AES_CBC-256/HMAC_SHA2_256_128
    installed 125s ago, rekeying in 3200s, expires in 3475s
    in  c0a1b2c3,   1536 bytes,    12 packets,     3s ago
    out c3b2a1c0,   2048 bytes,    10 packets,     3s ago
    local  0.0.0.0/0
    remote 10.30.0.1/32
rw: #4, ESTABLISHED, IKEv2, aaaaaaaaaaaaaaaa_i bbbbbbbbbbbbbbbb_r*
  local  '203.0.113.7' @ 10.0.0.5[4500]
  remote 'bob' @ 192.0.2.99[500] EAP: 'bob' [10.30.0.2]
  established 4000000s ago, rekeying in 1s
  net: #4, reqid 2, INSTALLED, TUNNEL, ESP:AES_GCM_16-256
    in  d0d0d0d0, 1073741824 bytes, 5 packets, 1s ago
    out e0e0e0e0, 2147483648 bytes, 5 packets, 1s ago
rw: #5, CONNECTING, IKEv2, cccccccccccccccc_i dddddddddddddddd_r*
  remote 'carol' @ 192.0.2.1[500] EAP: 'carol'
"""


def make_tar(members, mode="w:gz"):
    """members: list of (name, kwargs) -> path of a temp archive. kwargs: type, data, mode, linkname"""
    fd, path = tempfile.mkstemp(suffix=".tar.gz")
    os.close(fd)
    with tarfile.open(path, mode) as tf:
        for name, kw in members:
            ti = tarfile.TarInfo(name)
            ti.type = kw.get("type", tarfile.REGTYPE)
            ti.mode = kw.get("mode", 0o600)
            ti.linkname = kw.get("linkname", "")
            data = kw.get("data", b"x") if ti.type == tarfile.REGTYPE else b""
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data) if ti.type == tarfile.REGTYPE else None)
    return path


class ParseSas(unittest.TestCase):
    def test_only_established_sessions(self):
        sas = L.parse_sas(SAS)
        self.assertEqual([s["user"] for s in sas], ["alice", "bob"])

    def test_fields(self):
        a = L.parse_sas(SAS)[0]
        self.assertEqual((a["ip"], a["vip"], a["id"], a["secs"]), ("198.51.100.20", "10.30.0.1", 3, 125))
        self.assertEqual((a["rx"], a["tx"]), (1536, 2048))

    def test_empty_and_garbage(self):
        self.assertEqual(L.parse_sas(""), [])
        self.assertEqual(L.parse_sas("nonsense\n  remote 'x' @ y[1]\n"), [])

    def test_formatting(self):
        self.assertEqual(L.fmt_bytes(0), "0 B")
        self.assertEqual(L.fmt_bytes(1536), "1.5 KB")
        self.assertEqual(L.fmt_bytes(1073741824), "1.0 GB")
        self.assertEqual(L.fmt_dur(59), "59s")
        self.assertEqual(L.fmt_dur(125), "2m")
        self.assertEqual(L.fmt_dur(3700), "1h 1m")
        self.assertEqual(L.fmt_dur(4000000), "46d 7h")


class ZedLink(unittest.TestCase):
    def decode(self, link):
        self.assertTrue(link.startswith("zedsecure://"))
        b = link.split("://", 1)[1]
        self.assertNotIn("=", b)
        self.assertTrue(all(c not in b for c in "+/"), "must be valid as standard AND url-safe base64")
        return json.loads(base64.b64decode(b + "=" * (-len(b) % 4)))

    def test_roundtrip(self):
        for pw in ("Str0ng-Passw0rd.x1", "", "a" * 64, "p@ss+w/rd=~^*!%,."):
            d = self.decode(L.zedsecure_link("VPN x (u)", "203.0.113.7", "alice", pw, "-----BEGIN CERTIFICATE-----\nAB\n-----END CERTIFICATE-----"))
            s = d["s"]["settings"]
            self.assertEqual((s["server"], s["username"], s["password"]), ("203.0.113.7", "alice", pw))
            self.assertEqual(d["s"]["kind"], "ikev2")

    def test_cli_reads_password_from_environment_only(self):
        env = dict(os.environ, IKEV2_ZED_PASS="Env-Passw0rd.123")
        out = subprocess.run([sys.executable, os.path.join(ROOT, "ikev2lib.py"), "zedsecure", "n", "srv", "alice"],
                             capture_output=True, text=True, env=env).stdout.strip()
        self.assertEqual(self.decode(out)["s"]["settings"]["password"], "Env-Passw0rd.123")
        env.pop("IKEV2_ZED_PASS")
        out = subprocess.run([sys.executable, os.path.join(ROOT, "ikev2lib.py"), "zedsecure", "n", "srv", "alice"],
                             capture_output=True, text=True, env=env).stdout.strip()
        self.assertEqual(self.decode(out)["s"]["settings"]["password"], "")

    def test_cli_ca_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write("-----BEGIN CERTIFICATE-----\nZZ\n-----END CERTIFICATE-----\n")
        out = subprocess.run([sys.executable, os.path.join(ROOT, "ikev2lib.py"), "zedsecure", "n", "srv", "alice", f.name],
                             capture_output=True, text=True).stdout.strip()
        self.assertIn("BEGIN CERTIFICATE", self.decode(out)["s"]["settings"]["caCertPem"])


class CheckBackup(unittest.TestCase):
    def problems(self, members):
        p = make_tar(members)
        self.addCleanup(os.unlink, p)
        return L.check_backup(p)

    def test_good_archive(self):
        good = [("etc/ikev2/users.db", {}), ("etc/ikev2/pki", {"type": tarfile.DIRTYPE, "mode": 0o700}),
                ("etc/swanctl/private/server.key", {}), ("./etc/swanctl/swanctl.conf", {}),
                ("etc/letsencrypt/archive/d/cert1.pem", {}),
                ("etc/letsencrypt/live/d/cert.pem", {"type": tarfile.SYMTYPE, "linkname": "../../archive/d/cert1.pem"})]
        self.assertEqual(self.problems(good), [])

    def test_rejects(self):
        cases = {
            "absolute path": [("/etc/cron.d/evil", {})],
            "traversal": [("etc/ikev2/../../root/.ssh/authorized_keys", {})],
            "traversal2": [("etc/../etc/passwd", {})],
            "outside roots": [("etc/passwd", {})],
            "outside roots 2": [("usr/local/bin/vpn", {})],
            "bare etc dir": [("etc", {"type": tarfile.DIRTYPE, "mode": 0o777})],
            "prefix trick": [("etc/ikev2-evil/x", {})],
            "symlink escape": [("etc/ikev2/x", {"type": tarfile.SYMTYPE, "linkname": "../../root"})],
            "symlink to /": [("etc/ikev2/x", {"type": tarfile.SYMTYPE, "linkname": "/"})],
            "symlink dotdot to etc": [("etc/ikev2/x", {"type": tarfile.SYMTYPE, "linkname": "../letsencrypt/.."})],
            "hard link": [("etc/ikev2/h", {"type": tarfile.LNKTYPE, "linkname": "etc/passwd"})],
            "device": [("etc/ikev2/dev", {"type": tarfile.CHRTYPE})],
            "fifo": [("etc/ikev2/ff", {"type": tarfile.FIFOTYPE})],
            "setuid": [("etc/ikev2/su", {"mode": 0o4755})],
            "setgid": [("etc/ikev2/sg", {"mode": 0o2755})],
            "world writable": [("etc/swanctl/ww", {"mode": 0o666})],
            "mixed good+bad": [("etc/ikev2/ok", {}), ("etc/shadow", {})],
        }
        for label, members in cases.items():
            with self.subTest(label):
                self.assertTrue(self.problems(members), f"{label} should be rejected")

    def test_not_an_archive_or_empty(self):
        fd, p = tempfile.mkstemp()
        os.write(fd, b"not a tarball")
        os.close(fd)
        self.addCleanup(os.unlink, p)
        self.assertTrue(L.check_backup(p))
        self.assertTrue(self.problems([]))

    def test_cli_exit_codes(self):
        good = make_tar([("etc/ikev2/users.db", {})])
        bad = make_tar([("etc/passwd", {})])
        for p in (good, bad):
            self.addCleanup(os.unlink, p)
        run = lambda p: subprocess.run([sys.executable, os.path.join(ROOT, "ikev2lib.py"), "check-backup", p], capture_output=True, text=True)
        self.assertEqual(run(good).returncode, 0)
        r = run(bad)
        self.assertEqual(r.returncode, 1)
        self.assertIn("outside the allowed folders", r.stderr)


class KickAndOnline(unittest.TestCase):
    def test_kick_terminates_only_that_user(self):
        d = tempfile.mkdtemp()
        sas = os.path.join(d, "sas.txt")
        with open(sas, "w") as f:
            f.write(SAS)
        stub = os.path.join(d, "stubs")          # copy the stubs and make them executable (exec bits may be lost in a checkout)
        shutil.copytree(os.path.join(ROOT, "tests", "stubs"), stub, symlinks=False, ignore_dangling_symlinks=True)
        for name in os.listdir(stub):
            os.chmod(os.path.join(stub, name), 0o755)
        env = dict(os.environ, PATH=stub + os.pathsep + os.environ["PATH"], STUB_STATE=d, STUB_SAS_FILE=sas)
        out = subprocess.run([sys.executable, os.path.join(ROOT, "ikev2lib.py"), "kick", "alice"], capture_output=True, text=True, env=env).stdout.strip()
        self.assertEqual(out, "1")
        with open(os.path.join(d, "calls.log")) as f:
            calls = f.read()
        self.assertIn("swanctl --terminate --ike-id 3", calls)
        self.assertNotIn("--ike-id 4", calls)
        cnt = subprocess.run([sys.executable, os.path.join(ROOT, "ikev2lib.py"), "count"], capture_output=True, text=True, env=env).stdout.strip()
        self.assertEqual(cnt, "2")


if __name__ == "__main__":
    unittest.main(verbosity=1)
