import base64
import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import cpn


class CpnTests(unittest.TestCase):
    def test_https_only(self):
        with self.assertRaises(cpn.CpnError): cpn._safe_url("http://example.com/sub")
        with self.assertRaises(cpn.CpnError): cpn._safe_url("https://user:pass@example.com/sub")
        self.assertEqual(cpn._safe_url("https://example.com/sub"), "https://example.com/sub")

    def test_json_profiles(self):
        result = cpn.parse_profiles(b'{"profiles":[{"name":"Office","url":"vless://abc"}]}', "https://example.com")
        self.assertEqual(result[0]["name"], "Office")
        self.assertEqual(result[0]["source"], "vless://abc")

    def test_base64_lines(self):
        raw = "ss://abc#Home\nvless://xyz#Work"
        payload = base64.b64encode(raw.encode()).replace(b"=", b"")
        result = cpn.parse_profiles(payload, "https://example.com")
        self.assertEqual(len(result), 2)

    def test_invalid_format(self):
        with self.assertRaises(cpn.CpnError): cpn.parse_profiles(b"not a profile", "https://example.com")

    def test_state_atomic_roundtrip(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(cpn, "CONFIG_DIR", root / "config"), patch.object(cpn, "STATE_FILE", root / "config" / "state.json"):
                state = {"subscriptions": [{"url": "https://example.com"}], "profiles": [], "active_profile": None}
                cpn.save_state(state)
                self.assertEqual(cpn.load_state(), state)

    def test_cli_help(self):
        proc = subprocess.run([sys.executable, "cpn.py", "--help"], cwd=Path(__file__).parent, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("add-subscription", proc.stdout)

    def test_ssh_detection_and_read_only_contract(self):
        with patch.dict(cpn.os.environ, {"SSH_CONNECTION": "1.2.3.4 22 5.6.7.8 22"}, clear=True):
            self.assertTrue(cpn.ssh_session())
        self.assertFalse(cpn.safety_status()["network_mutations"])
        self.assertEqual(cpn.safety_status()["vpn_activation"], "explicit --activate only")
        self.assertEqual(cpn.safety_status()["route_changes"], "SSH route pinned")

    def test_safety_command(self):
        proc = subprocess.run([sys.executable, "cpn.py", "safety"], cwd=Path(__file__).parent, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("только через явный --activate", proc.stdout)

    def test_singbox_vless_config_is_tun_full_tunnel(self):
        profile = {"source": "vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls&sni=example.com"}
        config = cpn._singbox_config(profile)
        self.assertEqual(config["inbounds"][0]["type"], "tun")
        self.assertTrue(config["inbounds"][0]["auto_route"])
        self.assertEqual(config["route"]["final"], "proxy")
        self.assertEqual(config["dns"]["servers"][0]["type"], "https")
        self.assertEqual(config["dns"]["servers"][0]["server"], "1.1.1.1")
        self.assertEqual(config["inbounds"][0]["strict_route"], True)

    def test_ipv6_ssh_route_uses_128_prefix(self):
        with patch.dict(cpn.os.environ, {"SSH_CONNECTION": "2001:db8::25 22 2001:db8::1 22"}, clear=True), patch.object(cpn, "_run") as run:
            run.side_effect = [type("R", (), {"stdout": ""})(), type("R", (), {"stdout": "2001:db8::25 via 2001:db8::1 dev eth0 src 2001:db8::2"})()]
            route = cpn._ssh_route()
        self.assertEqual(route["prefix"], "2001:db8::25/128")

    def test_xray_json_profile_conversion(self):
        xray = {"outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "edge.example", "port": 443, "users": [{"id": "00000000-0000-0000-0000-000000000000", "encryption": "none"}]}]}, "streamSettings": {"network": "ws", "security": "tls", "tlsSettings": {"serverName": "edge.example"}, "wsSettings": {"path": "/api"}}}]}
        profiles = cpn.parse_profiles(json.dumps([xray]).encode(), "https://example.com")
        self.assertEqual(profiles[0]["kind"], "xray-json")
        outbound = cpn._singbox_config(profiles[0])["outbounds"][0]
        self.assertEqual(outbound["type"], "vless")
        self.assertEqual(outbound["transport"]["type"], "ws")
        self.assertEqual(outbound["tls"]["server_name"], "edge.example")

    def test_reality_enables_utls(self):
        xray = {"outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "edge.example", "port": 443, "users": [{"id": "00000000-0000-0000-0000-000000000000"}]}]}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"publicKey": "key", "shortId": "id", "serverName": "cdn.example"}}}]}
        profile = cpn.parse_profiles(json.dumps([xray]).encode(), "https://example.com")[0]
        tls = cpn._singbox_config(profile)["outbounds"][0]["tls"]
        self.assertEqual(tls["utls"], {"enabled": True, "fingerprint": "chrome"})
        self.assertEqual(tls["server_name"], "cdn.example")


if __name__ == "__main__":
    unittest.main(verbosity=2)
