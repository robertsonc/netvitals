"""Smoke tests for the HPE Demo Instrument web UI bridge."""
import json
import os
import sys
import threading
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netquality as nq  # noqa: E402
import nv_webui  # noqa: E402


class TestUiAssets(unittest.TestCase):
    def test_ui_files_present(self):
        root = nv_webui._ui_root()
        for rel in ("dashboard.html", "launcher.html", "css/tokens.css",
                    "css/app.css", "js/charts.js", "js/dashboard.js",
                    "js/launcher.js"):
            self.assertTrue(os.path.isfile(os.path.join(root, rel)), rel)

    def test_tokens_are_hpe_green(self):
        path = os.path.join(nv_webui._ui_root(), "css/tokens.css")
        with open(path, encoding="utf-8") as fh:
            css = fh.read()
        self.assertIn("#01a982", css.lower())
        self.assertNotIn("#8B7CFF", css)  # no violet accent in new world


class TestDashboardPayload(unittest.TestCase):
    def test_snapshot_payload_shape(self):
        args = nq.parse_args(["--peer", "127.0.0.1", "--no-gui"])
        engine = nq.Engine("127.0.0.1", size=200, pps=10, history_seconds=30)
        try:
            payload = nv_webui.build_dashboard_payload(nq, engine, args)
            self.assertIn("snap", payload)
            self.assertIn("history", payload)
            self.assertIn("series", payload)
            self.assertEqual(payload["snap"]["peer"], "127.0.0.1")
            self.assertEqual(payload["snap"]["stream_count"], len(nq.STREAMS))
            # JSON round-trip
            raw = json.dumps(payload)
            again = json.loads(raw)
            self.assertEqual(again["version"], nq.__version__)
        finally:
            engine.shutdown()


class TestHttpSmoke(unittest.TestCase):
    def test_launcher_bootstrap_route(self):
        ctx = nv_webui._UiContext("launcher", nq, launcher_result={"argv": None},
                                  update_url=nq.UPDATE_URL,
                                  args=type("A", (), {"_argv": []})())
        handler = nv_webui.make_handler(ctx)
        port = nv_webui._pick_port()
        httpd = nv_webui.ThreadingHTTPServer(("127.0.0.1", port), handler)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/api/launcher/bootstrap",
                    timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["version"], nq.__version__)
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/", timeout=3) as resp:
                html = resp.read().decode("utf-8")
            self.assertIn("Network Vitals", html)
            self.assertIn("HPE Demo Instrument", html)
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/css/tokens.css",
                    timeout=3) as resp:
                css = resp.read().decode("utf-8")
            self.assertIn("--accent: #01a982", css.lower().replace(" ", "")
                          if False else css)
            self.assertIn("#01a982", css.lower())
        finally:
            httpd.shutdown()
            httpd.server_close()


class TestMeshPayload(unittest.TestCase):
    def test_mesh_payload_lists_peers(self):
        args = nq.parse_args(["--peers", "127.0.0.1,127.0.0.2", "--no-gui"])
        engine = nq.Engine(peers=["127.0.0.1", "127.0.0.2"], size=200, pps=5,
                           history_seconds=30)
        try:
            payload = nv_webui.build_mesh_payload(nq, engine, args, "127.0.0.1")
            self.assertEqual(payload["mesh"]["peers"],
                             ["127.0.0.1", "127.0.0.2"])
            self.assertEqual(len(payload["mesh"]["rows"]), 2)
            self.assertEqual(payload["snap"]["peer"], "127.0.0.1")
        finally:
            engine.shutdown()


class TestEmbeddedZip(unittest.TestCase):
    def test_embedded_zip_round_trips(self):
        self.assertGreater(len(nq._NV_WEBUI_ZIP_B64), 1000)
        import base64
        import io
        import zipfile
        data = base64.b64decode(nq._NV_WEBUI_ZIP_B64)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
        self.assertIn("nv_webui.py", names)
        self.assertIn("ui/dashboard.html", names)
        self.assertIn("ui/launcher.html", names)


if __name__ == "__main__":
    unittest.main()
