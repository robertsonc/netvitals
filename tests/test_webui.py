"""Smoke tests for the HPE Demo Instrument web UI bridge."""
import json
import os
import subprocess
import sys
import textwrap
import threading
import unittest
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
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


class TestDockTeardown(unittest.TestCase):
    """The Tk dock must never be reclaimed by a worker thread's GC.

    Regression test for the 3.0.0 crash: starting a session from the web
    launcher hands off launcher -> dashboard inside ONE process. The
    launcher dock's Tk root, destroyed at handoff, formed reference cycles
    (root/widgets/callbacks), so it was reclaimed by whichever thread next
    triggered the cyclic GC. Once traffic starts, that is an HTTP worker or
    probe/load thread - _tkinter then deletes the Tcl interpreter on the
    wrong thread and Tcl abort()s the whole process:
        Tcl_AsyncDelete: async handler deleted by the wrong thread
    A C-level abort cannot be asserted in-process, so the scenario runs in
    a subprocess: without the fix in nv_webui it dies with SIGABRT (rc 134
    / -6), with the fix it exits 0.
    """

    def test_dock_teardown_survives_worker_thread_gc(self):
        script = textwrap.dedent("""
            import sys, threading, time
            sys.path.insert(0, %r)
            import netquality as nq
            import nv_webui

            nv_webui._open_host = lambda url: None  # no browser tabs from CI

            # Headless boxes never build a dock, so the hazard cannot exist
            # there - report a skip instead of passing vacuously.
            _keep_probe = []  # keep the probe root out of the GC experiment
            try:
                import tkinter
                probe = tkinter.Tk()
                probe.destroy()
                _keep_probe.append(probe)
            except Exception:
                print("SKIP-NO-DISPLAY")
                raise SystemExit(0)

            ctx = nv_webui._UiContext(
                "launcher", nq, launcher_result={"argv": None},
                args=type("A", (), {"_argv": []})())
            # "Click Start" shortly after the dock is up.
            threading.Timer(1.0, ctx.shutdown.set).start()

            # Allocation churn on background threads, standing in for the
            # ThreadingHTTPServer handlers + probe/load threads of a running
            # session: makes the cyclic GC fire off the main thread.
            stop = threading.Event()
            def churn():
                while not stop.is_set():
                    _ = [{"k": i} for i in range(500)]
            for _ in range(4):
                threading.Thread(target=churn, daemon=True).start()

            nv_webui._run_server(ctx, title="dock teardown test")
            time.sleep(3.0)  # the post-handoff window where 3.0.0 aborted
            stop.set()
            print("OK")
        """ % (REPO,))
        proc = subprocess.run(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
            cwd=REPO, text=True)
        if "SKIP-NO-DISPLAY" in proc.stdout:
            self.skipTest("no display: Tk dock never built here")
        self.assertEqual(
            proc.returncode, 0,
            f"dock teardown crashed the process (rc={proc.returncode})\n"
            f"stderr:\n{proc.stderr}")
        self.assertIn("OK", proc.stdout)


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
