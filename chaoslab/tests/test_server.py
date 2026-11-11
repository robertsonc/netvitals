"""The HTTP surface: dashboard API guards, install scripts, downloads, and the agent channel.
The last test runs two real agent processes against a real controller when an agent build exists."""
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from chaoslab.drivers.sim import SimLab
from chaoslab.engine import Engine
from chaoslab.fleet import Fleet
from chaoslab.server import App, serve
from chaoslab.store import Store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT = os.path.join(ROOT, "dist", "chaos-agent-linux-amd64")


def call(url, body=None, headers=None, method=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method or ("POST" if data is not None else "GET"),
                                 headers=dict({"Content-Type": "application/json"}, **(headers or {})))
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            kind = resp.headers.get_content_type()
            return resp.status, (json.loads(raw) if kind == "application/json" else
                                 raw if kind == "application/octet-stream" else raw.decode())
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, raw.decode()


UI = {"X-Chaoslab": "1"}


class ServerTest(unittest.TestCase):
    def start(self, demo=False, password="", dist=None):
        self.store = Store(tempfile.mkdtemp())
        self.fleet = Fleet(self.store)
        self.engine = Engine(self.store, self.fleet)
        if demo:
            self.engine.set_driver("sim", SimLab(seed=5))
        self.app = App(self.store, self.fleet, self.engine, dist=dist or tempfile.mkdtemp(), demo=demo, port=0,
                       password=password)
        self.server = serve(self.app, "127.0.0.1", 0)
        self.addCleanup(self.server.shutdown)
        self.app.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.app.port}"

    def test_state_and_static(self):
        self.start()
        status, state = call(self.url + "/api/state")
        self.assertEqual(status, 200)
        self.assertEqual((state["status"], state["agents"], state["demo"]), ("idle", [], False))
        self.assertEqual(call(self.url + "/")[0], 200)
        self.assertEqual(call(self.url + "/app.js")[0], 200)
        self.assertEqual(call(self.url + "/../chaoslab/store.py")[0], 404)
        self.assertEqual(call(self.url + "/%2e%2e/store.py")[0], 404)

    def test_state_changes_need_the_custom_header(self):
        self.start(demo=True)
        self.assertEqual(call(self.url + "/api/discover", {})[0], 403)        # what a cross-site form post looks like
        self.assertEqual(call(self.url + "/api/discover", {}, UI)[0], 200)

    def test_live_runs_need_an_acknowledgement(self):
        self.start()
        self.engine.set_driver("sim", SimLab(seed=5))          # a connected driver, but not demo mode
        status, out = call(self.url + "/api/run", {"cycles": 1}, UI)
        self.assertEqual(status, 400)
        self.assertIn("authorised", out["error"])
        self.assertTrue(self.engine.idle())

    def test_password(self):
        self.start(password="s3cret")
        self.assertEqual(call(self.url + "/api/state")[0], 401)
        self.assertEqual(call(self.url + "/api/login", {"password": "nope"}, UI)[0], 401)
        req = urllib.request.Request(self.url + "/api/login", data=json.dumps({"password": "s3cret"}).encode(),
                                     headers=dict(UI, **{"Content-Type": "application/json"}))
        with urllib.request.urlopen(req, timeout=10) as resp:
            cookie = resp.headers["Set-Cookie"].split(";")[0]
        self.assertEqual(call(self.url + "/api/state", headers={"Cookie": cookie})[0], 200)
        # Agents and installers never need the dashboard password.
        self.assertEqual(call(self.url + "/api/agent/hello", {"token": self.fleet.join_token})[0], 200)

    def test_install_scripts_carry_address_and_token(self):
        self.start()
        token = self.fleet.join_token
        status, script = call(f"{self.url}/install.sh?token={token}")
        self.assertEqual(status, 200)
        self.assertIn(f"CONTROLLER='{self.url}'", script)
        self.assertIn(f"TOKEN='{token}'", script)
        status, script = call(f"{self.url}/install.ps1?token={token}")
        self.assertIn(f"$Controller = '{self.url}'", script)
        status, script = call(f"{self.url}/install.sh?token=wrong")
        self.assertEqual(status, 403)
        self.assertIn("does not recognise", script)
        # A hostile Host header must not reach the generated shell script.
        status, script = call(f"{self.url}/install.sh?token={token}", headers={"Host": "x';rm -rf /;'"})
        self.assertNotIn("rm -rf", script)

    @unittest.skipUnless(shutil.which("sh"), "no POSIX shell")
    def test_install_scripts_parse(self):
        self.start()
        for name in ("install.sh", "uninstall.sh"):
            _, script = call(f"{self.url}/{name}?token={self.fleet.join_token}")
            done = subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True, timeout=10)
            self.assertEqual(done.returncode, 0, done.stderr)

    def test_missing_agent_build_explains_itself(self):
        self.start()
        status, out = call(self.url + "/dl/chaos-agent-linux-amd64")
        self.assertEqual(status, 404)
        self.assertIn("build-agents", out["error"])
        self.assertEqual(call(self.url + "/dl/../../etc/passwd")[0], 404)

    def test_agent_channel(self):
        self.start()
        self.assertEqual(call(self.url + "/api/agent/enroll", {"token": "bad", "instance": "abcdefgh"})[0], 403)
        ids = []
        for name in ("a", "b"):
            status, out = call(self.url + "/api/agent/enroll", {"token": self.fleet.join_token, "name": name,
                                                                 "instance": f"instance-{name}", "addrs": [f"10.9.0.{len(ids) + 1}"]})
            self.assertEqual(status, 200)
            ids.append(out)
        self.assertEqual(call(self.url + "/api/agent/sync", {}, {"X-Agent-Id": ids[0]["agent_id"], "X-Agent-Key": "x"})[0], 401)
        self.fleet.create_flow({"name": "f", "topology": "ptp", "proto": "udp", "src": ids[0]["agent_id"],
                                "dsts": [ids[1]["agent_id"]]})
        auth = {"X-Agent-Id": ids[0]["agent_id"], "X-Agent-Key": ids[0]["key"]}
        status, out = call(self.url + "/api/agent/sync", {"cfg_rev": 0, "t_send": 1}, auth)
        self.assertEqual(status, 200)
        self.assertEqual(out["cfg"]["send"][0]["dst"], "10.9.0.2")
        self.assertGreater(out["t_reply"], out["t_recv"] - 1)
        status, out = call(self.url + "/api/agent/sync", {"cfg_rev": out["cfg_rev"]}, auth)
        self.assertNotIn("cfg", out)                                # unchanged configuration is not resent

    @unittest.skipUnless(os.path.isfile(AGENT) and sys.platform == "linux" and platform.machine() == "x86_64",
                         "no agent build for this machine (python3 -m chaoslab build-agents)")
    def test_real_agents_end_to_end(self):
        self.start(dist=os.path.join(ROOT, "dist"))
        self.assertEqual(call(self.url + "/dl/chaos-agent-linux-amd64")[0], 200)
        work = tempfile.mkdtemp()
        procs = []
        try:
            for name in ("alpha", "bravo"):
                procs.append(subprocess.Popen(
                    [AGENT, "run", "--controller", self.url, "--token", self.fleet.join_token, "--name", name,
                     "--state", os.path.join(work, name + ".json")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            deadline = time.time() + 15
            while len(self.fleet.agents()) < 2 and time.time() < deadline:
                time.sleep(0.2)
            agents = {a["name"]: a for a in self.fleet.agents()}
            self.assertEqual(sorted(agents), ["alpha", "bravo"])
            for a in agents.values():      # both processes share this host: make them talk over loopback
                self.fleet.update_agent(a["id"], {"testAddr": "127.0.0.1"})
            self.fleet.create_flow({"name": "udp", "topology": "ptp", "proto": "udp", "src": agents["alpha"]["id"],
                                    "dsts": [agents["bravo"]["id"]], "port": 39211, "pps": 100, "size": 200})
            self.fleet.create_flow({"name": "tcp", "topology": "ptp", "proto": "tcp", "src": agents["bravo"]["id"],
                                    "dsts": [agents["alpha"]["id"]], "port": 39212, "pps": 50, "size": 512})
            deadline = time.time() + 25
            done = {}
            while time.time() < deadline:
                done = {k: v for k, v in self.fleet.window(0, 10 ** 14).items()
                        if v["seconds"] >= 3 and v["fwdLoss"] is not None}
                if len(done) == 2:
                    break
                time.sleep(0.5)
            self.assertEqual(len(done), 2, "both legs should have reported from both ends")
            for stats in done.values():
                self.assertEqual((stats["loss"], stats["fwdLoss"], stats["revLoss"]), (0.0, 0.0, 0.0))
                self.assertLess(stats["rtt"], 5.0)                    # loopback
                self.assertGreater(stats["sent"], 100)
            status, state = call(self.url + "/api/state")
            self.assertTrue(all(a["online"] and a["kernelTs"] for a in state["agents"]))
            self.assertEqual({l["stale"] for l in state["legs"].values()}, {False})
        finally:
            for p in procs:
                p.terminate()
            for p in procs:
                p.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
