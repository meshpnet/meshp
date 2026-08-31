"""A canned control plane, so the page can be driven in a real browser.

    python3 web/testdata/fixture.py web && open http://localhost:8731/

Serves web/ and just enough of the API for app.js to render an overview, mint an enrolment
token and revoke a device. Nothing here is a control plane: every answer is made up, the
cookie is not checked, and it exists so that somebody changing app.js can watch the page do
what it does. The checks worth running are in docs/testing/the-page.md.

Two things make it useful rather than merely static. It polls once a second rather than
every five, and `POST /fixture` replaces the state the answers are built from — so a check
can make a device develop a fault, which sorts it to the top of the table, or rename one,
between two polls of a page somebody is looking at.

There is deliberately no test runner here. ADR-0022 §3 keeps Node out of this repository,
and running these checks is a person opening a browser.
"""
import json, os, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ROOT = os.path.abspath(sys.argv[1])
NET = "11111111-2222-3333-4444-555555555555"
NAMES = ["alpha", "bravo", "charlie", "delta"]
IDS = {n: "%s-0000-0000-0000-00000000000%d" % ("a" * 8, i) for i, n in enumerate(NAMES)}

state = {"fault": None, "rename": {}, "revoked": [], "tick": 0, "fail_mint": False, "slow_mint": 0}
lock = threading.Lock()


def device(name):
    mid = IDS[name]
    faults = []
    if state["fault"] == name:
        faults = [{"code": "unapplied", "message": "has not applied its configuration"}]
    return {
        "membership_id": mid,
        "device_name": state["rename"].get(name, name),
        "state": "revoked" if name in state["revoked"] else "active",
        "connected": True,
        "applied_version": 7,
        "reported_version": 7,
        "address_v4": "100.80.0.%d" % (NAMES.index(name) + 2),
        "tunnel": {"peers": 3, "talking": 3 - len(faults), "relayed": 0},
        "faults": faults,
    }


def overview():
    devices = [device(n) for n in NAMES]
    return {
        "as_of": "2026-08-31T12:00:0%dZ" % (state["tick"] % 10),
        "network": {"id": NET, "slug": "hq", "name": "hq", "state_version": 12},
        "devices": devices,
        "devices_truncated": False,
        "route_groups": [{
            "id": "99999999-0000-0000-0000-000000000001",
            "slug": "office", "name": "office", "kind": "subnet",
            "selection_mode": "priority", "prefixes": ["10.0.0.0/24"], "faults": [],
            "advertisers": [{
                "membership_id": IDS[n], "device_name": n, "priority": i, "weight": 1,
                "admin_state": "enabled", "health": "healthy", "connected": True,
                "viable": True, "in_use_by": 2 - i,
            } for i, n in enumerate(NAMES[:2])],
        }],
        "fault_count": sum(len(d["faults"]) for d in devices),
        "poll_after_seconds": 1,
    }


AUDIT = {"events": [
    {"id": "3", "at": "2026-08-31T11:00:00Z", "actor_kind": "user",
     "actor_label": "aswin", "action": "device.enrolled", "metadata": {}},
    {"id": "2", "at": "2026-08-31T10:00:00Z", "actor_kind": "device",
     "actor_label": "alpha", "action": "route.switched", "metadata": {"reason": "probe failed"}},
    {"id": "1", "at": "2026-08-31T09:00:00Z", "actor_kind": "user",
     "actor_label": "aswin", "action": "policy.published", "metadata": {}},
]}

NETWORKS = {"networks": [{"id": NET, "slug": "hq", "organization_slug": "acme",
                          "active_device_count": len(NAMES)}]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send_json(self, body, code=200):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = urlparse(self.path).path
        with lock:
            if path.endswith("/overview"):
                state["tick"] += 1
                return self.send_json(overview())
            if path.endswith("/audit"):
                return self.send_json(AUDIT)
            if path == "/api/v1/me/permissions":
                return self.send_json({"permissions": [], "unlimited": True})
            if path == "/api/v1/networks":
                return self.send_json(NETWORKS)
        name = "index.html" if path in ("/", "") else path.lstrip("/")
        try:
            with open(os.path.join(ROOT, name), "rb") as fh:
                raw = fh.read()
        except OSError:
            return self.send_json({"error": "not_found"}, 404)
        kind = {"js": "text/javascript", "css": "text/css"}.get(name.rsplit(".", 1)[-1], "text/html")
        self.send_response(200)
        self.send_header("content-type", kind + "; charset=utf-8")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("content-length") or 0))
        if self.path == "/fixture":
            with lock:
                state.update(json.loads(raw or b"{}"))
            return self.send_json(state)
        if self.path.endswith("/enrollment-tokens"):
            # So that a failing write can be watched without taking the page offline with it:
            # the poll keeps succeeding, which is the case the error has to survive.
            if state["fail_mint"]:
                return self.send_json({"error": "boom", "message": "the control plane said no"}, 500)
            # And so that a slow one can be watched: several polls land while the button is
            # still waiting, which is the case the button has to survive.
            time.sleep(state["slow_mint"])
            return self.send_json({"token": "mp_" + "k" * 40})
        self.send_json({"error": "not_found"}, 404)

    def do_DELETE(self):
        with lock:
            mid = self.path.rsplit("/", 1)[-1]
            for name, known in IDS.items():
                if known == mid:
                    state["revoked"].append(name)
        self.send_json({"ok": True})


ThreadingHTTPServer(("127.0.0.1", 8731), Handler).serve_forever()
