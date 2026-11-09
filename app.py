#!/usr/bin/env python3
"""
Network Security Scanner & Firewall Visualizer  -  app.py
==========================================================
Flask backend for Network Security Assignment.
"""

import ipaddress
import itertools
import os
import socket
import threading

import nmap
from flask import Flask, jsonify, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)

MAX_PORTS_PER_SCAN = 2048
ALLOW_PUBLIC_TARGETS = os.environ.get("ALLOW_PUBLIC_TARGETS") == "1"


def parse_port_list(spec):
    ports = set()
    if not spec:
        return [80, 8081, 8082, 8083, 8084]
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                sub = part.split("-", 1)
                lo, hi = int(sub[0]), int(sub[1])
            else:
                lo = hi = int(part)
            if 1 <= lo <= hi <= 65535:
                # Limit large ranges to prevent hanging, or cap per scan
                ports.update(range(lo, min(hi, lo + 200) + 1))
        except Exception:
            continue
    if not ports:
        return [80, 8081, 8082, 8083, 8084]
    return sorted(list(ports))


def service_name(port, proto):
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


class Rule:
    def __init__(self, rid, priority, action, ip, port, protocol):
        self.id = rid
        self.action = str(action).upper()
        if self.action not in ("ALLOW", "DENY"):
            raise ValueError("Action must be ALLOW or DENY.")
        self.priority = int(priority)
        self.protocol = str(protocol).lower()
        ip = str(ip).strip().lower()
        if ip in ("", "any", "*"):
            self.ip, self.net = "any", None
        else:
            self.net = ipaddress.ip_network(ip, strict=False)
            self.ip = ip
        
        try:
            port_str = str(port).strip().lower()
            if port_str in ("", "any", "*"):
                self.lo, self.hi = 1, 65535
            elif "-" in port_str:
                p_parts = port_str.split("-", 1)
                self.lo, self.hi = int(p_parts[0]), int(p_parts[1])
            else:
                self.lo = self.hi = int(port_str)
        except Exception:
            self.lo, self.hi = 1, 65535

        self.port = "any" if (self.lo, self.hi) == (1, 65535) else (
            str(self.lo) if self.lo == self.hi else f"{self.lo}-{self.hi}")

    def matches(self, ip, port, proto):
        if self.net is not None and ipaddress.ip_address(ip) not in self.net:
            return False
        if self.protocol != "any" and self.protocol != proto:
            return False
        return self.lo <= port <= self.hi

    def to_dict(self):
        return {"id": self.id, "priority": self.priority, "action": self.action,
                "ip": self.ip, "port": self.port, "protocol": self.protocol}


class Firewall:
    def __init__(self):
        self._lock = threading.RLock()
        self._rules = []
        self._ids = itertools.count(1)
        self.default_policy = "ALLOW"

    def add(self, **kw):
        with self._lock:
            rule = Rule(next(self._ids), **kw)
            self._rules.append(rule)
            return rule

    def delete(self, rid):
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.id != rid]
            return len(self._rules) < before

    def clear(self):
        with self._lock:
            self._rules = []

    def ordered(self):
        with self._lock:
            return sorted(self._rules, key=lambda r: (r.priority, r.id))

    def evaluate(self, ip, port, proto):
        for rule in self.ordered():
            if rule.matches(ip, port, proto):
                return {"action": rule.action, "rule_id": rule.id,
                        "reason": f"Rule #{rule.id} (priority {rule.priority})"}
        return {"action": self.default_policy, "rule_id": None,
                "reason": f"Default policy ({self.default_policy})"}


firewall = Firewall()

LAB_IP = "127.0.0.1"


class LabService:
    def __init__(self, port, proto):
        self.port, self.proto = port, proto
        self.sock, self.thread, self.error = None, None, None
        self.stop_evt = threading.Event()

    @property
    def listening(self):
        return self.sock is not None

    def start(self):
        if self.listening:
            return
        kind = socket.SOCK_STREAM if self.proto == "tcp" else socket.SOCK_DGRAM
        try:
            s = socket.socket(socket.AF_INET, kind)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((LAB_IP, self.port))
            if self.proto == "tcp":
                s.listen(16)
            s.settimeout(0.5)
        except OSError as exc:
            self.error = str(exc)
            return
        self.error, self.sock = None, s
        self.stop_evt = threading.Event()
        self.thread = threading.Thread(target=self._serve, args=(s, self.stop_evt), daemon=True)
        self.thread.start()

    def stop(self):
        if not self.listening:
            return
        self.stop_evt.set()
        try:
            self.sock.close()
        finally:
            self.sock = None

    def _serve(self, sock, stop_evt):
        banner = f"LAB-SERVICE {self.proto}/{self.port}\r\n".encode()
        while not stop_evt.is_set():
            try:
                if self.proto == "tcp":
                    conn, _ = sock.accept()
                    conn.sendall(banner)
                    conn.close()
                else:
                    _, addr = sock.recvfrom(1024)
                    sock.sendto(banner, addr)
            except socket.timeout:
                continue
            except OSError:
                break


LAB = [LabService(p, "tcp") for p in (8081, 8082, 8083, 8084)] + [LabService(9091, "udp")]


def sync_lab_services():
    for svc in LAB:
        verdict = firewall.evaluate(LAB_IP, svc.port, svc.proto)["action"]
        svc.start() if verdict == "ALLOW" else svc.stop()


def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve '{target}'.")
    return ip


def run_scan(target, scan_type, ports):
    ip = resolve_target(target)
    proto = "udp" if scan_type == "udp" else "tcp"
    allowed, blocked = [], []
    for p in ports:
        verdict = firewall.evaluate(ip, p, proto)
        (allowed if verdict["action"] == "ALLOW" else blocked).append((p, verdict))

    results = [{"ip": ip, "port": p, "protocol": proto, "service": service_name(p, proto),
                "status": "blocked", "rule": v["reason"]} for p, v in blocked]

    for p, v in allowed:
        status = "open"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.02)  # Ultra-fast timeout
            res = s.connect_ex((ip, p))
            s.close()
            status = "open" if res == 0 else "closed"
        except Exception:
            status = "open"
        
        if status != "closed":
            results.append({
                "ip": ip, "port": p, "protocol": proto,
                "service": service_name(p, proto), "status": status,
                "rule": v["reason"]
            })

    results.sort(key=lambda r: r["port"])
    return {
        "target": target, "ip": ip, "scan_type": scan_type, "protocol": proto,
        "results": results,
        "summary": {"requested": len(ports), "probed": len(allowed), "blocked": len(blocked),
                    "open": sum(r["status"] == "open" for r in results)},
    }


@app.route("/")
def index():
    html_path = os.path.join(BASE_DIR, "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/api/rules")
def list_rules():
    return jsonify(rules=[r.to_dict() for r in firewall.ordered()],
                   default_policy=firewall.default_policy)


@app.post("/api/rules")
def add_rule():
    b = request.get_json(silent=True) or {}
    rule = firewall.add(priority=b.get("priority"), action=b.get("action", ""),
                        ip=b.get("ip", "any"), port=b.get("port", "any"),
                        protocol=b.get("protocol", "any"))
    sync_lab_services()
    return jsonify(rule.to_dict()), 201


@app.delete("/api/rules/<int:rid>")
def delete_rule(rid):
    if not firewall.delete(rid):
        return jsonify(error="Rule not found."), 404
    sync_lab_services()
    return jsonify(ok=True)


@app.delete("/api/rules")
def clear_rules():
    firewall.clear()
    sync_lab_services()
    return jsonify(ok=True)


@app.post("/api/scan")
def scan():
    try:
        b = request.get_json(silent=True) or {}
        target = str(b.get("target", "127.0.0.1")).strip()
        ports = parse_port_list(b.get("ports", "8081-8084"))
        return jsonify(run_scan(target, str(b.get("scan_type", "connect")).lower(), ports))
    except Exception as exc:
        return jsonify(error=str(exc)), 400


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify(error="API endpoint not found"), 404
    return index()


if __name__ == "__main__":
    sync_lab_services()
    print("Dashboard: http://127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001, debug=False, threaded=True)