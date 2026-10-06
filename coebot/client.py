"""Minimal SFS2X game client: handshake -> login -> commands -> heartbeat.

Credentials come from a JSON file (never commit it), see config.example.json.
"""
import json
import socket
import threading
import time

from . import sfs
from .sfs import Typed


class Client:
    def __init__(self, cfg, cnmm, host=None, port=None, log=print):
        self.cfg, self.cnmm, self.log = cfg, cnmm, log
        self.addr = (host or cfg["host"], port or cfg["port"])
        self.sock = None
        self.parser = sfs.PacketParser()
        self.pending = []
        self.lock = threading.Lock()

    # -- transport --
    def connect(self):
        self.sock = socket.create_connection(self.addr, timeout=15)

    def send(self, obj):
        self.sock.sendall(sfs.frame(obj))

    def recv(self, timeout=15):
        self.sock.settimeout(timeout)
        while not self.pending:
            data = self.sock.recv(65536)
            if not data:
                raise ConnectionError("server closed")
            self.pending.extend(self.parser.feed(data))
        return self.pending.pop(0)

    # -- session --
    def handshake(self):
        self.send({"c": Typed(sfs.BYTE, 0), "a": Typed(sfs.SHORT, 0),
                   "p": {"api": "1.7.5", "cl": "Unity"}})
        return self.recv()  # contains tk

    def login(self):
        acc = self.cfg["account"]
        self.send({"c": Typed(sfs.BYTE, 0), "a": Typed(sfs.SHORT, 1), "p": {
            "zn": acc.get("zone", "COE1"), "un": acc["gameUid"], "pw": acc["pw"],
            "p": acc["login_params"]}})
        while True:
            pkt = self.recv(30)
            p = pkt.get("p", {})
            if pkt.get("a") == 1:
                if p.get("rs", 0) != 0:
                    raise RuntimeError(f"login failed: {p}")
                return p

    def command(self, name, params=None, wait=True):
        params = dict(params or {})
        params["cnmm"] = self.cnmm(name, params)
        self.send({"c": Typed(sfs.BYTE, 1), "a": Typed(sfs.SHORT, 13),
                   "p": {"c": name, "p": params}})
        if not wait:
            return None
        while True:
            pkt = self.recv(30)
            p = pkt.get("p", {})
            if p.get("c") == name:
                return p.get("p", p)

    def heart_beat(self):
        return self.command("heart_beat", {
            "bClickScreen": True, "ct": Typed(sfs.LONG, int(time.time() * 1000))},
            wait=False)

    def run(self, on_ready):
        self.connect()
        self.handshake()
        self.login()
        stop = threading.Event()

        def hb():
            while not stop.wait(7):
                with self.lock:
                    self.heart_beat()
        threading.Thread(target=hb, daemon=True).start()
        try:
            on_ready(self)
        finally:
            stop.set()
            self.sock.close()


def load_config(path):
    with open(path) as f:
        return json.load(f)
