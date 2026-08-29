"""The public room list, end to end: does a room announced by one peer reach
another, does search reach past what you happen to hold, does it disappear."""
import os, socket, threading, time
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))
import talkshit as ts

KEYMAP = {}
_o = ts.OnionIdentity.__init__
def patched(self, key, label, slot, epoch=0):
    _o(self, key, label, slot, epoch); KEYMAP[self.control_key] = self.address
ts.OnionIdentity.__init__ = patched
REG, LOCK, PROBES = {}, threading.Lock(), []

class Tor:
    extended = True
    def __init__(self): self.mine = {}
    def connect(self, address, timeout=45.0, auth=None, on_socket=None):
        with LOCK:
            PROBES.append(address)
            port = REG.get(address)
        if port is None:
            time.sleep(0.4)
            raise ts.SocksError("onion descriptor not found", 0xF0)
        time.sleep(1.0)
        return socket.create_connection(("127.0.0.1", port), timeout=10)
    def publish(self, key, port):
        a = KEYMAP[key]
        with LOCK: REG[a] = port
        self.mine[a] = port
        return a
    def unpublish(self, a):
        with LOCK: REG.pop(a, None)
        self.mine.pop(a, None)

def wait(cond, limit=90):
    t0 = time.time()
    while time.time() - t0 < limit:
        if cond(): return time.time() - t0
        time.sleep(0.2)
    return -1.0

ts.CLAIM_SETTLE = (0.5, 1.0)

print("=== one peer alone: how many doors does startup cost? ===")
PROBES.clear()
solo = ts.Index(Tor(), publish=True)
solo.start()
wait(lambda: not solo.mesh.probing, 120)
print(f"  doors probed before giving up : {len(PROBES)}   (16 is one sweep)")
print(f"  claimed an index door         : {solo.mesh.claimed is not None}")
solo.close(); time.sleep(0.5)

print("\n=== four peers, three rooms announced ===")
REG.clear()
peers = [ts.Index(Tor(), publish=True) for _ in range(4)]
for p in peers:
    p.start(); time.sleep(0.4)
wait(lambda: all(p.mesh.links for p in peers[1:]), 60)
print(f"  index links per peer : {[len(p.mesh.links) for p in peers]}")

counts = {"general": 4, "linux-chat": 12, "quiet-corner": 2}
for p, (name, n) in zip(peers, counts.items()):
    p.publish(name, (lambda n=n: n), f"fp-{name}")
seen = wait(lambda: len(peers[3].rooms()) >= 3, 90)
print(f"  a peer that announced nothing sees all three : "
      + (f"yes, {seen:.0f}s" if seen >= 0 else "NO"))
print(f"  what it sees : {peers[3].rooms()}")

print("\n=== search reaches past what a peer already holds ===")
lonely = ts.Index(Tor(), publish=True)
lonely.start()
wait(lambda: lonely.mesh.links, 60)
lonely.entries.clear()
lonely.find("linux")
found = wait(lambda: any("linux" in n for n, _ in lonely.rooms()), 60)
print(f"  asked the network for 'linux' : "
      + (f"found in {found:.0f}s" if found >= 0 else "NOT FOUND"))

print("\n=== a room disappears when its last person leaves ===")
peers[1].unpublish(last_one_out=True)
gone = wait(lambda: not any(n == "linux-chat" for n, _ in peers[3].rooms()), 60)
print(f"  dropped from another peer's list : "
      + (f"yes, {gone:.0f}s" if gone >= 0 else "NO - still listed"))

print("\n=== a stranger cannot evict real rooms by flooding ===")
before = {n for n, _ in peers[3].rooms()}
import base64
for i in range(200):
    peers[3]._on_object({"kind": "room", "room": f"junk{i}", "n": 1,
                         "fp": f"f{i}", "id": os.urandom(6).hex(),
                         "from": base64.b64encode(os.urandom(32)).decode()}, None)
after = {n for n, _ in peers[3].rooms()}
print(f"  real rooms still listed after 200 fakes : {before <= after}")
for p in peers + [lonely]: p.close()
