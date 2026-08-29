"""Exercise the three ways into a room, over a loopback stand-in for tor
where a live onion is slow to reach and an empty one answers quickly - which
is the shape that makes a joiner claim a door before it finds anybody."""
import collections, os, socket, threading, time
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))
import talkshit as ts

KEYMAP = {}
_o = ts.OnionIdentity.__init__
def patched(self, key, label, slot, epoch=0):
    _o(self, key, label, slot, epoch); KEYMAP[self.control_key] = self.address
ts.OnionIdentity.__init__ = patched

REG, LOCK = {}, threading.Lock()

class Tor:
    extended = True
    def __init__(self): self.mine = {}
    def connect(self, address, timeout=45.0, auth=None, on_socket=None):
        with LOCK:
            port = REG.get(address)
        if port is None:
            time.sleep(2)                     # a lookup that finds nothing
            raise ts.SocksError("onion descriptor not found", 0xF0)
        time.sleep(9)                         # a full rendezvous, much slower
        return socket.create_connection(("127.0.0.1", port), timeout=10)
    def publish(self, key, port):
        a = KEYMAP[key]
        with LOCK: REG[a] = port
        self.mine[a] = port
        return a
    def unpublish(self, a):
        with LOCK: REG.pop(a, None)
        self.mine.pop(a, None)

def usable(chat):
    return bool(chat.mesh.address
                or any(l.alive and l.ready for l in chat.mesh.links))

def wait(cond, limit=120):
    t0 = time.time()
    while time.time() - t0 < limit:
        if cond(): return time.time() - t0
        time.sleep(0.2)
    return -1.0

ts.CLAIM_SETTLE = (1.0, 2.0)
room = ts.Room("joins", "a-passphrase-for-joining")

print("=== a room with three people already in it ===")
hosts = [ts.Chat(Tor(), room, f"host{i}") for i in range(3)]
for h in hosts:
    h.start(); time.sleep(0.3)
wait(lambda: all(h.mesh.address for h in hosts))
print(f"  {sum(1 for h in hosts if h.mesh.address)} hosts holding doors,"
      f" {ts.DOORS - 3} doors still free")

joiner = ts.Chat(Tor(), room, "joiner")
t0 = time.time()
joiner.start()
in_at = wait(lambda: usable(joiner))
linked = wait(lambda: any(l.alive and l.ready for l in joiner.mesh.links), 150)
print(f"  join screen lets you in : {in_at:.0f}s")
print(f"  actually reaches a peer : {linked:.0f}s")
print(f"  claimed a door first    : {joiner.mesh.claimed is not None}")
saw = wait(lambda: joiner.count >= 2, 120)
print(f"  roster shows others     : {saw:.0f}s   (count {joiner.count})")
for c in hosts + [joiner]: c.close()

print("\n=== a peer whose clock is an epoch behind ===")
REG.clear()
room2 = ts.Room("skew", "a-passphrase-for-skewing")
old = ts.Chat(Tor(), room2, "slowclock")
old.start()
wait(lambda: old.mesh.address)
with LOCK:                       # move them onto the previous epoch's doors
    REG.pop(old.mesh.address, None)
    REG[room2.doors_at(ts.door_epoch() - 1)[0].address] = old.mesh.local_port
print(f"  peer now only reachable on epoch {ts.door_epoch() - 1}")
newc = ts.Chat(Tor(), room2, "rightclock")
newc.start()
found = wait(lambda: any(l.alive and l.ready for l in newc.mesh.links), 200)
print(f"  joiner on epoch {ts.door_epoch()} finds them : "
      + (f"yes, {found:.0f}s" if found >= 0 else "NO - skew fallback broken"))
for c in (old, newc): c.close()
