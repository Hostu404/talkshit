"""Run a roomful of peers over loopback instead of tor.

Stands in for the transport only: every peer is the real Mesh, Link, Chat and
crypto. Onion addresses become localhost ports, and a connection to an address
nobody published fails the way tor's ExtendedErrors reports it, which is what
the door-claiming logic reads.
"""
import socket, sys, threading, time, queue, collections
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))
import talkshit as ts

# ---- make the fake transport able to turn a control key back into an address
KEYMAP = {}
_orig = ts.OnionIdentity.__init__


def _patched(self, key, label, slot, epoch=0):
    _orig(self, key, label, slot, epoch)
    KEYMAP[self.control_key] = self.address


ts.OnionIdentity.__init__ = _patched

REG = collections.defaultdict(list)      # address -> [port, ...] newest last
REG_LOCK = threading.Lock()
COLLISIONS = []


class FakeTransport:
    extended = True

    def __init__(self, name):
        self.name = name
        self.mine = {}

    def connect(self, address, timeout=45.0, auth=None, on_socket=None):
        with REG_LOCK:
            ports = list(REG.get(address, []))
        if not ports:
            raise ts.SocksError("onion descriptor not found", 0xF0)
        return socket.create_connection(("127.0.0.1", ports[-1]), timeout=10)

    def publish(self, control_key, local_port):
        address = KEYMAP[control_key]
        with REG_LOCK:
            if REG[address]:
                COLLISIONS.append(address)   # two peers on one door, as tor allows
            REG[address].append(local_port)
            self.mine[address] = local_port
        return address

    def unpublish(self, address):
        with REG_LOCK:
            port = self.mine.pop(address, None)
            if port in REG.get(address, []):
                REG[address].remove(port)
            if not REG.get(address):
                REG.pop(address, None)

    def close(self):
        for a in list(self.mine):
            self.unpublish(a)


def main(n=40):
    # tighten the timers so a soak fits in a minute
    ts.PROBE_TIMEOUT = 4.0
    ts.CONFIRM_TIMEOUT = 4.0
    ts.CLAIM_SETTLE = (2.0, 5.0)
    ts.GOSSIP_EVERY = 8.0
    ts.RESCAN_EVERY = 4.0
    ts.HEARTBEAT = 8.0
    ts.DOOR_BACKOFF = 1
    ts.MAX_LINKS = int(__import__("os").environ.get("MAXLINKS", ts.MAX_LINKS))
    ts.PROBE_WAVE = int(__import__("os").environ.get("WAVE", ts.PROBE_WAVE))
    ts.DOOR_EPOCH = float(__import__("os").environ.get("EPOCH", 3600))
    ts.DOOR_PATIENCE = 25.0

    room = ts.Room("soak", "a-passphrase-for-testing")   # one scrypt run, shared
    chats = []
    for i in range(n):
        c = ts.Chat(FakeTransport(f"p{i}"), room, f"peer{i}")
        chats.append(c)

    for c in chats:
        c.start()
        time.sleep(0.05)

    seen = [set() for _ in chats]

    def drain_all():
        """Drained on demand, not by a background thread: with a thousand-odd
        link threads in one process a poller gets starved, and that shows up
        as the protocol losing messages when it has not."""
        for i, c in enumerate(chats):
            while True:
                try:
                    m = c.inbox.get_nowait()
                except queue.Empty:
                    break
                if m.get("type") == "msg":
                    seen[i].add(m["text"])

    for step in range(int(__import__("os").environ.get("STEPS", 12))):
        time.sleep(5)
        drain_all()
        links = [sum(1 for l in c.mesh.links if l.alive) for c in chats]
        known = [len(c.mesh.known) for c in chats]
        counts = [c.count for c in chats]
        print(f"  t+{(step + 1) * 5:>3}s  links {min(links)}-{max(links)}"
              f" (avg {sum(links) / len(links):.1f})"
              f"   addresses known {min(known)}-{max(known)}"
              f"   roster {min(counts)}-{max(counts)}", flush=True)

    print("\n  sending one message from each of three peers...")
    for i in (0, n // 2, n - 1):
        chats[i].say(f"marker-from-{i}")
        time.sleep(0.5)
    for _ in range(int(__import__("os").environ.get("SETTLE", 30))):
        time.sleep(1)
        drain_all()

    markers = {f"marker-from-{i}" for i in (0, n // 2, n - 1)}
    reach = [len(markers & s) for s in seen]
    published = sum(1 for a, p in REG.items() if p)
    doors = {d.address for d in room.identities}
    on_doors = sum(1 for a in REG if a in doors)

    print(f"\n  peers                : {n}")
    print(f"  addresses published  : {published} ({on_doors} of {ts.DOORS} doors,"
          f" {published - on_doors} by word of mouth)")
    print(f"  unresolved collisions: {sum(1 for a in doors if len(REG.get(a, [])) > 1)}"
          f"  (raced {len(COLLISIONS)} times, then settled)")
    hist = collections.Counter(reach)
    zeros = [i for i, r in enumerate(reach) if r == 0]
    print(f"  messages reached     : {sum(reach)}/{3 * n} deliveries"
          f"   spread {dict(sorted(hist.items()))}")
    print(f"  peers at zero        : {zeros[:8]}"
          f"  (senders were 0, {n // 2}, {n - 1})")
    for i in zeros[:3]:
        c = chats[i]
        print(f"     peer{i}: links={sum(1 for l in c.mesh.links if l.alive)}"
              f" roster={c.count} known={len(c.mesh.known)}"
              f" inbox={c.inbox.qsize()} addr={'yes' if c.mesh.address else 'no'}")
    print(f"  roster size          : {min(c.count for c in chats)}"
          f"-{max(c.count for c in chats)} of {n}")

    ok = min(reach) == 3 and sum(1 for a in doors if len(REG.get(a, [])) > 1) == 0
    for c in chats:
        c.close()
    print("\n  RESULT:", "pass" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 40))
