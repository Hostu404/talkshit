"""Try the attacks against the mitigations, rather than trusting them."""
import base64, os, socket, time
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))
import talkshit as ts


class Stub:
    extended = True

    def connect(self, *a, **k):
        raise ts.SocksError("onion descriptor not found", 0xF0)

    def publish(self, *a, **k):
        raise OSError("not publishing in this test")

    def unpublish(self, *a, **k):
        pass


def key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def onion() -> str:
    return ts.onion_address(os.urandom(32))


def mesh() -> ts.Mesh:
    return ts.Mesh(Stub(), ts.PublicIndex(), publish=False)


def link(m, ready=True) -> ts.Link:
    a, b = socket.socketpair()
    l = ts.Link.__new__(ts.Link)          # no handshake threads for a unit test
    l.sock, l.mesh, l.address = a, m, ""
    l.alive, l.useful = True, False
    import collections as _c
    l.seen_here, l.fresh, l.keys_here = _c.deque(), _c.deque(), {}
    l.opened = l.last_heard = time.time()
    l.lock = __import__("threading").Lock()
    l._tx = object() if ready else None
    l._rx = l._tx
    return l


def minting_brake():
    m = mesh()
    l = link(m)
    l.opened = time.time() - ts.RATE_WINDOW * 10      # an established circuit
    passed = sum(0 if (l.minting(key()) or l.saturated()) else 1
                 for _ in range(2000))
    print(f"  2000 messages, a fresh key each   -> {passed} accepted"
          f"   (new keys capped at {ts.NEW_KEYS_PER_WINDOW} per window)")
    return passed <= ts.NEW_KEYS_PER_WINDOW * 2


def new_key_budget():
    m = mesh()
    l = link(m)                                       # a brand-new circuit
    one = key()
    passed = sum(0 if l.minting(one) else 1 for _ in range(200))
    print(f"  200 messages, one unknown key     -> {passed} accepted"
          f"   (budget is {ts.NEW_KEY_BUDGET})")
    return passed <= ts.NEW_KEY_BUDGET


def big_room_unaffected():
    """The check that would have caught the room being capped at 64. A link
    relays for everybody, so a limit on distinct keys is a limit on people."""
    m = mesh()
    l = link(m)
    l.opened = time.time() - ts.RATE_WINDOW * 10
    people = [key() for _ in range(300)]
    for who in people:              # everyone speaks once, spread over time
        l.minting(who)
        l.fresh.clear()
    for e in l.keys_here.values():
        e[0] = time.time() - ts.RATE_WINDOW * 4      # settled residents
    blocked = sum(1 for who in people if l.minting(who))
    print(f"  300 settled speakers on one link  -> {blocked} blocked"
          f"   (must be 0)")
    return blocked == 0


def honest_peer_unaffected():
    m = mesh()
    l = link(m)
    l.opened = time.time() - ts.RATE_WINDOW * 10
    one = key()
    passed = sum(0 if l.minting(one) else 1 for _ in range(20))
    print(f"  20 messages from a brand new key  -> {passed} accepted"
          f"   (must be 20: a joiner is not a flooder)")
    return passed == 20


def gossip_flood():
    m = mesh()
    liar, real = key(), [key(), key(), key()]
    good = [onion() for _ in range(20)]
    for src in real:                                  # three peers agree
        m._learn(good, src)
    m._learn([onion() for _ in range(6000)], liar)     # one peer invents
    kept = len(m.known)
    survived = sum(1 for a in good if a in m.known)
    junk = kept - survived
    print(f"  6000 invented from one source     -> {junk} of them kept"
          f"   (budget is {ts.GOSSIP_PER_PEER})")
    print(f"  20 corroborated addresses         -> {survived} survived")
    return junk <= ts.GOSSIP_PER_PEER and survived == 20


def eviction_prefers_corroborated():
    m = mesh()
    trusted = [onion() for _ in range(10)]
    for src in (key(), key()):
        m._learn(trusted, src)
    for _ in range(ts.MAX_KNOWN // ts.GOSSIP_PER_PEER + 4):   # many liars
        m._learn([onion() for _ in range(ts.GOSSIP_PER_PEER)], key())
    survived = sum(1 for a in trusted if a in m.known)
    print(f"  known table pushed to its cap     -> {survived}/10 corroborated"
          f" addresses survived   (table holds {len(m.known)})")
    return survived == 10


def silent_socket_holds_no_slot():
    m = mesh()
    m.links = [link(m, ready=False) for _ in range(ts.MAX_LINKS * 2)]
    quiet = m.crowded()
    m.links = [link(m, ready=True) for _ in range(ts.MAX_LINKS)]
    real = m.crowded()
    print(f"  {ts.MAX_LINKS * 2} sockets that never agreed keys -> crowded: {quiet}"
          f"   (must be False)")
    print(f"  {ts.MAX_LINKS} real peers                     -> crowded: {real}"
          f"   (must be True)")
    return not quiet and real


def homoglyphs():
    bad = [("admin", "\u0430dmin"), ("moot", "m00t"), ("alice", "a1ice")]
    ok = [("alice", "bob"), ("dave", "david")]
    hits = all(ts.folded(a) == ts.folded(b) for a, b in bad)
    misses = all(ts.folded(a) != ts.folded(b) for a, b in ok)
    print(f"  lookalike handles collide         -> {hits}"
          f"   distinct handles stay distinct -> {misses}")
    return hits and misses


if __name__ == "__main__":
    checks = [("identity minting", minting_brake),
              ("big room not capped", big_room_unaffected),
              ("unknown-key budget", new_key_budget),
              ("honest peer unaffected", honest_peer_unaffected),
              ("gossip flood", gossip_flood),
              ("eviction order", eviction_prefers_corroborated),
              ("silent socket slots", silent_socket_holds_no_slot),
              ("homoglyph handles", homoglyphs)]
    results = []
    for name, fn in checks:
        print(f"\n{name}")
        try:
            results.append((name, fn()))
        except Exception as exc:
            print(f"  ERROR {exc!r}")
            results.append((name, False))
    print("\n" + "=" * 58)
    for name, ok in results:
        print(f"  {'pass' if ok else 'FAIL'}  {name}")
    raise SystemExit(0 if all(ok for _, ok in results) else 1)
