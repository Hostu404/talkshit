"""Isolation for every test: nothing may touch the developer's home, the real
network, or leave threads behind."""
import os, sys, socket, tempfile, threading, shutil, importlib
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import talkshit as ts


@pytest.fixture(autouse=True)
def isolate_home(tmp_path, monkeypatch):
    """Point every path the app knows about at a throwaway directory."""
    home = str(tmp_path / "home")
    monkeypatch.setattr(ts, "HOME", home)
    if hasattr(ts, "_bind_paths"):
        ts._bind_paths()
    os.makedirs(home, exist_ok=True)
    yield home
    if hasattr(ts, "_bind_paths"):
        ts.HOME = home


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Any test that reaches the internet is a bug in the test."""
    def refuse(*a, **k):
        raise AssertionError("test attempted a real network connection")
    monkeypatch.setattr(ts.urllib.request, "urlopen", refuse)
    yield


@pytest.fixture(autouse=True)
def no_thread_leaks():
    """Fail a test that leaves a thread running."""
    before = {t.ident for t in threading.enumerate()}
    yield
    import time
    for _ in range(40):
        extra = [t for t in threading.enumerate()
                 if t.ident not in before and t.is_alive()]
        if not extra:
            return
        time.sleep(0.05)
    names = sorted(t.name for t in extra)
    if names:
        pytest.fail(f"threads still running after the test: {names}")


@pytest.fixture
def stub_transport():
    """A transport that never reaches tor. Doors always answer 'nobody here'."""
    class Stub:
        extended = True
        def __init__(self):
            self.published, self.unpublished, self.dialled = [], [], []
        def connect(self, address, timeout=45.0, auth=None, on_socket=None):
            self.dialled.append(address)
            raise ts.SocksError("onion descriptor not found", 0xF0)
        def publish(self, key, port):
            a = ts.onion_address(os.urandom(32))
            self.published.append(a)
            return a
        def unpublish(self, a):
            self.unpublished.append(a)
    return Stub()


@pytest.fixture
def room():
    return ts.Room("testroom", "a-passphrase-for-testing")


@pytest.fixture
def fake_link():
    """A Link built without a socket handshake, for feeding bodies directly."""
    import collections, queue, time
    made = []
    def build(mesh, address=""):
        a, b = socket.socketpair()
        made.append((a, b))
        l = ts.Link.__new__(ts.Link)
        l.sock, l.mesh, l.address = a, mesh, address
        l.alive, l.useful = True, False
        l.out = queue.Queue()
        l._pending = []
        l._tx = l._rx = None
        l.seen_here = collections.deque()
        l.fresh = collections.deque()
        l.keys_here = {}
        l.opened = l.last_heard = time.time()
        l.lock = threading.Lock()
        return l
    yield build
    for a, b in made:
        a.close(); b.close()


@pytest.fixture
def signed():
    """Produce a correctly signed body from a fresh identity."""
    import base64, time
    def make(room, kind="msg", ident=None, **fields):
        ident = ident or ts.Identity()
        body = {"kind": kind, "ts": time.time(),
                "id": os.urandom(8).hex(), "rm": room.fingerprint}
        body.update(fields)
        body["from"] = base64.b64encode(ident.edpub).decode()
        body["sig"] = base64.b64encode(ident.sign(ts.signed_bytes(body))).decode()
        return body
    return make
