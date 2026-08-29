"""Threads, shutdown, and what gets left behind. Every test here has a
timeout: a hang is a failure, not a wait."""
import gc, os, socket, threading, time
import pytest
import talkshit as ts


def fds():
    try:
        return len(os.listdir(f"/proc/{os.getpid()}/fd"))
    except OSError:
        return -1


@pytest.mark.timeout(120)
class TestLifecycle:
    def test_joining_and_leaving_leaks_nothing(self, stub_transport):
        base_threads = threading.active_count()
        base_fds = fds()
        for i in range(12):
            room = ts.Room(f"room{i}", "a-passphrase-for-cycling")
            chat = ts.Chat(stub_transport, room, "me")
            chat.start()
            time.sleep(0.4)
            chat.say("something")
            chat.close()
            del chat, room
            gc.collect()
        for _ in range(60):
            if threading.active_count() <= base_threads + 1:
                break
            time.sleep(0.1)
        assert threading.active_count() <= base_threads + 1, \
            [t.name for t in threading.enumerate()]
        assert fds() <= base_fds + 2

    def test_onion_services_are_withdrawn(self, stub_transport, room):
        chat = ts.Chat(stub_transport, room, "me")
        chat.start()
        time.sleep(1.0)
        chat.close()
        time.sleep(0.5)
        assert set(stub_transport.published) <= set(stub_transport.unpublished)

    def test_close_is_idempotent(self, stub_transport, room):
        chat = ts.Chat(stub_transport, room, "me", publish=False)
        chat.start()
        time.sleep(0.3)
        chat.close(); chat.close(); chat.close()

    def test_close_before_start(self, stub_transport, room):
        ts.Chat(stub_transport, room, "me", publish=False).close()

    def test_shutdown_during_the_opening_sweep(self, room):
        # Modelled on the real thing: tor accepts the socket immediately and
        # the wait happens afterwards, inside the negotiation. Closing that
        # socket is what ends it, so the stub must block on a socket rather
        # than on a sleep, which nothing can interrupt.
        held = []

        class Slow:
            extended = True
            def connect(self, a, timeout=45.0, auth=None, on_socket=None):
                mine, theirs = socket.socketpair()
                held.append((mine, theirs))
                if on_socket:
                    on_socket(mine)
                mine.settimeout(timeout)
                try:
                    mine.recv(1)
                except OSError:
                    raise ts.SocksError("gone", 0)
                raise ts.SocksError("no", 0xF0)
            def publish(self, k, p):
                return ts.onion_address(os.urandom(32))
            def unpublish(self, a):
                pass

        chat = ts.Chat(Slow(), room, "me")
        chat.start()
        time.sleep(1.0)
        began = time.time()
        chat.close()
        assert time.time() - began < 20, "close blocked on the sweep"
        deadline = time.time() + 12
        while time.time() < deadline:
            if not [t for t in threading.enumerate()
                    if "probe" in t.name and t.is_alive()]:
                break
            time.sleep(0.1)
        alive = [t.name for t in threading.enumerate()
                 if "probe" in t.name and t.is_alive()]
        for a, b in held:
            a.close(); b.close()
        assert not alive, f"dials outlived the room: {alive}"


@pytest.mark.timeout(120)
class TestConcurrentAccess:
    def test_many_threads_dispatching_at_once(self, stub_transport, room,
                                              fake_link, signed):
        chat = ts.Chat(stub_transport, room, "me", publish=False)
        errors = []
        link = fake_link(chat.mesh)

        def hammer():
            for _ in range(300):
                try:
                    chat.mesh._dispatch(
                        signed(room, kind="msg", nick="p", text="x"), link)
                except Exception as exc:
                    errors.append(exc)

        threads = [threading.Thread(target=hammer) for _ in range(8)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=60)
        chat.close()
        assert not errors, errors[:3]

    def test_reading_the_roster_while_it_changes(self, stub_transport, room,
                                                 fake_link, signed):
        chat = ts.Chat(stub_transport, room, "me", publish=False)
        link = fake_link(chat.mesh)
        errors, stop = [], threading.Event()

        def writer():
            i = 0
            while not stop.is_set():
                i += 1
                link.fresh.clear()
                try:
                    chat.mesh._dispatch(
                        signed(room, kind="ping", nick=f"p{i % 50}"), link)
                except Exception as exc:
                    errors.append(exc)

        def reader():
            while not stop.is_set():
                try:
                    chat.fingerprints(); chat.count; chat.peers; chat._prune()
                except Exception as exc:
                    errors.append(exc)

        ws = [threading.Thread(target=writer) for _ in range(4)]
        rs = [threading.Thread(target=reader) for _ in range(3)]
        for t in ws + rs: t.start()
        time.sleep(5)
        stop.set()
        for t in ws + rs: t.join(timeout=30)
        chat.close()
        assert not errors, errors[:3]

    def test_who_does_not_deadlock(self, stub_transport, room):
        chat = ts.Chat(stub_transport, room, "me", publish=False)
        done = threading.Event()

        def call():
            for _ in range(200):
                chat.fingerprints(); chat.count; chat._prune()
            done.set()

        threading.Thread(target=call, daemon=True).start()
        assert done.wait(30), "fingerprints/count/prune deadlocked"
        chat.close()

    def test_index_under_concurrent_announcers(self, stub_transport):
        import base64
        idx = ts.Index(stub_transport, publish=False)
        errors, stop = [], threading.Event()

        def announce():
            i = 0
            while not stop.is_set():
                i += 1
                try:
                    idx._on_object({"kind": "room", "room": f"room{i % 400}",
                                    "n": 3, "fp": f"fp{i % 5}",
                                    "id": os.urandom(6).hex(),
                                    "from": base64.b64encode(
                                        os.urandom(32)).decode()}, None)
                except Exception as exc:
                    errors.append(exc)

        def read():
            while not stop.is_set():
                try:
                    idx.rooms(); idx._compact()
                except Exception as exc:
                    errors.append(exc)

        ths = [threading.Thread(target=announce) for _ in range(5)] + \
              [threading.Thread(target=read) for _ in range(2)]
        for t in ths: t.start()
        time.sleep(6)
        stop.set()
        for t in ths: t.join(timeout=30)
        idx.close()
        assert not errors, errors[:3]


@pytest.mark.timeout(180)
class TestNoUnboundedGrowth:
    def test_containers_stay_bounded_under_sustained_traffic(
            self, stub_transport, room, fake_link, signed):
        chat = ts.Chat(stub_transport, room, "me", publish=False)
        link = fake_link(chat.mesh)
        import base64
        keys = [ts.Identity() for _ in range(30)]
        for i in range(6000):
            link.fresh.clear()
            chat.mesh._dispatch(
                signed(room, kind="msg", nick=f"n{i % 30}", text="x" * 40,
                       ident=keys[i % 30]), link)
            if i % 200 == 0:
                while chat.inbox.qsize():
                    chat.inbox.get_nowait()
            if i % 7 == 0:
                chat.mesh._learn(
                    [ts.onion_address(os.urandom(32)) for _ in range(6)],
                    f"src{i % 20}")
        assert len(chat.mesh.seen) <= ts.MAX_SEEN
        assert len(chat.mesh.known) <= ts.MAX_KNOWN
        assert len(chat.mesh.rates) <= ts.MAX_ROSTER * 2
        assert len(chat.nicks) <= ts.MAX_ROSTER
        assert len(link.seen_here) <= ts.LINK_RATE_LIMIT
        chat.close()
