"""Message handling and the error paths. Everything here is fed through the
real dispatch, with bodies a hostile peer could actually send."""
import base64, os, queue, time
import pytest
import talkshit as ts


@pytest.fixture
def mesh(stub_transport, room):
    m = ts.Mesh(stub_transport, room, publish=False)
    yield m
    m.stop.set()
    m.close()


@pytest.fixture
def chat(stub_transport, room):
    c = ts.Chat(stub_transport, room, "me", publish=False)
    yield c
    c.close()


def drain(chat, kind=None):
    out = []
    while True:
        try:
            m = chat.inbox.get_nowait()
        except queue.Empty:
            return [x for x in out if kind is None or x.get("type") == kind]
        out.append(m)


class TestDispatchRejects:
    @pytest.mark.parametrize("body", [
        {}, {"kind": "msg"}, {"kind": None}, {"kind": 123},
        {"kind": "msg", "id": None}, {"kind": "msg", "ts": "soon"},
        {"kind": "msg", "ts": float("inf")},
        {"kind": "msg", "ts": float("nan")},
        {"kind": "msg", "ts": 1e400},
    ])
    def test_malformed_bodies_do_not_raise(self, mesh, fake_link, body):
        mesh._dispatch(body, fake_link(mesh))

    def test_stale_timestamp_is_dropped(self, chat, fake_link, signed, room):
        body = signed(room, kind="msg", nick="bob", text="old",
                      ts=time.time() - ts.CLOCK_SLACK * 3)
        chat.mesh._dispatch(body, fake_link(chat.mesh))
        assert drain(chat, "msg") == []

    def test_future_timestamp_is_dropped(self, chat, fake_link, signed, room):
        body = signed(room, kind="msg", nick="bob", text="soon",
                      ts=time.time() + ts.CLOCK_SLACK * 3)
        chat.mesh._dispatch(body, fake_link(chat.mesh))
        assert drain(chat, "msg") == []


class TestDeduplication:
    def test_a_relayed_duplicate_is_delivered_once(self, chat, fake_link,
                                                   signed, room):
        link = fake_link(chat.mesh)
        body = signed(room, kind="msg", nick="bob", text="hello")
        for _ in range(5):
            chat.mesh._dispatch(body, link)
        assert len(drain(chat, "msg")) == 1

    def test_one_member_cannot_suppress_another_by_reusing_an_id(
            self, chat, fake_link, signed, room):
        """Dedup keyed on the id alone let anyone silence anyone."""
        link = fake_link(chat.mesh)
        mid = os.urandom(8).hex()
        chat.mesh._dispatch(
            signed(room, kind="msg", nick="mallory", text="noise", id=mid), link)
        chat.mesh._dispatch(
            signed(room, kind="msg", nick="bob", text="the real thing", id=mid),
            link)
        texts = [m["text"] for m in drain(chat, "msg")]
        assert "the real thing" in texts

    def test_a_flood_cannot_evict_another_speaker_s_ids(self, mesh):
        now = time.time()
        for i in range(ts.MAX_SEEN + 3000):
            mesh.seen[("flooder", str(i))] = now
            if len(mesh.seen) > ts.MAX_SEEN:
                mesh._forget_seen()
        mesh.seen[("quiet-speaker", "important")] = now
        for i in range(ts.MAX_SEEN):
            mesh.seen[("flooder", f"more{i}")] = now
            if len(mesh.seen) > ts.MAX_SEEN:
                mesh._forget_seen()
        assert ("quiet-speaker", "important") in mesh.seen

    def test_the_table_stays_bounded(self, mesh):
        now = time.time()
        for i in range(ts.MAX_SEEN * 2):
            mesh.seen[(f"s{i % 40}", str(i))] = now
            if len(mesh.seen) > ts.MAX_SEEN:
                mesh._forget_seen()
        assert len(mesh.seen) <= ts.MAX_SEEN


class TestRateLimits:
    def test_a_circuit_is_capped(self, mesh, fake_link):
        link = fake_link(mesh)
        allowed = sum(0 if link.saturated() else 1 for _ in range(5000))
        assert allowed <= ts.LINK_RATE_LIMIT

    def test_the_window_does_not_grow_with_the_flood(self, mesh, fake_link):
        link = fake_link(mesh)
        for _ in range(20000):
            link.saturated()
        assert len(link.seen_here) <= ts.LINK_RATE_LIMIT

    def test_minting_fresh_keys_is_capped(self, mesh, fake_link):
        link = fake_link(mesh)
        through = sum(
            0 if link.minting(base64.b64encode(os.urandom(32)).decode()) else 1
            for _ in range(2000))
        assert through <= ts.NEW_KEYS_PER_WINDOW * 2

    def test_a_big_room_is_not_capped(self, mesh, fake_link):
        """A link relays for everybody, so a limit on distinct keys would be
        a limit on the room."""
        link = fake_link(mesh)
        people = [base64.b64encode(os.urandom(32)).decode() for _ in range(300)]
        for who in people:
            link.minting(who)
            link.fresh.clear()
        for entry in link.keys_here.values():
            entry[0] = time.time() - ts.RATE_WINDOW * 4
        assert sum(1 for who in people if link.minting(who)) == 0

    def test_a_settled_speaker_is_not_throttled(self, mesh, fake_link):
        link = fake_link(mesh)
        one = base64.b64encode(os.urandom(32)).decode()
        assert sum(0 if link.minting(one) else 1 for _ in range(20)) == 20


class TestRosterAndHandles:
    def test_a_forged_bye_cannot_remove_someone(self, chat, fake_link, signed,
                                                room):
        link = fake_link(chat.mesh)
        bob = ts.Identity()
        chat.mesh._dispatch(signed(room, kind="join", nick="bob", ident=bob), link)
        drain(chat)
        assert "bob" in chat.peers
        chat.mesh._dispatch(signed(room, kind="bye", nick="bob"), link)
        drain(chat)
        assert "bob" in chat.peers

    def test_impersonation_gets_a_fingerprint(self, chat, fake_link, signed, room):
        link = fake_link(chat.mesh)
        chat.mesh._dispatch(signed(room, kind="join", nick="bob"), link)
        drain(chat)
        chat.mesh._dispatch(signed(room, kind="join", nick="b0b"), link)
        warned = [m["text"] for m in drain(chat, "sys")]
        assert any("handle" in w for w in warned)

    def test_displayed_time_is_arrival_not_claimed(self, chat, fake_link,
                                                   signed, room):
        link = fake_link(chat.mesh)
        claimed = time.time() - ts.CLOCK_SLACK + 20
        chat.mesh._dispatch(
            signed(room, kind="msg", nick="bob", text="x", ts=claimed), link)
        got = drain(chat, "msg")
        assert got and abs(got[0]["ts"] - time.time()) < 5

    def test_roster_is_bounded(self, chat, fake_link, signed, room):
        link = fake_link(chat.mesh)
        for i in range(200):
            link.fresh.clear()
            chat.mesh._dispatch(signed(room, kind="ping", nick=f"p{i}"), link)
        drain(chat)
        assert chat.count <= ts.MAX_ROSTER


class TestGossip:
    def test_junk_addresses_are_refused(self, mesh):
        mesh._learn(["not-an-onion", "", None, 123, "x" * 500,
                     "aaaa.onion", "127.0.0.1"], "someone")
        assert all(ts.valid_onion(a) for a in mesh.known)

    def test_the_address_book_is_bounded(self, mesh):
        for i in range(200):
            mesh._learn([ts.onion_address(os.urandom(32)) for _ in range(50)],
                        f"source{i}")
        assert len(mesh.known) <= ts.MAX_KNOWN

    def test_hearsay_dialling_is_budgeted(self, mesh):
        addrs = [ts.onion_address(os.urandom(32)) for _ in range(200)]
        allowed = sum(1 for a in addrs if mesh._may_dial(a))
        assert allowed <= ts.DIAL_BUDGET

    def test_corroborated_addresses_bypass_the_budget(self, mesh):
        addr = ts.onion_address(os.urandom(32))
        for i in range(ts.CORROBORATED + 1):
            mesh._learn([addr], f"voucher{i}")
        for _ in range(ts.DIAL_BUDGET * 3):
            mesh._may_dial(ts.onion_address(os.urandom(32)))
        assert mesh._may_dial(addr) is True


class TestFaults:
    def test_a_failing_loop_is_recorded_not_swallowed(self, mesh):
        mesh.fault("presence", RuntimeError("boom"))
        mesh.fault("presence", RuntimeError("boom"))
        assert mesh.faults["presence"][0] == 2
        assert any("presence" in c for c in mesh.complaints())

    def test_no_faults_means_no_complaints(self, mesh):
        assert mesh.complaints() == []


class TestDedupTrimHappensOnItsOwn:
    """The bounded-table test above calls _forget_seen() by hand, so it never
    checked that dispatch actually triggers the trim - disabling the trim
    entirely left every test passing."""

    def test_dispatch_trims_without_being_asked(self, chat, fake_link):
        link = fake_link(chat.mesh)
        now = time.time()
        for i in range(ts.MAX_SEEN + 3000):
            chat.mesh._dispatch(
                {"kind": "ping", "nick": "x", "ts": now,
                 "id": f"id{i}", "from": f"key{i % 50}"}, link)
            if i % 500 == 0:
                while chat.inbox.qsize():
                    chat.inbox.get_nowait()
        assert len(chat.mesh.seen) <= ts.MAX_SEEN, (
            f"the table reached {len(chat.mesh.seen)} without being trimmed")

    def test_trim_keeps_the_table_useful_afterwards(self, chat, fake_link):
        link = fake_link(chat.mesh)
        now = time.time()
        for i in range(ts.MAX_SEEN + 2000):
            chat.mesh._dispatch({"kind": "ping", "nick": "x", "ts": now,
                                 "id": f"id{i}", "from": "flooder"}, link)
        recent = {"kind": "ping", "nick": "x", "ts": time.time(),
                  "id": "still-fresh", "from": "someone-else"}
        chat.mesh._dispatch(recent, link)
        assert ("someone-else", "still-fresh") in chat.mesh.seen


class TestSendDuringHandshake:
    """Observed over real tor: two peers linked, both rosters correct, and a
    message sent the instant the far side reported ready never arrived. The
    near side was still agreeing keys, and 'nobody here' and 'not ready yet'
    were being treated the same."""

    def test_a_message_sent_before_our_side_settles_is_not_lost(
            self, chat, fake_link):
        link = fake_link(chat.mesh)          # alive, but _tx is still None
        chat.mesh.links.append(link)
        sent = []
        chat.mesh.broadcast = lambda o, skip=None: sent.append(o)

        chat.say("the message that vanished")
        assert chat.unsent, "a message sent mid-handshake was not held"

        link._tx = object()                  # key agreement completes
        chat._flush_unsent()
        assert any(o.get("text") == "the message that vanished" for o in sent)
        assert chat.unsent == []

    def test_it_is_sent_once_the_peer_speaks(self, chat, fake_link, signed, room):
        link = fake_link(chat.mesh)
        chat.mesh.links.append(link)
        sent = []
        chat.mesh.broadcast = lambda o, skip=None: sent.append(o)
        chat.say("held")
        link._tx = object()
        chat.mesh._dispatch(signed(room, kind="ping", nick="bob"), link)
        assert any(o.get("text") == "held" for o in sent)

    def test_it_does_not_wait_for_ever(self, chat, fake_link):
        link = fake_link(chat.mesh)
        chat.mesh.links.append(link)
        chat.say("into the void")
        chat.unsent = [(time.time() - ts.SETTLE_HOLD - 5, o)
                       for _, o in chat.unsent]
        chat._flush_unsent()
        assert chat.unsent == []
        told = [m["text"] for m in drain(chat, "sys")]
        assert any("not sent" in t for t in told)

    def test_a_ready_link_still_sends_immediately(self, chat, fake_link):
        link = fake_link(chat.mesh)
        link._tx = object()
        chat.mesh.links.append(link)
        sent = []
        chat.mesh.broadcast = lambda o, skip=None: sent.append(o)
        chat.say("straight out")
        assert sent and chat.unsent == []


class TestTransientRendezvousFailures:
    """Observed over real tor: alice published a door, bob never reached her
    in seven minutes. A failed rendezvous was read as 'occupied, move on',
    so the one door with somebody behind it was written off on a single bad
    attempt and never dialled again."""

    def _transport(self, code, succeed_after):
        import itertools
        counter = itertools.count(1)

        class Flaky:
            extended = True
            def __init__(self):
                self.attempts = {}
            def connect(self, address, timeout=45.0, auth=None, on_socket=None):
                n = self.attempts.get(address, 0) + 1
                self.attempts[address] = n
                if address != "live":
                    raise ts.SocksError("nothing there", 0xF0)
                if n <= succeed_after:
                    raise ts.SocksError("rendezvous failed", code)
                a, b = socket.socketpair()
                self._peer = b
                return a
            def publish(self, k, p):
                return ts.onion_address(os.urandom(32))
            def unpublish(self, a):
                pass
        return Flaky()

    @pytest.mark.parametrize("code", sorted(ts.TRANSIENT_ONION))
    def test_a_flaky_door_is_dialled_again(self, room, code):
        tr = self._transport(code, succeed_after=1)
        mesh = ts.Mesh(tr, room, publish=False)
        try:
            door = type("D", (), {"address": "live", "slot": 0})()
            mesh._probe([door], timeout=1.0)
            assert tr.attempts.get("live", 0) >= 2, (
                "a transient failure was never retried")
        finally:
            mesh.stop.set(); mesh.close()

    @pytest.mark.parametrize("code", sorted(ts.TRANSIENT_ONION))
    def test_a_flaky_door_is_never_called_free(self, room, code):
        tr = self._transport(code, succeed_after=99)
        mesh = ts.Mesh(tr, room, publish=False)
        try:
            door = type("D", (), {"address": "live", "slot": 0})()
            free = mesh._probe([door], timeout=1.0)
            assert free == [], (
                "an unreachable but occupied door was offered up as free")
        finally:
            mesh.stop.set(); mesh.close()

    def test_an_absent_door_is_still_free(self, room):
        tr = self._transport(0xF2, succeed_after=0)
        mesh = ts.Mesh(tr, room, publish=False)
        try:
            door = type("D", (), {"address": "empty", "slot": 0})()
            assert mesh._probe([door], timeout=1.0) == [door]
        finally:
            mesh.stop.set(); mesh.close()


class TestNothingTravelsUnnamed:
    """Duplicate detection is the only thing stopping a relayed body going
    round the mesh for ever, and it keys on the id. A signed message with no
    id skipped the check entirely, was passed on, came back, and was passed
    on again - a permanent loop from one member sending one message."""

    @pytest.mark.parametrize("kind", sorted(ts.RELAYED))
    def test_a_relayed_body_without_an_id_is_refused(
            self, chat, fake_link, signed, room, kind):
        link = fake_link(chat.mesh)
        sent = []
        chat.mesh.broadcast = lambda o, skip=None: sent.append(o)
        body = signed(room, kind=kind, nick="m", text="x")
        body.pop("id")
        for _ in range(10):
            link.seen_here.clear(); link.fresh.clear(); chat.mesh.rates.clear()
            chat.mesh._dispatch(body, link)
        assert sent == [], f"{kind} with no id was relayed {len(sent)} times"

    def test_an_identified_body_is_relayed_exactly_once(
            self, chat, fake_link, signed, room):
        link = fake_link(chat.mesh)
        sent = []
        chat.mesh.broadcast = lambda o, skip=None: sent.append(o)
        body = signed(room, kind="msg", nick="m", text="x")
        for _ in range(5):
            link.seen_here.clear(); chat.mesh.rates.clear()
            chat.mesh._dispatch(body, link)
        assert len(sent) == 1

    @pytest.mark.parametrize("kind", ["hello", "kx", "peers", "here", "find"])
    def test_link_local_kinds_still_need_no_id(self, chat, fake_link, signed,
                                               room, kind):
        link = fake_link(chat.mesh)
        body = signed(room, kind=kind, nick="m")
        body.pop("id")
        chat.mesh._dispatch(body, link)      # must not raise


class TestOneMemberCannotSpendAnothersAllowance:
    """Rate limiting keyed on the sender alone let a member be silenced with
    their own words: keep a pile of somebody's old messages, replay them down
    your own circuit, fill their quota, and their next real message is dropped
    as flooding."""

    def _alice(self, room):
        ident = ts.Identity()
        def says(text):
            o = {"kind": "msg", "nick": "alice", "text": text,
                 "ts": time.time(), "id": os.urandom(8).hex(),
                 "rm": room.fingerprint}
            o["from"] = base64.b64encode(ident.edpub).decode()
            o["sig"] = base64.b64encode(ident.sign(ts.signed_bytes(o))).decode()
            return o
        return ident, says

    def test_replaying_someone_cannot_silence_them(self, chat, fake_link, room):
        honest, attacker = fake_link(chat.mesh), fake_link(chat.mesh)
        _, says = self._alice(room)
        for body in [says(f"old {i}") for i in range(ts.RATE_LIMIT + 40)]:
            attacker.seen_here.clear()
            chat.mesh._dispatch(body, attacker)
        drain(chat)
        for i in range(10):
            honest.seen_here.clear()
            chat.mesh._dispatch(says(f"urgent {i}"), honest)
        assert len(drain(chat, "msg")) == 10, (
            "alice was silenced by a replay of her own traffic")

    def test_a_flooder_is_still_capped_on_its_own_circuit(self, chat,
                                                          fake_link, room):
        link = fake_link(chat.mesh)
        ident, says = self._alice(room)
        who = base64.b64encode(ident.edpub).decode()
        for _ in range(ts.RATE_LIMIT + 10):
            chat.mesh._flooding(who, link)
        assert chat.mesh._flooding(who, link) is True

    def test_the_rate_table_stays_bounded(self, chat, fake_link, room):
        links = [fake_link(chat.mesh) for _ in range(6)]
        for i in range(4000):
            chat.mesh._flooding(f"speaker{i % 500}", links[i % 6])
        assert len(chat.mesh.rates) <= ts.MAX_ROSTER * 4
