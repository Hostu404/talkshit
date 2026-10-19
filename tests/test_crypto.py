"""Cryptographic invariants. These are properties that must hold, not
implementation details - if any fails the security claims are void."""
import base64, os, time
import pytest
import talkshit as ts


class TestKeySeparation:
    def test_passphrase_changes_the_key(self):
        assert ts.Room("x", "passphrase-one-here").key != \
               ts.Room("x", "passphrase-two-here").key

    def test_room_name_changes_the_key(self):
        assert ts.Room("alpha", "same-passphrase-here").key != \
               ts.Room("bravo", "same-passphrase-here").key

    def test_derivation_is_deterministic(self):
        a = ts.Room("alpha", "same-passphrase-here")
        b = ts.Room("alpha", "same-passphrase-here")
        assert a.key == b.key and a.fingerprint == b.fingerprint
        assert [d.address for d in a.identities] == [d.address for d in b.identities]

    def test_different_rooms_share_no_doors(self):
        a = ts.Room("alpha", "same-passphrase-here")
        b = ts.Room("alpha", "other-passphrase-xx")
        assert {d.address for d in a.identities}.isdisjoint(
               {d.address for d in b.identities})

    def test_unicode_passphrases_work_and_differ(self):
        a = ts.Room("r", "паssphrase-with-cyrillic")
        b = ts.Room("r", "passphrase-with-cyrillic")
        assert a.key != b.key


class TestOuterSeal:
    def test_round_trip(self, room):
        assert room.open(room.seal({"kind": "hello"})) == {"kind": "hello"}

    def test_wrong_room_cannot_open(self, room):
        other = ts.Room("testroom", "a-different-passphrase")
        assert other.open(room.seal({"kind": "hello"})) is None

    def test_any_flipped_bit_is_refused(self, room):
        blob = room.seal({"kind": "hello"})
        for pos in (0, 5, len(blob) // 2, len(blob) - 1):
            broken = bytearray(blob)
            broken[pos] ^= 1
            assert room.open(bytes(broken)) is None

    def test_truncation_is_refused(self, room):
        blob = room.seal({"kind": "hello"})
        for cut in (0, 1, 12, len(blob) // 2, len(blob) - 1):
            assert room.open(blob[:cut]) is None

    @pytest.mark.parametrize("junk", [b"", b"\x00", b"\xff" * 200, b"{}"])
    def test_junk_is_refused(self, room, junk):
        assert room.open(junk) is None

    def test_nonce_is_never_reused(self, room):
        blobs = [room.seal({"n": i}) for i in range(200)]
        assert len(set(b[:12] for b in blobs)) == 200


class TestSignatures:
    def test_genuine_body_verifies(self, room, signed):
        assert ts.verify(signed(room, text="hi"))

    @pytest.mark.parametrize("break_it", [
        lambda b: {k: v for k, v in b.items() if k != "sig"},
        lambda b: {**b, "sig": ""},
        lambda b: {**b, "sig": None},
        lambda b: {**b, "sig": "!!!not base64!!!"},
        lambda b: {**b, "from": ""},
        lambda b: {**b, "from": base64.b64encode(b"\x00" * 31).decode()},
        lambda b: {**b, "from": base64.b64encode(b"\x00" * 32).decode()},
        lambda b: {**b, "text": "tampered"},
        lambda b: {**b, "extra": "added"},
        lambda b: {**b, "ts": 99.0},
        lambda b: {**b, "rm": "otherroom"},
    ])
    def test_every_tamper_is_refused(self, room, signed, break_it):
        assert not ts.verify(break_it(signed(room, text="hi")))

    def test_a_key_cannot_claim_another_key_s_signature(self, room, signed):
        body = signed(room, text="hi")
        other = ts.Identity()
        body["from"] = base64.b64encode(other.edpub).decode()
        assert not ts.verify(body)

    @pytest.mark.parametrize("junk", [None, "", 0, [], {"kind": "msg"}])
    def test_junk_bodies(self, junk):
        try:
            assert ts.verify(junk) in (False, None)
        except (AttributeError, TypeError):
            pass   # rejecting by exception is acceptable; the caller guards it


class TestSignedBytes:
    def test_field_order_does_not_matter(self):
        a = {"kind": "msg", "text": "x", "ts": 1.0}
        b = {"ts": 1.0, "text": "x", "kind": "msg"}
        assert ts.signed_bytes(a) == ts.signed_bytes(b)

    def test_signature_field_is_excluded(self):
        a = {"kind": "msg", "text": "x"}
        assert ts.signed_bytes(a) == ts.signed_bytes({**a, "sig": "zzz"})

    def test_every_other_field_is_covered(self):
        base = {"kind": "msg", "text": "x", "ts": 1.0, "id": "a", "rm": "r"}
        canon = ts.signed_bytes(base)
        for k in base:
            assert ts.signed_bytes({**base, k: "CHANGED"}) != canon
        assert ts.signed_bytes({**base, "new": 1}) != canon

    def test_no_delimiter_confusion(self):
        pairs = [
            ({"a": "x,y"}, {"a": "x", "y": ""}),
            ({"ab": 1}, {"a": {"b": 1}}),
            ({"a:b": 1}, {"a": ":b1"}),
            ({"a": 1}, {"a": True}),
            ({"a": 1}, {"a": 1.0}),
            ({"a": "\u00e9"}, {"a": "e\u0301"}),
        ]
        for x, y in pairs:
            assert ts.signed_bytes(x) != ts.signed_bytes(y), (x, y)


class TestLinkKeys:
    def test_two_sides_agree(self, room):
        (ax, apub), (bx, bpub) = ts.link_keypair(), ts.link_keypair()
        tx1, rx1 = ts.link_keys(ax, apub, bpub, room.key)
        tx2, rx2 = ts.link_keys(bx, bpub, apub, room.key)
        n = os.urandom(12)
        assert rx2.decrypt(n, tx1.encrypt(n, b"secret", room.label),
                           room.label) == b"secret"
        assert rx1.decrypt(n, tx2.encrypt(n, b"other", room.label),
                           room.label) == b"other"

    def test_directions_are_distinct(self, room):
        (ax, apub), (_, bpub) = ts.link_keypair(), ts.link_keypair()
        tx1, rx1 = ts.link_keys(ax, apub, bpub, room.key)
        n = os.urandom(12)
        with pytest.raises(Exception):
            rx1.decrypt(n, tx1.encrypt(n, b"x", room.label), room.label)

    def test_each_link_is_independent(self, room):
        (ax, apub), (_, bpub), (_, cpub), (dx, dpub) = (
            ts.link_keypair() for _ in range(4))
        tx1, _ = ts.link_keys(ax, apub, bpub, room.key)
        _, rx2 = ts.link_keys(dx, dpub, cpub, room.key)
        n = os.urandom(12)
        with pytest.raises(Exception):
            rx2.decrypt(n, tx1.encrypt(n, b"x", room.label), room.label)

    @pytest.mark.parametrize("point", [
        b"\x00" * 32,
        b"\x01" + b"\x00" * 31,
        bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd"
                      "866205165f49b800"),
        bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffff"
                      "ffffffffffffff7f"),
    ])
    def test_low_order_points_are_rejected(self, point):
        private, _ = ts.link_keypair()
        with pytest.raises(Exception):
            private.exchange(ts.X25519PublicKey.from_public_bytes(point))


def _wait(predicate, seconds=10.0):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


class TestCircuitKeys:
    """Key agreement happens per circuit, not per session. The README promised
    a fresh key per connection while every circuit in a session shared one
    pair - so two circuits to the same peer agreed identical keys, and the
    private half lived for as long as the room was open."""

    @pytest.fixture
    def two_meshes(self, stub_transport, room):
        meshes = [ts.Mesh(stub_transport, room, publish=False) for _ in range(2)]
        yield meshes
        for m in meshes:
            m.stop.set()
            m.close()

    def _circuit(self, mine, theirs):
        import socket
        a, b = socket.socketpair()
        here, there = ts.Link(a, mine), ts.Link(b, theirs)
        assert _wait(lambda: here.ready and there.ready), "keys never agreed"
        return here, there

    def test_two_circuits_to_the_same_peer_have_different_keys(self, two_meshes,
                                                              room):
        a, b = two_meshes
        first_here, first_there = self._circuit(a, b)
        second_here, second_there = self._circuit(a, b)
        n = os.urandom(12)
        sealed = first_here._tx.encrypt(n, b"x", room.label)
        assert first_there._rx.decrypt(n, sealed, room.label) == b"x"
        with pytest.raises(Exception):
            second_there._rx.decrypt(n, sealed, room.label)
        assert first_here._xpub != second_here._xpub
        for link in (first_here, first_there, second_here, second_there):
            link.drop()

    def test_the_private_half_is_gone_once_keys_are_agreed(self, two_meshes):
        here, there = self._circuit(*two_meshes)
        assert here._x is None and there._x is None
        here.drop(); there.drop()

    def test_a_circuit_to_ourselves_never_comes_up(self, two_meshes):
        """Claiming a door dials it: a circuit that comes up means somebody
        else holds it too. Reaching our own listener must not look like that."""
        import socket
        mesh = two_meshes[0]
        a, b = socket.socketpair()
        out, back = ts.Link(a, mesh), ts.Link(b, mesh)
        assert _wait(lambda: not out.alive and not back.alive), \
            "a circuit to ourselves stayed open"
        assert not out.ready and not back.ready

    def test_our_offer_is_still_known_after_its_circuit_closes(self, two_meshes):
        """Both ends of a circuit to ourselves read each other's offer
        moments apart. The first to notice hangs up; if its offer were
        forgotten then, the second would agree keys with a dead circuit and
        read itself as somebody else holding our door."""
        import socket
        mesh = two_meshes[0]
        a, a_far = socket.socketpair()
        b, b_far = socket.socketpair()
        try:
            first, second = ts.Link(a, mesh), ts.Link(b, mesh)
            first.drop()
            second._on_kx({"kind": "kx", "v": ts.PROTOCOL,
                           "epk": base64.b64encode(first._xpub).decode()})
            assert not second.ready
            second.drop()
        finally:
            for s in (a_far, b_far):
                s.close()

    def test_old_offers_are_forgotten(self, two_meshes, monkeypatch):
        mesh = two_meshes[0]
        mesh.offered(b"x" * 32)
        assert mesh.is_ours(b"x" * 32)
        monkeypatch.setattr(ts, "OWN_OFFER_MEMORY", -1.0)
        mesh.offered(b"y" * 32)
        assert not mesh.is_ours(b"x" * 32)


class TestPadding:
    @pytest.mark.parametrize("n", [0, 1, 100, 255, 256, 257, 1000, 2584])
    def test_round_trip_and_block_alignment(self, n):
        raw = b"x" * n
        assert len(ts.pad_body(raw)) % ts.PAD_TO == 0
        assert ts.unpad_body(ts.pad_body(raw)) == raw

    def test_padding_hides_length_within_a_block(self):
        assert len(ts.pad_body(b"a")) == len(ts.pad_body(b"a" * 50))


class TestIdentity:
    def test_keys_are_distinct_per_identity(self):
        ids = [ts.Identity() for _ in range(50)]
        assert len({i.edpub for i in ids}) == 50
        assert len({ts.link_keypair()[1] for _ in range(50)}) == 50

    def test_signature_verifies_against_its_own_key(self):
        me = ts.Identity()
        ts.Ed25519PublicKey.from_public_bytes(me.edpub).verify(
            me.sign(b"message"), b"message")

    def test_fingerprint_is_stable_and_long_enough(self):
        """Eight hex characters is thirty two bits, which a vanity key
        generator matches in minutes."""
        me = ts.Identity()
        assert me.fingerprint == ts.key_fingerprint(me.edpub)
        assert len(me.fingerprint) == 16


class TestDropHangsUp:
    """close() alone left the connection open: the reader's makefile kept the
    socket alive, so a peer we dropped never found out and the reader went on
    handling everything it sent."""

    def test_the_far_end_sees_the_hang_up(self, stub_transport, room):
        import socket
        meshes = [ts.Mesh(stub_transport, room, publish=False) for _ in range(2)]
        try:
            a, b = socket.socketpair()
            here, there = ts.Link(a, meshes[0]), ts.Link(b, meshes[1])
            assert _wait(lambda: here.ready and there.ready)
            here.drop()
            assert _wait(lambda: not there.alive), "the peer never heard us hang up"
        finally:
            for m in meshes:
                m.stop.set()
                m.close()
