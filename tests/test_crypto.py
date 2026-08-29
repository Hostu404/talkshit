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
        a, b = ts.Identity(), ts.Identity()
        tx1, rx1 = ts.link_keys(a.x, a.xpub, b.xpub, room.key)
        tx2, rx2 = ts.link_keys(b.x, b.xpub, a.xpub, room.key)
        n = os.urandom(12)
        assert rx2.decrypt(n, tx1.encrypt(n, b"secret", room.label),
                           room.label) == b"secret"
        assert rx1.decrypt(n, tx2.encrypt(n, b"other", room.label),
                           room.label) == b"other"

    def test_directions_are_distinct(self, room):
        a, b = ts.Identity(), ts.Identity()
        tx1, rx1 = ts.link_keys(a.x, a.xpub, b.xpub, room.key)
        n = os.urandom(12)
        with pytest.raises(Exception):
            rx1.decrypt(n, tx1.encrypt(n, b"x", room.label), room.label)

    def test_each_link_is_independent(self, room):
        a, b, c, d = (ts.Identity() for _ in range(4))
        tx1, _ = ts.link_keys(a.x, a.xpub, b.xpub, room.key)
        _, rx2 = ts.link_keys(d.x, d.xpub, c.xpub, room.key)
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
        me = ts.Identity()
        with pytest.raises(Exception):
            me.x.exchange(ts.X25519PublicKey.from_public_bytes(point))


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
        assert len({i.xpub for i in ids}) == 50

    def test_signature_verifies_against_its_own_key(self):
        me = ts.Identity()
        ts.Ed25519PublicKey.from_public_bytes(me.edpub).verify(
            me.sign(b"message"), b"message")

    def test_fingerprint_is_stable_and_short(self):
        me = ts.Identity()
        assert me.fingerprint == me.fingerprint
        assert 6 <= len(me.fingerprint) <= 16
