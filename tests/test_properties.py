"""Property-based tests. The point is the invariants, not the randomness:
each property states something that must hold for every input."""
import base64, os, string
import pytest
from hypothesis import given, strategies as st, settings, HealthCheck, assume
import talkshit as ts

SETTINGS = settings(max_examples=300, deadline=None,
                    suppress_health_check=[HealthCheck.function_scoped_fixture])
text = st.text(max_size=400)
printable_text = st.text(alphabet=string.printable, max_size=200)


class TestPrintableProperties:
    @given(text)
    @SETTINGS
    def test_output_is_always_printable_or_space(self, raw):
        for ch in ts.printable(raw, 500):
            assert ch.isprintable() or ch == " "

    @given(text, st.integers(min_value=0, max_value=300))
    @SETTINGS
    def test_never_exceeds_the_limit(self, raw, limit):
        assert len(ts.printable(raw, limit)) <= limit

    @given(text)
    @SETTINGS
    def test_is_idempotent(self, raw):
        once = ts.printable(raw, 200)
        assert ts.printable(once, 200) == once

    @given(text)
    @SETTINGS
    def test_never_lengthens_the_input(self, raw):
        assert len(ts.printable(raw, 10**6)) <= len(raw)


class TestWrapProperties:
    @given(printable_text, st.integers(min_value=1, max_value=120))
    @SETTINGS
    def test_no_line_is_wider_than_asked(self, raw, width):
        clean = ts.printable(raw, 400)
        for line in ts.wrap_styled(ts.styled_words(clean), width):
            drawn = "".join(t for t, _ in line)
            assert ts.cell_width(drawn) <= max(4, width) + 1

    @given(printable_text, st.integers(min_value=1, max_value=120))
    @SETTINGS
    def test_no_character_is_lost_or_invented(self, raw, width):
        clean = ts.printable(raw, 400)
        lines = ts.wrap_styled(ts.styled_words(clean), width)
        flat = "".join(t for ln in lines for t, _ in ln)
        assert flat.replace(" ", "") == clean.replace(" ", "")

    @given(printable_text)
    @SETTINGS
    def test_every_word_keeps_one_colour(self, raw):
        for word, style in ts.styled_words(ts.printable(raw, 300)):
            assert style in (ts.PAIR_TEXT, ts.PAIR_GREEN, ts.PAIR_LINK)

    @given(st.text(alphabet="abc >", max_size=80))
    @SETTINGS
    def test_greentext_never_goes_back_to_plain(self, raw):
        seen_green = False
        for _, style in ts.styled_words(raw):
            if style != ts.PAIR_TEXT:
                seen_green = True
            elif seen_green:
                pytest.fail("colour reverted mid-message")


class TestCellWidth:
    @given(text)
    @SETTINGS
    def test_width_is_never_negative(self, raw):
        assert ts.cell_width(raw) >= 0

    @given(text, text)
    @SETTINGS
    def test_width_is_additive(self, a, b):
        assert ts.cell_width(a + b) == ts.cell_width(a) + ts.cell_width(b)


class TestOnionProperties:
    @given(st.binary(min_size=32, max_size=32))
    @SETTINGS
    def test_every_derived_address_validates(self, key):
        assert ts.valid_onion(ts.onion_address(key))

    @given(st.binary(min_size=32, max_size=32))
    @SETTINGS
    def test_derivation_is_injective_and_stable(self, key):
        assert ts.onion_address(key) == ts.onion_address(key)
        other = bytes([key[0] ^ 1]) + key[1:]
        assert ts.onion_address(key) != ts.onion_address(other)

    @given(st.text(max_size=80))
    @SETTINGS
    def test_arbitrary_text_is_not_a_valid_address(self, raw):
        assume(not raw.endswith(".onion"))
        assert ts.valid_onion(raw) is False


class TestSignatureProperties:
    @given(st.dictionaries(st.text(min_size=1, max_size=12),
                           st.one_of(st.text(max_size=40), st.integers(),
                                     st.booleans(), st.none()),
                           max_size=8))
    @SETTINGS
    def test_canonical_form_is_stable_under_reordering(self, body):
        assume("sig" not in body)
        shuffled = dict(reversed(list(body.items())))
        assert ts.signed_bytes(body) == ts.signed_bytes(shuffled)

    @given(st.dictionaries(st.text(min_size=1, max_size=12),
                           st.text(max_size=40), min_size=1, max_size=6))
    @SETTINGS
    def test_signing_then_verifying_always_works(self, body):
        assume("sig" not in body and "from" not in body)
        me = ts.Identity()
        body["from"] = base64.b64encode(me.edpub).decode()
        body["sig"] = base64.b64encode(
            me.sign(ts.signed_bytes(body))).decode()
        assert ts.verify(body)

    @given(st.dictionaries(st.text(min_size=1, max_size=10),
                           st.text(max_size=30), min_size=1, max_size=5),
           st.text(min_size=1, max_size=10), st.text(max_size=30))
    @SETTINGS
    def test_any_change_breaks_the_signature(self, body, field, value):
        assume("sig" not in body and "from" not in body)
        assume(field not in ("sig", "from"))
        me = ts.Identity()
        body["from"] = base64.b64encode(me.edpub).decode()
        body["sig"] = base64.b64encode(
            me.sign(ts.signed_bytes(body))).decode()
        assume(body.get(field) != value)
        assert not ts.verify({**body, field: value})


class TestPaddingProperties:
    @given(st.binary(max_size=3000))
    @SETTINGS
    def test_round_trip_is_exact(self, raw):
        assert ts.unpad_body(ts.pad_body(raw)) == raw

    @given(st.binary(max_size=3000))
    @SETTINGS
    def test_always_a_whole_number_of_blocks(self, raw):
        assert len(ts.pad_body(raw)) % ts.PAD_TO == 0


class TestSealProperties:
    @given(st.dictionaries(st.text(min_size=1, max_size=8),
                           st.text(max_size=60), max_size=5))
    @SETTINGS
    def test_seal_open_round_trip(self, body):
        room = ts.Room("prop", "a-passphrase-for-properties")
        assert room.open(room.seal(body)) == body

    @given(st.binary(max_size=400))
    @SETTINGS
    def test_arbitrary_bytes_never_open(self, blob):
        room = ts.Room("prop", "a-passphrase-for-properties")
        assert room.open(blob) is None


class TestFoldingProperties:
    @given(st.text(max_size=60))
    @SETTINGS
    def test_folding_is_idempotent(self, raw):
        assert ts.folded(ts.folded(raw)) == ts.folded(raw)

    @given(st.text(max_size=60))
    @SETTINGS
    def test_folding_never_lengthens(self, raw):
        """Measured against NFKD *and* casefold: casefold legitimately grows
        some characters ('\u00df' -> 'ss'), so the bare NFKD length was the
        wrong yardstick, not the function."""
        import unicodedata
        baseline = unicodedata.normalize("NFKD", raw).casefold()
        assert len(ts.folded(raw)) <= len(baseline)

    @given(st.text(max_size=40))
    @SETTINGS
    def test_leet_folding_is_stable(self, raw):
        assert ts._fold_leet(ts._fold_leet(raw)) == ts._fold_leet(raw)


class TestPassphraseProperties:
    @given(st.integers(min_value=12, max_value=40))
    @SETTINGS
    def test_generated_always_passes_its_own_check(self, n):
        p = ts.new_passphrase(n)
        assert len(p) == n
        assert ts.weak_passphrase(p, "anyroom") is None

    @given(st.text(max_size=30), st.text(max_size=20))
    @SETTINGS
    def test_check_never_raises(self, phrase, room):
        result = ts.weak_passphrase(phrase, room)
        assert result is None or isinstance(result, str)

    @given(st.text(min_size=ts.MIN_PASSPHRASE, max_size=24))
    @SETTINGS
    def test_a_passphrase_equal_to_the_room_name_is_always_refused(self, name):
        """Generated at length rather than filtered to it - assume() was
        discarding most of what hypothesis produced."""
        assert ts.weak_passphrase(name, name) is not None

    @given(st.text(alphabet="abcdefgh -_", min_size=12, max_size=20))
    @SETTINGS
    def test_room_name_check_survives_punctuation_only_names(self, name):
        """A name of nothing but separators reduced to an empty string, and
        the room-name comparison was skipped entirely."""
        assert ts.weak_passphrase(name, name) is not None


class TestBridgeProperties:
    @given(st.text(max_size=200))
    @SETTINGS
    def test_cleaned_lines_never_carry_a_newline(self, raw):
        got = ts.clean_bridge(raw)
        assert got is None or not any(c in got for c in "\r\n\x00")

    @given(st.lists(st.text(max_size=80), max_size=20))
    @SETTINGS
    def test_clean_bridges_returns_a_list_of_safe_lines(self, lines):
        for line in ts.clean_bridges(lines):
            assert not any(c in line for c in "\r\n\x00")
