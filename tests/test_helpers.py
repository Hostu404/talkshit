"""Pure helpers, tested against what they claim to do rather than through
their callers. Boundaries, unicode, malformed input, and the adversarial
cases each function exists to stop."""
import os, sys, unicodedata
import pytest
import talkshit as ts


# ---------------------------------------------------------------- printable
class TestPrintable:
    @pytest.mark.parametrize("raw", [None, 0, [], {}, b"bytes", 1.5, True])
    def test_non_strings_give_empty(self, raw):
        assert ts.printable(raw, 50) == ""

    def test_empty_and_whitespace(self):
        assert ts.printable("", 50) == ""
        assert ts.printable("   ", 50) == ""
        assert ts.printable("\t\n\r", 50) == ""

    @pytest.mark.parametrize("attack,forbidden", [
        ("\x1b[2Jgone", "\x1b"),
        ("\x1b]0;title\x07x", "\x1b"),
        ("\x9b31mred", "\x9b"),
        ("over\rwrite", "\r"),
        ("a\x08b", "\x08"),
        ("ding\x07", "\x07"),
        ("abc\u202edef", "\u202e"),
        ("a\u2028b", "\u2028"),
        ("a\u0085b", "\u0085"),
        ("a\ue000b", "\ue000"),
        ("a\u200bb", "\u200b"),
    ])
    def test_control_and_format_chars_removed(self, attack, forbidden):
        assert forbidden not in ts.printable(attack, 200)

    def test_limit_is_respected(self):
        assert len(ts.printable("x" * 10000, 20)) == 20

    def test_negative_and_zero_limit(self):
        assert ts.printable("hello", 0) == ""
        # a negative limit must not silently return the whole string
        assert len(ts.printable("hello", -1)) <= len("hello")

    def test_combining_marks_are_bounded(self):
        out = ts.printable("e" + "\u0301" * 500, 3000)
        marks = sum(1 for c in out if unicodedata.combining(c))
        assert marks <= ts.MAX_MARKS

    def test_leading_marks_dropped(self):
        assert ts.printable("\u0301\u0301abc", 50) == "abc"

    @pytest.mark.parametrize("text", [
        "cafe\u0301", "Tie\u0301ng Vie\u0323t", "\u0915\u094d\u0937\u093f",
        "\u0e01\u0e49\u0e33", "\u05e9\u05c1\u05b8\u05dc", "한국어", "日本語",
    ])
    def test_real_scripts_survive(self, text):
        assert ts.printable(text, 100) == text.strip()


# ------------------------------------------------------------------- folded
class TestFolded:
    def test_catches_confusables_for_admin(self):
        target = ts.folded("admin")
        for variant in ["\u0430dmin", "a\u0501min", "ad\u043cin", "adm\u0456n",
                        "admi\u043f", "\uff41\uff44\uff4d\uff49\uff4e",
                        "adm\u0131n", "4dmin", "adm1n", "adm|n",
                        "a\u0301dmin", "_admin_", "ADMIN", "\u03b1dmin"]:
            assert ts.folded(variant) == target, variant

    def test_distinct_handles_do_not_collide(self):
        names = ["alice", "bob", "carol", "dave", "erin", "mark", "marc",
                 "jon", "john", "sam", "samuel", "li", "lee", "anna", "anne",
                 "chris", "kris", "max", "zoe", "liam", "milo", "nina", "iris"]
        folded = [ts.folded(n) for n in names]
        clashes = [(a, b) for i, a in enumerate(names) for j, b in enumerate(names)
                   if i < j and folded[i] == folded[j]]
        assert clashes == []

    def test_is_idempotent(self):
        for n in ["admin", "\u0430dmin", "4dmin", "ADMIN"]:
            assert ts.folded(ts.folded(n)) == ts.folded(n)

    @pytest.mark.parametrize("raw", ["", " ", "___", "..."])
    def test_degenerate_input(self, raw):
        assert isinstance(ts.folded(raw), str)


# ------------------------------------------------------------ clean_handle
class TestCleanHandle:
    def test_colon_removed_so_a_handle_cannot_forge_a_header(self):
        assert ":" not in ts.clean_handle("alice: sure, go ahead")

    def test_all_colons_falls_back_to_empty(self):
        assert ts.clean_handle(":::") == ""

    def test_limit(self):
        assert len(ts.clean_handle("x" * 100)) <= 20


# --------------------------------------------------------------- valid_onion
class TestValidOnion:
    def test_accepts_a_genuine_address(self):
        assert ts.valid_onion(ts.onion_address(os.urandom(32)))

    @pytest.mark.parametrize("mangle", [
        lambda a: a[:-6],                       # no suffix
        lambda a: a + ".onion",                 # doubled suffix
        lambda a: a.replace(".onion", ".onion.onion"),
        lambda a: a.upper(),
        lambda a: a[:5].upper() + a[5:],
        lambda a: a + ".",
        lambda a: a + ":80",
        lambda a: "." + a,
        lambda a: " " + a,
        lambda a: a + "/path",
        lambda a: ("b" if a[0] == "a" else "a") + a[1:],   # checksum break
    ])
    def test_rejects_everything_else(self, mangle):
        assert not ts.valid_onion(mangle(ts.onion_address(os.urandom(32))))

    @pytest.mark.parametrize("junk", ["", None, 0, [], "abcdefghij234567.onion",
                                      "127.0.0.1", "localhost", "x" * 5000])
    def test_junk(self, junk):
        assert ts.valid_onion(junk) is False

    def test_matches_the_tor_v3_spec(self):
        import base64, hashlib
        key = os.urandom(32)
        raw = base64.b32decode(
            ts.onion_address(key).replace(".onion", "").upper())
        assert raw[:32] == key
        assert raw[34] == 3
        assert raw[32:34] == hashlib.sha3_256(
            b".onion checksum" + key + bytes([3])).digest()[:2]


# ---------------------------------------------------------- passphrase rules
class TestPassphrase:
    def test_generated_length_and_alphabet(self):
        p = ts.new_passphrase()
        assert len(p) == ts.PASSPHRASE_LEN
        assert set(p) <= set(ts.ALPHABET)

    def test_generated_are_not_repeated(self):
        assert len({ts.new_passphrase() for _ in range(500)}) == 500

    def test_uses_system_randomness(self):
        import inspect
        assert "SystemRandom" in inspect.getsource(ts.new_passphrase)

    def test_generated_always_pass_the_check(self):
        for _ in range(300):
            assert ts.weak_passphrase(ts.new_passphrase(), "general") is None

    @pytest.mark.parametrize("bad", [
        "short", "", "aaaaaaaaaaaa", "abcabcabcabc",
        "passwordpassword", "p4ssw0rdp4ssw0rd", "letmeinletmein",
        "general12345", "g3n3ral12345", "12345general", "GENERAL-12345",
        "generalgeneral", "generalroom1",
    ])
    def test_weak_ones_refused(self, bad):
        assert ts.weak_passphrase(bad, "general") is not None

    @pytest.mark.parametrize("good", [
        "Tr0ub4dor&3xyzzy", "the mitochondria is the powerhouse",
        "purple-marmoset-9931", "generously vast horizons",
    ])
    def test_good_ones_accepted(self, good):
        assert ts.weak_passphrase(good, "general") is None

    def test_leet_folding_is_not_transposed(self):
        assert ts._fold_leet("p4ssw0rd") == "password"
        assert ts._fold_leet("g3n3ral") == "general"
        assert ts._fold_leet("l33t") == "leet"

    def test_repeated_unit(self):
        assert ts._repeated_unit("abcabcabc") == "abc"
        assert ts._repeated_unit("abcd") == "abcd"
        assert ts._repeated_unit("") == ""


# ------------------------------------------------------------ width and wrap
class TestWrapping:
    def test_wide_and_combining_widths(self):
        assert ts.char_width("a") == 1
        assert ts.char_width("漢") == 2
        assert ts.char_width("\u0301") == 0

    @pytest.mark.parametrize("width", [1, 2, 4, 7, 40, 200])
    def test_no_line_exceeds_the_width(self, width):
        text = "漢字 " * 30 + "x" * 200 + " short words here"
        for line in ts.wrap_styled(ts.styled_words(text), width):
            assert ts.cell_width("".join(t for t, _ in line)) <= max(4, width) + 1

    def test_nothing_is_lost(self):
        text = "the quick brown fox " * 10 + "漢" * 50
        lines = ts.wrap_styled(ts.styled_words(text), 33)
        flat = "".join(t for ln in lines for t, _ in ln)
        assert flat.replace(" ", "") == text.replace(" ", "")

    def test_greentext_starts_mid_message(self):
        words = ts.styled_words("as I was saying >deep thought")
        styles = dict(words)
        assert styles["as"] == ts.PAIR_TEXT
        assert styles[">deep"] == ts.PAIR_GREEN
        assert styles["thought"] == ts.PAIR_GREEN

    def test_bare_arrow_is_not_greentext(self):
        assert all(s == ts.PAIR_TEXT for _, s in ts.styled_words("is a > b"))

    def test_quote_links_use_link_colour(self):
        assert dict(ts.styled_words("see >>1234"))[">>1234"] == ts.PAIR_LINK

    def test_wrap_cells_matches_wrap_styled(self):
        for text in ["", "a", "hello world", "x" * 90, "漢" * 40]:
            for w in (5, 20, 80):
                a = ts.wrap_cells(text, w)
                b = ["".join(t for t, _ in ln)
                     for ln in ts.wrap_styled(
                         [(x, ts.PAIR_TEXT) for x in text.split(" ")], w)]
                assert a == b


# ------------------------------------------------------------------ scaling
class TestScaling:
    def test_presence_interval_grows_with_headcount(self):
        vals = [ts.presence_interval(n) for n in (1, 10, 100, 1000, 5000)]
        assert vals == sorted(vals)
        assert all(v > 0 for v in vals)

    def test_ttl_exceeds_the_interval(self):
        for n in (1, 10, 100, 1000, 4000):
            assert ts.presence_ttl(n) > ts.presence_interval(n)

    @pytest.mark.parametrize("n", [0, -1, 10**9])
    def test_degenerate_headcounts(self, n):
        assert ts.presence_interval(n) > 0
        assert ts.presence_ttl(n) > 0
        assert ts.announce_interval(n) > 0


# -------------------------------------------------------------- door epochs
class TestEpochs:
    def test_epoch_is_stable_within_the_hour(self):
        base = (int(1_700_000_000 // ts.DOOR_EPOCH)) * ts.DOOR_EPOCH
        assert ts.door_epoch(base) == ts.door_epoch(base + ts.DOOR_EPOCH - 1)
        assert ts.door_epoch(base) + 1 == ts.door_epoch(base + ts.DOOR_EPOCH)

    def test_doors_differ_between_epochs(self, room):
        e = ts.door_epoch()
        now = {d.address for d in room.doors_at(e)}
        nxt = {d.address for d in room.doors_at(e + 1)}
        assert now.isdisjoint(nxt)
        assert len(now) == ts.DOORS

    def test_slot_index_is_preserved_across_rotation(self, room):
        e = ts.door_epoch()
        for i in range(ts.DOORS):
            assert room.doors_at(e)[i].slot == room.doors_at(e + 1)[i].slot == i

    def test_door_cache_does_not_grow_without_bound(self, room):
        for i in range(50):
            room.doors_at(ts.door_epoch() + i)
        assert len(room._doors) <= 8
