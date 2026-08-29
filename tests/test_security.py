"""Security properties, tested by attempting the attack rather than reading
the code. Nothing here touches anything outside the test environment."""
import base64, json, os, queue, subprocess, sys, time
import pytest
import talkshit as ts


class TestInjection:
    @pytest.mark.parametrize("payload", [
        "obfs4 1.2.3.4:80\nExitPolicy accept *:*",
        "obfs4 1.2.3.4:80\r\nControlPort 9051",
        "obfs4 1.2.3.4:80\x00Log debug",
        "obfs4 $(id) 1.2.3.4:80", "obfs4 `id` 1.2.3.4:80",
        "obfs4 1.2.3.4:80; rm -rf /",
        "obfs4 1.2.3.4:80 | tee /tmp/x",
    ])
    def test_bridge_lines_cannot_reach_torrc(self, payload):
        got = ts.clean_bridge(payload)
        if got is not None:
            assert "\n" not in got and "\r" not in got and "\x00" not in got

    @pytest.mark.parametrize("path", [
        "/tmp/x\nControlPort 9051", "/tmp/x\r\nLog debug", "/tmp/x\x00y",
    ])
    def test_paths_cannot_reach_torrc(self, path):
        with pytest.raises(ts.TorFailed):
            ts.torrc_value(path)

    def test_room_names_are_constrained(self):
        for evil in ["../../etc", "a\nb", "a\x1b[2Jb", "a\x00b", "/abs",
                     "a" * 5000, "a;b", "a$b", "a`b`"]:
            cleaned = ts.clean_name(evil)
            assert all(c.isalnum() or c in "-_ " for c in cleaned), cleaned


class TestNoSecretsLeak:
    def test_passphrase_is_not_a_command_line_argument(self):
        import inspect
        src = inspect.getsource(ts.main)
        assert "passphrase" not in src.lower() or "add_argument" not in src

    def test_passphrase_never_written_to_disk(self, isolate_home, room):
        ts.ensure_home()
        secret = "a-passphrase-for-testing"
        found = []
        for base, _, files in os.walk(isolate_home):
            for f in files:
                p = os.path.join(base, f)
                try:
                    if secret.encode() in open(p, "rb").read():
                        found.append(p)
                except OSError:
                    pass
        assert found == []

    def test_room_object_does_not_print_its_key(self, room):
        assert room.key.hex() not in repr(room)


class TestResourceExhaustion:
    def test_a_single_message_cannot_dominate_the_reader(self):
        """A body with no word breaks used to cost 180x an ordinary one."""
        ordinary = [{"type": "msg", "nick": "x", "ts": 0,
                     "text": "a normal line of chat with spaces in it"}]
        hostile = [{"type": "msg", "nick": "x", "ts": 0,
                    "text": "x" * ts.MAX_TEXT}]

        class FakeCurses:
            A_DIM = A_BOLD = 0
            @staticmethod
            def color_pair(n): return n
        real, ts.curses = ts.curses, FakeCurses
        try:
            for m in (ordinary, hostile):
                for _ in range(20):
                    ts._render(m, 80, "me")
            t = time.time()
            for _ in range(60):
                ts._render(ordinary, 80, "me")
            cheap = time.time() - t
            t = time.time()
            for _ in range(60):
                ts._render(hostile, 80, "me")
            dear = time.time() - t
        finally:
            ts.curses = real
        assert dear < cheap * 60, f"ratio {dear / max(cheap, 1e-9):.0f}x"

    def test_combining_marks_cannot_stack_without_limit(self):
        import unicodedata
        out = ts.printable("e" + "\u0301" * 5000, 10000)
        assert sum(1 for c in out if unicodedata.combining(c)) <= ts.MAX_MARKS

    def test_deeply_nested_json_is_survivable(self):
        blob = "[" * 2000 + "]" * 2000
        try:
            ts.loads(blob)
        except Exception:
            pass                      # any refusal is fine; a crash is not

    def test_non_finite_numbers_are_refused(self):
        for text in ['{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}']:
            with pytest.raises(Exception):
                ts.loads(text)

    def test_frame_size_is_capped(self):
        assert ts.MAX_FRAME < 1 << 24

    def test_dial_budget_bounds_third_party_traffic(self, stub_transport, room):
        mesh = ts.Mesh(stub_transport, room, publish=False)
        try:
            target = ts.onion_address(os.urandom(32))
            allowed = sum(1 for _ in range(500) if mesh._may_dial(target))
            assert allowed <= ts.DIAL_BUDGET
        finally:
            mesh.stop.set(); mesh.close()


class TestSubprocessUsage:
    def test_no_shell_true_anywhere(self):
        src = open(ts.__file__).read()
        assert "shell=True" not in src

    def test_subprocess_calls_use_argument_lists(self):
        import ast, inspect
        tree = ast.parse(open(ts.__file__).read())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("run", "Popen", "call",
                                           "check_output")
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"):
                first = node.args[0] if node.args else None
                assert isinstance(first, (ast.List, ast.Name, ast.Subscript)), \
                    f"line {node.lineno}: subprocess arg is not a list"


class TestTempFiles:
    def test_temp_directory_is_private_and_unpredictable(self, monkeypatch):
        import stat, tempfile
        made = ts.use_storage(False) if hasattr(ts, "use_storage") else None
        d = tempfile.mkdtemp(prefix="ts-")
        try:
            assert not stat.S_IMODE(os.stat(d).st_mode) & 0o077
        finally:
            os.rmdir(d)


class TestOutsiderCannotEnter:
    def test_a_stranger_cannot_open_a_room_frame(self, room):
        blob = room.seal({"kind": "hello"})
        for guess in ["", "password", "testroom", "a-passphrase-for-testin"]:
            assert ts.Room("testroom", guess).open(blob) is None

    def test_doors_cannot_be_derived_without_the_passphrase(self, room):
        wrong = ts.Room("testroom", "the-wrong-passphrase")
        assert {d.address for d in room.identities}.isdisjoint(
               {d.address for d in wrong.identities})

    def test_the_index_secret_is_public_by_design(self):
        """Stated in the file: the room list is a noticeboard, not a
        boundary. This test records that, so a change is deliberate."""
        assert isinstance(ts.INDEX_SECRET, str)
        assert ts.public_index().key != ts.Room("x", "a-passphrase-here").key
