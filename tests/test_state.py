"""Filesystem, persistence and recovery. Clean state, create, corrupt,
reload, wipe - and check permissions along the way."""
import os, stat, sys, tempfile, shutil
import pytest
import talkshit as ts


class TestHomeCreation:
    def test_directories_are_private_at_every_level(self, tmp_path, monkeypatch):
        deep = str(tmp_path / "a" / "b" / "c")
        monkeypatch.setattr(ts, "HOME", deep)
        ts.ensure_home()
        node = deep
        for _ in range(3):
            mode = stat.S_IMODE(os.stat(node).st_mode)
            assert not mode & 0o077, f"{node} is {oct(mode)}"
            node = os.path.dirname(node)

    def test_is_idempotent(self, isolate_home):
        ts.ensure_home(); ts.ensure_home()
        assert os.path.isdir(isolate_home)

    def test_refuses_a_path_with_a_newline(self):
        with pytest.raises(ts.TorFailed):
            ts.torrc_value("/tmp/x\nControlPort 9051")

    @pytest.mark.parametrize("path", ["/tmp/plain", "C:/Users/A B/x", "/a'b"])
    def test_quotes_ordinary_paths(self, path):
        out = ts.torrc_value(path)
        assert out.startswith('"') and out.endswith('"')
        assert "\n" not in out


class TestBridges:
    def test_round_trip(self, isolate_home):
        lines = ["obfs4 1.2.3.4:80 CERT=abc", "5.6.7.8:9001"]
        ts.write_bridges(lines)
        assert ts.read_bridges() == lines

    def test_empty_write_clears(self, isolate_home):
        ts.write_bridges(["obfs4 1.2.3.4:80 CERT=abc"])
        ts.write_bridges([])
        assert ts.read_bridges() == []

    @pytest.mark.parametrize("evil", [
        "obfs4 1.2.3.4:80\nExitPolicy accept *:*",
        "obfs4 1.2.3.4:80\rBridge x",
        "obfs4 1.2.3.4:80\x00evil",
        "exec /bin/sh", "; rm -rf /", "$(id)", "`id`",
        "obfs4 " + "A" * 5000,
        "", "   ", "justoneword",
    ])
    def test_injection_and_junk_refused(self, evil):
        got = ts.clean_bridge(evil)
        assert got is None or ("\n" not in got and "\r" not in got
                               and "\x00" not in got)

    @pytest.mark.parametrize("good", [
        "1.2.3.4:9001", "[2001:db8::1]:9001",
        "obfs4 1.2.3.4:80 CERT=abc", "1.2.3.4:9001 ABCDEF",
    ])
    def test_real_bridge_lines_accepted(self, good):
        assert ts.clean_bridge(good) is not None

    def test_corrupt_bridge_file_does_not_crash(self, isolate_home):
        ts.write_bridges(["obfs4 1.2.3.4:80 CERT=abc"])
        with open(ts.BRIDGE_FILE, "wb") as f:
            f.write(b"\xff\xfe not text at all \x00\x00")
        assert isinstance(ts.read_bridges(), list)

    def test_missing_bridge_file(self, isolate_home):
        if os.path.exists(ts.BRIDGE_FILE):
            os.remove(ts.BRIDGE_FILE)
        assert ts.read_bridges() == []

    def test_no_automatic_clearnet_fetch(self, isolate_home, monkeypatch):
        """Fetching the built-in list before tor starts announces to the
        network exactly what bridges are for hiding."""
        reached = []
        monkeypatch.setattr(ts, "fetch_builtin_bridges",
                            lambda *a, **k: reached.append(1) or [])
        open(ts.BRIDGES_ON, "w").close()
        ts.ensure_bridges(lambda m: None)
        assert reached == []


class TestWipe:
    def test_removes_what_it_made(self, isolate_home, monkeypatch, capsys):
        ts.ensure_home()
        marker = os.path.join(isolate_home, "marker")
        open(marker, "w").write("x")
        monkeypatch.setattr(ts, "stored_home", lambda: isolate_home)
        monkeypatch.setattr(ts, "tools_home", lambda: isolate_home)
        ts.wipe()
        assert not os.path.exists(marker)

    def test_wipe_on_a_clean_machine_is_harmless(self, tmp_path, monkeypatch):
        gone = str(tmp_path / "never-existed")
        monkeypatch.setattr(ts, "stored_home", lambda: gone)
        monkeypatch.setattr(ts, "tools_home", lambda: gone)
        ts.wipe()


class TestTempSweeping:
    def test_a_symlink_is_not_followed(self, tmp_path, monkeypatch):
        precious = tmp_path / "precious"
        precious.mkdir()
        (precious / "keep.txt").write_text("do not delete")
        link = tempfile.gettempdir() + "/ts-" + os.urandom(4).hex()
        try:
            os.symlink(str(precious), link)
        except OSError:
            pytest.skip("cannot create symlinks here")
        try:
            ts.sweep_abandoned()
            assert (precious / "keep.txt").exists()
        finally:
            if os.path.islink(link):
                os.unlink(link)

    def test_a_live_pid_lock_is_left_alone(self):
        d = tempfile.mkdtemp(prefix="ts-")
        os.makedirs(os.path.join(d, "tordata"), exist_ok=True)
        with open(os.path.join(d, "tordata", "lock"), "w") as f:
            f.write(str(os.getpid()))
        try:
            ts.sweep_abandoned()
            assert os.path.isdir(d)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_a_junk_lock_does_not_crash(self):
        d = tempfile.mkdtemp(prefix="ts-")
        os.makedirs(os.path.join(d, "tordata"), exist_ok=True)
        with open(os.path.join(d, "tordata", "lock"), "w") as f:
            f.write("not-a-number\n../../etc")
        try:
            ts.sweep_abandoned()
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestProcessIdentification:
    def test_never_signals_an_unidentified_process(self):
        """This decides whether to send a kill. A stale lock file can outlive
        a reboot, and pids are reused."""
        assert ts.looks_like_tor(os.getpid()) is False
        assert ts.looks_like_tor(1) is False
        assert ts.looks_like_tor(999_999) is False

    @pytest.mark.parametrize("junk", [-1, 0, 2**40])
    def test_degenerate_pids(self, junk):
        assert ts.looks_like_tor(junk) is False


class TestArchiveSafety:
    @pytest.mark.parametrize("name", [
        "../escape", "/abs/path", "tor/../../etc/passwd", "..",
        "./../x", "tor\\..\\..\\win",
    ])
    def test_traversal_refused(self, tmp_path, name):
        assert not ts.safe_member(name, os.path.realpath(str(tmp_path)))

    @pytest.mark.parametrize("name", ["tor/tor", "tor/sub/file", "a/./b"])
    def test_ordinary_members_allowed(self, tmp_path, name):
        assert ts.safe_member(name, os.path.realpath(str(tmp_path)))

    def test_a_symlink_planted_earlier_cannot_be_written_through(self, tmp_path):
        root = os.path.realpath(str(tmp_path / "root"))
        outside = os.path.realpath(str(tmp_path / "outside"))
        os.makedirs(root); os.makedirs(outside)
        try:
            os.symlink(outside, os.path.join(root, "sneak"))
        except OSError:
            pytest.skip("cannot create symlinks here")
        assert not ts.safe_member("sneak/payload", root)


class TestFramingLimits:
    def test_download_and_unpack_caps_are_sane(self):
        assert 0 < ts.MAX_DOWNLOAD < 1 << 31
        assert ts.MAX_UNPACKED >= ts.MAX_DOWNLOAD

    def test_frame_cap_bounds_a_message(self):
        assert ts.MAX_FRAME > ts.MAX_TEXT


class TestCorruptState:
    """Every file the program reads back can be damaged between runs."""

    @pytest.mark.parametrize("payload", [
        b"\xff\xfe not text \x00\x00",
        b"\x00" * 4096,
        b"obfs4 1.2.3.4:80 CERT=abc\xff\xfe",
        os.urandom(2048),
    ])
    def test_corrupt_bridge_file(self, isolate_home, payload):
        ts.write_bridges(["obfs4 1.2.3.4:80 CERT=abc"])
        with open(ts.BRIDGE_FILE, "wb") as f:
            f.write(payload)
        assert isinstance(ts.read_bridges(), list)

    @pytest.mark.parametrize("payload", [
        b"", b"{", b"null", b"[]", b'{"lines": "not a list"}',
        b'{"fetched": "soon", "lines": []}', b"\xff\xfe\x00",
    ])
    def test_corrupt_auto_file(self, isolate_home, payload):
        with open(ts.AUTO_FILE, "wb") as f:
            f.write(payload)
        assert isinstance(ts.read_auto(), list)

    def test_bridge_file_that_is_a_directory(self, isolate_home):
        if os.path.exists(ts.BRIDGE_FILE):
            os.remove(ts.BRIDGE_FILE)
        os.makedirs(ts.BRIDGE_FILE, exist_ok=True)
        assert ts.read_bridges() == []

    def test_unreadable_bridge_file(self, isolate_home):
        ts.write_bridges(["obfs4 1.2.3.4:80 CERT=abc"])
        os.chmod(ts.BRIDGE_FILE, 0o000)
        try:
            assert isinstance(ts.read_bridges(), list)
        finally:
            os.chmod(ts.BRIDGE_FILE, 0o600)
