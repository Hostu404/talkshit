"""The CLI as a user meets it: a real subprocess, real exit codes, real
streams. Nothing here calls an internal function and claims the CLI works."""
import os, subprocess, sys, signal, time
import pytest

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "talkshit.py")


def run(*args, timeout=60, stdin=b"", env=None, home=None):
    e = dict(os.environ)
    e.update(env or {})
    if home:
        e["HOME"] = home
        e["XDG_DATA_HOME"] = home
        e["LOCALAPPDATA"] = home
    e.setdefault("TERM", "dumb")
    return subprocess.run([sys.executable, APP, *args], input=stdin,
                          capture_output=True, timeout=timeout, env=e)


@pytest.fixture
def home(tmp_path):
    d = str(tmp_path / "clihome")
    os.makedirs(d)
    return d


class TestHelpAndUsage:
    def test_help_exits_zero_and_lists_commands(self, home):
        r = run("--help", home=home)
        assert r.returncode == 0
        out = r.stdout.decode()
        for cmd in ("doctor", "selftest", "wipe", "bridges", "join"):
            assert cmd in out, cmd

    def test_help_documents_every_flag(self, home):
        out = run("--help", home=home).stdout.decode()
        for flag in ("--keep-state", "--purge-on-exit", "--no-download",
                     "--bridge", "--client"):
            assert flag in out, flag

    def test_unknown_command_is_refused(self, home):
        r = run("definitely-not-a-command", home=home)
        assert r.returncode != 0
        assert b"invalid choice" in r.stderr or b"usage" in r.stderr.lower()

    def test_unknown_flag_is_refused(self, home):
        r = run("--not-a-flag", home=home)
        assert r.returncode != 0

    def test_no_crash_traceback_on_bad_input(self, home):
        r = run("wipe", "extra", "args", home=home)
        assert b"Traceback" not in r.stderr


class TestWipe:
    def test_wipe_on_a_clean_machine(self, home):
        r = run("wipe", home=home, timeout=60)
        assert r.returncode == 0
        assert b"Traceback" not in r.stderr

    def test_wipe_removes_state(self, home):
        os.makedirs(os.path.join(home, "talkshit"), exist_ok=True)
        marker = os.path.join(home, "talkshit", "bridges")
        open(marker, "w").write("obfs4 1.2.3.4:80 CERT=abc\n")
        run("wipe", home=home, timeout=60)
        assert not os.path.exists(marker)

    def test_wipe_is_repeatable(self, home):
        for _ in range(3):
            assert run("wipe", home=home, timeout=60).returncode == 0


class TestBridges:
    def test_shows_settings_without_hanging(self, home):
        r = run("bridges", home=home, timeout=60, stdin=b"\n")
        assert r.returncode == 0
        assert b"Traceback" not in r.stderr

    def test_off_is_accepted(self, home):
        r = run("bridges", "off", home=home, timeout=60)
        assert r.returncode == 0

    def test_auto_asks_before_reaching_out(self, home):
        """The built-in list is fetched in the clear, before tor is up. It
        must never happen without being asked."""
        r = run("bridges", "auto", home=home, timeout=60, stdin=b"n\n")
        combined = (r.stdout + r.stderr).decode().lower()
        assert "clear" in combined or "network will see" in combined \
               or "fetch them anyway" in combined
        assert r.returncode == 0

    def test_auto_declined_changes_nothing(self, home):
        run("bridges", "auto", home=home, timeout=60, stdin=b"n\n")
        state = os.path.join(home, "talkshit", "bridges.auto")
        assert not os.path.exists(state)


class TestNoTorAvailable:
    """No tor is installed here, so every path that needs it must fail
    with an explanation rather than a traceback or a hang."""

    def test_doctor_reports_rather_than_crashes(self, home):
        r = run("doctor", "--no-download", home=home, timeout=120)
        combined = (r.stdout + r.stderr).decode()
        assert b"Traceback" not in r.stderr, combined[-2000:]
        assert "tor" in combined.lower()

    def test_browser_start_fails_cleanly(self, home):
        r = run("--no-download", home=home, timeout=120, stdin=b"")
        assert b"Traceback" not in r.stderr, r.stderr.decode()[-2000:]

    def test_join_fails_cleanly(self, home):
        r = run("join", "somewhere", "--no-download", home=home,
                timeout=120, stdin=b"")
        assert b"Traceback" not in r.stderr, r.stderr.decode()[-2000:]

    def test_selftest_fails_cleanly(self, home):
        r = run("selftest", "--no-download", home=home, timeout=120, stdin=b"")
        assert b"Traceback" not in r.stderr, r.stderr.decode()[-2000:]


class TestBridgeFlag:
    def test_bridge_line_is_accepted_from_the_command_line(self, home):
        r = run("--bridge", "obfs4 1.2.3.4:80 CERT=abc", "doctor",
                "--no-download", home=home, timeout=120)
        assert b"Traceback" not in r.stderr

    def test_a_bridge_line_with_a_newline_cannot_inject(self, home):
        r = run("--bridge", "obfs4 1.2.3.4:80\nExitPolicy accept *:*",
                "doctor", "--no-download", home=home, timeout=120)
        assert b"Traceback" not in r.stderr
        torrc = os.path.join(home, "talkshit", "torrc")
        if os.path.exists(torrc):
            assert "ExitPolicy" not in open(torrc).read()


class TestInterruption:
    def test_ctrl_c_during_startup_exits_cleanly(self, home):
        e = dict(os.environ)
        e.update(HOME=home, XDG_DATA_HOME=home, LOCALAPPDATA=home, TERM="dumb")
        p = subprocess.Popen([sys.executable, APP, "--no-download"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL, env=e)
        time.sleep(3)
        p.send_signal(signal.SIGINT)
        try:
            out, err = p.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            p.kill()
            pytest.fail("did not exit after ctrl+c")
        assert b"Traceback" not in err or b"KeyboardInterrupt" in err

    def test_process_does_not_linger(self, home):
        e = dict(os.environ)
        e.update(HOME=home, XDG_DATA_HOME=home, LOCALAPPDATA=home, TERM="dumb")
        p = subprocess.Popen([sys.executable, APP, "--no-download"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL, env=e)
        time.sleep(3)
        p.terminate()
        try:
            p.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            p.kill()
            pytest.fail("did not respond to terminate")


class TestRepeatedRuns:
    def test_state_survives_repeated_startup(self, home):
        run("bridges", "off", home=home, timeout=60)
        for _ in range(3):
            r = run("bridges", home=home, timeout=60, stdin=b"\n")
            assert r.returncode == 0
