# Test suite

    pip install pytest hypothesis pytest-timeout pytest-cov
    python3 -m pytest tests/ -q --timeout=400

338 tests. Everything is isolated: `conftest.py` redirects the app's storage
to a temporary directory, refuses any real network call, and fails a test
that leaves a thread running.

| File | What it covers |
|---|---|
| `test_helpers.py` | pure functions - sanitising, folding, onion validation, passphrase rules, wrapping, epochs |
| `test_crypto.py` | key separation, AEAD, signatures, canonicalisation, link keys, padding |
| `test_protocol.py` | dispatch, dedup, rate limits, roster, gossip, faults |
| `test_state.py` | filesystem, permissions, bridges, corrupt state, archive safety, pid identification |
| `test_cli.py` | the CLI as a subprocess - exit codes, streams, interruption |
| `test_concurrency.py` | shutdown, leaks, concurrent dispatch, unbounded growth |
| `test_security.py` | injection, secrets, resource exhaustion, subprocess usage |
| `test_properties.py` | Hypothesis invariants for parsers, wrapping, crypto, folding |

## Not covered here

No Tor binary and no general network egress in this environment, so the Tor
bootstrap, control port, SOCKS negotiation, download and bridge fetch are
exercised only through stubs. There is no TTY, so curses drawing is tested by
calling `_render` directly rather than by driving a terminal. Two machines on
two networks remains untested by anything.

Run `python3 talkshit.py doctor` and `selftest` on a real machine for those.
