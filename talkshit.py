#!/usr/bin/env python3
"""
talk shit - serverless encrypted chatrooms over tor.

    python3 talkshit.py           browse rooms, search, create or join
    python3 talkshit.py join NAME  go straight into a room by name, without
                                  listing it publicly - the passphrase is the
                                  only way in
    python3 talkshit.py --client  take part without hosting (phones, locked
                                  down networks, or when publishing fails)
    python3 talkshit.py --keep-state  keep tor's state between runs (only
                                  needed if tor is not installed)
    python3 talkshit.py doctor    check tor and report what works
    python3 talkshit.py selftest  two tors, a real room, a real message
    python3 talkshit.py bridges   bridge settings (off by default)
    python3 talkshit.py wipe      remove everything it put on disk

There is no server. A room's passphrase derives a small fixed set of v3 onion
addresses - its doors. Everyone holding the passphrase computes the same
doors, the first arrivals claim them, and later arrivals knock on them to get
in. Without the passphrase you cannot compute a single door, so a room is not
merely private but unlocatable.

The doors are the way in, not the size of the room. Once inside, peers pass
each other's addresses over the encrypted link, so a peer that could not get
a door publishes an address of its own and is found by word of mouth. That
is what lets a room grow past its doors: joining costs sixteen probes whether
there are six people inside or six thousand.

Each peer keeps about eight links regardless of room size and relays what it
receives, so a thousand person room costs roughly eight thousand circuits
rather than the million a full mesh would need. Presence works the same way:
the heartbeat interval widens as the room fills, so the background traffic a
peer sees stays flat instead of growing with the headcount.

The public room list works the same way from a constant built into this file:
the first peers online claim the doors, everyone else finds them. It shows a
room name and a headcount, nothing more. Entries live on a short lease, so a
room disappears seconds after the last person leaves. Nothing is written to
disk but tor's own state and your bridge settings.

No address is ever displayed, and peers reach each other only through tor
circuits, so nobody learns anybody's ip.

WHAT THIS PROTECTS, ASSUMING THE READER HAS THIS FILE
    Nothing depends on the source being secret. A room's security is its
    passphrase and nothing else. Knowing the code, the protocol, and a
    room's name gets an attacker no closer to it.

    Message contents   sealed twice: an ephemeral X25519 session key per
                       link, inside a room key from the passphrase. Session
                       keys never touch disk, so traffic recorded today
                       stays unreadable even if the passphrase leaks later.
    Who is speaking    every body is Ed25519 signed. A handle belongs to
                       the key that used it first; anyone else asking for
                       it is shown with a fingerprint attached.
    Your address       peers meet only over tor circuits, and each room
                       uses a fresh signing key, so two rooms cannot be
                       tied to one person.
    Finding a room     doors come from the passphrase, so a room cannot be
                       located or probed without it. Addresses passed by
                       word of mouth travel only inside the room's own
                       encryption, so they never leave the membership.

WHAT IT DOES NOT PROTECT
    The room list is public and unauthenticated by design. Anyone can list
    a room, inflate a headcount, or squat doors. Rooms are reached through
    the list, so whoever holds the doors can hide a room from people who do
    not already know it is there.

    A weak passphrase defeats everything above, because room names are
    public and a short one can be ground out offline until the doors match.
    Generated passphrases are ~50 bits; that is the intended floor.

    Anyone holding a passphrase is a full member and can flood, lie about
    the room being full, or walk away still knowing it. Removing someone
    means a new passphrase. Members also learn each other's onion addresses
    - as they always did, since derived doors were computable by anyone
    holding the passphrase anyway.

    Tor is the anonymity boundary. An adversary watching both ends is out
    of scope here, as it is for tor generally.

    Tor connects directly by default, so whoever runs your network can see
    that you use tor - not who you talk to or what you say. 'bridges' turns
    that off, either with the built-in list fetched from the tor project or
    with lines you supply. Bridges are also what gets you onto tor from a
    network that blocks it. They are not the default because the shared
    built-in ones are widely blocked and often leave tor stalled at 75%.

    The bundled tor download is checksum verified but not signature
    verified. Installing tor from your distro is the stronger path.

WHAT IT LEAVES BEHIND
    Nothing of what was said. No transcript, no room names, no handles, no
    keys: all of it lives in memory and dies with the process. The chat
    draws on the terminal's alternate screen, so it is not in scrollback
    either.

    Tor itself has to exist somewhere. If it is installed, nothing of ours
    is ever written to disk. If it is not, and the machine has a package
    manager, you are shown the one command that installs it and asked
    before anything is downloaded. Only where there is no package manager
    to use - a plain windows box, typically - is a copy fetched without
    asking, and even then the folder holds the program alone.

    Nothing is kept between runs. Tor needs a state directory, so one is
    made in the system temp area at startup and deleted on the way out -
    there is no talk shit folder anywhere afterwards. That costs a fresh
    set of entry guards every run, which tor's design considers worse for
    anonymity over time; --keep-state trades the other way and puts that
    state in the platform's app-data folder. It is also the only way to
    have talk shit download tor for you, since a download needs somewhere
    to live. With tor installed by a package manager, nothing persists.

    Two things no program can clean up for you: your shell history, which
    records that you ran this, and the passphrase in memory - python
    strings are immutable and cannot be wiped after use, so a memory dump
    of a running process could recover one.

Needs: pip install cryptography     (Windows also: pip install windows-curses)
Tor is used if installed, otherwise fetched once into the platform's
app-data folder after asking.
"""

from __future__ import annotations

import argparse
import base64
import collections
import getpass
import glob
import hashlib
import json
import locale
import math
import os
import platform
import queue
import random
import re
import atexit
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unicodedata
import urllib.request

try:
    import curses
except ImportError:
    sys.exit("this needs curses:  pip install windows-curses")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives import serialization
except ImportError:
    sys.exit("missing dependency:  pip install cryptography")

# Nothing is kept between runs unless you ask for it. HOME is a temporary
# directory created at startup and deleted on exit; --keep-state swaps it for
# a real one, which is only needed if tor has to be downloaded.
HOME = ""
_TEMP_ROOT = ""
BRIDGE_FILE = AUTO_FILE = BRIDGES_ON = ""
CLI_BRIDGES: list = []
NO_DOWNLOAD = False


def stored_home() -> str:
    """Where a kept-state install lives - the platform's own place for it,
    not a dotfile dropped in your home directory."""
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "talkshit")
    if sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library",
                            "Application Support", "talkshit")
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "talkshit")


def tools_home() -> str:
    """Where a downloaded tor lives. Separate from state on purpose: the
    program is just a program, no more telling than any other installed app.
    Nothing about your use of it is kept here - no state, no bridges, no
    record that a room was ever opened."""
    return stored_home()


def _bind_paths() -> None:
    global BRIDGE_FILE, AUTO_FILE, BRIDGES_ON
    BRIDGE_FILE = os.path.join(HOME, "bridges")
    AUTO_FILE = os.path.join(HOME, "bridges.auto")
    BRIDGES_ON = os.path.join(HOME, "bridges.on")


def use_storage(keep: bool) -> None:
    global HOME, _TEMP_ROOT
    if keep:
        HOME = stored_home()
    else:
        sweep_abandoned()
        HOME = _TEMP_ROOT = tempfile.mkdtemp(prefix="ts-")
    _bind_paths()


_SHUTTING_DOWN = threading.Lock()
_LIVE_TORS: list = []
PURGE_TOR = False


def shutdown(*_args) -> None:
    """Everything that must happen however we leave: normally, on ctrl-c, on
    a killed terminal, or when the window is closed with the mouse. Idempotent,
    because several of those can arrive at once."""
    if not _SHUTTING_DOWN.acquire(blocking=False):
        return
    try:
        for running in list(_LIVE_TORS):
            running.stop()
        if PURGE_TOR and os.path.isdir(tools_home()):
            shutil.rmtree(tools_home(), ignore_errors=True)
        release_storage()
    except Exception:
        pass


def watch_for_exit() -> None:
    """Closing a terminal window does not run finally blocks. On unix that
    arrives as a hangup; on windows it is a console control event, which
    python does not surface, so it is taken from kernel32 directly."""
    atexit.register(shutdown)
    for name in ("SIGTERM", "SIGHUP", "SIGBREAK", "SIGQUIT"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, lambda *_: (shutdown(), os._exit(0)))
        except (ValueError, OSError):
            pass
    if sys.platform.startswith("win"):
        try:
            import ctypes
            handler = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint)(
                lambda event: (shutdown(), os._exit(0), 1)[2])
            _WIN_HANDLERS.append(handler)      # must outlive this function
            ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True)
        except Exception:
            pass


_WIN_HANDLERS: list = []


def sweep_abandoned() -> None:
    """A run killed outright cannot tidy up after itself, so clear anything an
    earlier one left in the temp area before making our own."""
    for path in glob.glob(os.path.join(tempfile.gettempdir(), "ts-*")):
        if os.path.islink(path) or not os.path.isdir(path):
            continue                    # a planted symlink is not ours to follow
        lock = os.path.join(path, "tordata", "lock")
        try:
            if os.path.isfile(lock):
                with open(lock) as f:
                    pid = int(f.read().strip() or "0")
                if pid > 0:
                    os.kill(pid, 0)
                    continue            # still in use by a running copy
        except (OSError, ValueError):
            pass                        # no lock, or the holder is gone
        try:
            if time.time() - os.path.getmtime(path) > 60:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass


def release_storage() -> None:
    """Called on the way out. With temporary storage this is the whole of it:
    no directory, no leftovers, nothing to wipe."""
    global _TEMP_ROOT
    if _TEMP_ROOT:
        shutil.rmtree(_TEMP_ROOT, ignore_errors=True)
        _TEMP_ROOT = ""


ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"
ONION_VERSION = b"\x03"
VIRTUAL_PORT = 80

SCRYPT_N = 2 ** 16       # offline guessing cost for a room passphrase
PAD_TO = 256             # message bodies are padded to a multiple of this

# Doors are the way into a room, not its capacity. A fixed, small number of
# them is what keeps joining cheap however large the room grows: everyone
# probes these and nothing else, and the people behind them hand out the
# addresses of everyone else.
DOORS = 16
DOOR_EPOCH = 3600.0      # doors move to fresh addresses this often
DOOR_OVERLAP = 600.0     # and the old ones stay up this long after they do
DOOR_PATIENCE = 90.0     # a link that answers but never speaks is not a peer
ROOM_LIMIT = 100000      # a ceiling on memory, not a design limit on people


def door_epoch(when: float | None = None) -> int:
    """Which set of doors is current. Derived from the clock alone, so every
    holder of the passphrase agrees without anyone coordinating."""
    return int((time.time() if when is None else when) // DOOR_EPOCH)

HEARTBEAT = 45.0         # presence ping in a small room; widens as it fills
PRESENCE_BUDGET = 32     # people whose heartbeats one peer should carry
LINK_IDLE = 900.0        # a circuit silent this long is closed
FANOUT = 8               # links each peer opens, whatever the room size
MAX_LINKS = FANOUT * 3   # and accepts. a link costs a slot at each end, so
                         # this has to sit well above twice FANOUT or the
                         # graph saturates and stragglers never get in
COLD_FOR = 20.0          # first pass-over of a refused address; then doubles
COLD_MAX = 600.0         # but never longer than this
FRESH_DROP = 15.0        # a link lost this fast was a refusal, not a peer
INDEX_SECRET = "talk shit public index v1"
PROTOCOL = 1             # bumped when the wire format changes. this is an open
                         # file and forks are expected, so peers say which one
                         # they speak: without it a fork that alters padding or
                         # the key schedule still agrees keys, then drops every
                         # message it is sent, and looks exactly like an empty
                         # room to both sides
ANNOUNCE_EVERY = 30.0    # room announce in a quiet index; widens as it fills
ANNOUNCE_BUDGET = 64     # rooms whose announcements one peer should carry
MAX_TEXT = 2000
MAX_FRAME = 64 * 1024    # a peer that sends more than this per line is dropped
MAX_QUEUE = 256          # outbound backlog per link before we give up on it
MAX_ROSTER = 4096        # cap on remembered handles, so nobody can flood it
MAX_ENTRIES = 4000       # cap on index entries, likewise
MAX_KNOWN = 4096         # cap on gossiped peer addresses
KNOWN_TTL = 1800.0       # a gossiped address unheard of this long is dropped
PEER_SAMPLE = 12         # addresses handed over in one word-of-mouth message
GOSSIP_PER_PEER = 64     # addresses one peer may put into our head per window
GOSSIP_WINDOW = 300.0    # over this long, so nobody can fill it on their own
CORROBORATED = 2         # sources before an address is preferred when dialling
DIAL_BUDGET = 24         # circuits opened to addresses we were merely told
DIAL_WINDOW = 60.0       # about, per window. nothing in a gossiped address
                         # says it belongs to a peer, so a room told to dial
                         # somebody else's hidden service will do it - once
                         # per member, which for a large room is a crowd
                         # arriving at a stranger's door. door probing is
                         # bounded by the door count and is not counted here
GOSSIP_EVERY = 40.0
PUSH_SAMPLE = 48         # index entries pushed to a new link at once
CLOCK_SLACK = 300.0      # bodies older or newer than this are refused
MAX_SEEN = 20000         # message ids remembered for duplicate suppression
RATE_LIMIT = 150         # new bodies per window from one identity
LINK_RATE_LIMIT = 600    # and per circuit, whatever identities they use
NEW_KEYS_PER_WINDOW = 32 # fresh identities one circuit may introduce per
                         # window. minting a key costs a tenth of a millisecond
                         # so a per-key limit is no limit, but capping how many
                         # distinct keys a circuit may carry is worse: a circuit
                         # relays for everybody, so that caps the room itself -
                         # and did, at 64 people. rate of arrival is the tell
NEW_KEY_BUDGET = 30      # bodies a just-met key may send until it settles.
                         # not tight, deliberately: every identity in the room
                         # is new to a circuit the moment it opens, so a mean
                         # allowance here throttles a joiner's whole first
                         # minute. LINK_RATE_LIMIT is the real ceiling - this
                         # only stops one identity laundering through many
KX_PATIENCE = 20.0       # a circuit that never agrees keys is not a peer
RATE_WINDOW = 10.0
INDEX_PER_KEY = 5        # rooms one announcer may list, so nobody floods it
PROBE_TIMEOUT = 75.0     # a slow onion must not be read as an empty door
CONFIRM_TIMEOUT = 120.0  # a door is only read as free after timing out
                         # twice, so the total patience is what protects a
                         # live door - not the length of any single wait.
                         # stretching the first wait to 150s only meant a
                         # dial that missed sat there for two and a half
                         # minutes before anything retried it   # the second look, before believing a door is free
PROBE_WAVE = 8           # doors tried at once when topping up connections.
                         # this one runs every half minute for as long as the
                         # room is open, so it stays modest
JOIN_WAVE = DOORS        # but the first sweep tries every door at once. it
                         # happens once, and splitting it means proving eight
                         # addresses unpublished - the slowest thing tor does -
                         # before even dialling the one somebody is behind
RESCAN_EVERY = 30.0      # how often to top up connections
DOOR_BACKOFF = 5         # rescans between knocking on the doors again
CLAIM_SETTLE = (5.0, 15.0)   # pause before checking a claimed door is ours alone
BROWSE_TICK = 400        # ms between browser redraws
JOIN_PATIENCE = 180.0    # how long to wait on the doors before giving up. tor
                         # took 112s to find a peer in testing, so the old 25
                         # second countdown was quitting on rooms that worked
FIND_EVERY = 1.5         # seconds between asking the network about a search
PAUSE_GUARD = 0.5        # seconds a held message ignores keys already typed
PAUSE_LIMIT = 300.0      # but never wait forever for one
DEFAULT_NICK = "anon"
SETTLE_HOLD = 30.0       # how long a message waits for a link that is still
                         # agreeing keys. seconds, not minutes: long enough to
                         # cover a handshake, too short to surprise anybody
MAX_MARKS = 3            # combining marks allowed to stack on one character
MIN_PASSPHRASE = 12      # short ones can be ground out offline; names are public
PASSPHRASE_LEN = 12      # 12 x 5 bits = 60. at ten it was 50, and fifty bits
                         # against a memory-hard hash is roughly four months
                         # for somebody with a hundred thousand GPUs. two more
                         # characters is a thousand times the work for them
                         # and two more keystrokes for everybody else


def presence_interval(count: int) -> float:
    """One heartbeat per peer, flooded to every peer, is the one thing here
    that grows with the square of the room: a thousand people pinging every
    forty five seconds is twenty two messages a second of pure presence,
    relayed to everyone, before anybody has said anything. So the interval
    widens with the headcount. A handful of people ping briskly; a thousand
    ping rarely; what each peer actually carries stays roughly flat."""
    return HEARTBEAT * max(1.0, count / PRESENCE_BUDGET)


def presence_ttl(count: int) -> float:
    """Silence only means gone after a few missed heartbeats, so this has to
    follow the interval rather than being a constant."""
    return presence_interval(count) * 3.5


def announce_interval(rooms: int) -> float:
    """The same trick for the room list, which is a flood of its own."""
    return ANNOUNCE_EVERY * max(1.0, rooms / ANNOUNCE_BUDGET)


# ==========================================================================
# onion identities derived from a secret
# ==========================================================================

def onion_address(pub: bytes) -> str:
    checksum = hashlib.sha3_256(b".onion checksum" + pub + ONION_VERSION).digest()[:2]
    return base64.b32encode(pub + checksum + ONION_VERSION).decode().lower() + ".onion"


def valid_onion(address: str) -> bool:
    """One address, one spelling.

    replace(".onion", "") struck the suffix wherever it appeared and however
    often, so 'x.onion.onion' and a bare 'x' both passed and both named the
    same service. Cooldowns, dial budgets and the address book are all keyed
    on the string, so several spellings of one address meant several helpings
    of every limit that was supposed to bound it."""
    if not isinstance(address, str) or not address.endswith(".onion"):
        return False
    stem = address[:-len(".onion")]
    if stem != stem.lower() or not stem.isalnum():
        return False
    try:
        raw = base64.b32decode(stem.upper())
    except Exception:
        return False
    if len(raw) != 35 or raw[34:35] != ONION_VERSION:
        return False
    return raw[32:34] == hashlib.sha3_256(
        b".onion checksum" + raw[:32] + ONION_VERSION).digest()[:2]


def expanded_secret(seed: bytes) -> bytes:
    """Tor's ED25519-V3 control key is the clamped sha512 expansion."""
    h = bytearray(hashlib.sha512(seed).digest())
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)


class OnionIdentity:
    def __init__(self, key: bytes, label: bytes, slot: int, epoch: int = 0):
        self.slot, self.epoch = slot, epoch
        self.seed = hashlib.sha256(b"talkshit:onion:" + label + b":" + key
                                   + slot.to_bytes(2, "big")
                                   + epoch.to_bytes(8, "big")).digest()
        priv = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.address = onion_address(self.pub)
        self.control_key = "ED25519-V3:" + base64.b64encode(
            expanded_secret(self.seed)).decode()


def private_identity() -> OnionIdentity:
    """An address belonging to nobody in particular, for a peer that could not
    get a door. It is not derived from the passphrase, so it is reachable only
    by people who were told about it - which is exactly the room."""
    return OnionIdentity(os.urandom(32), b"peer", 0)


# ==========================================================================
# secrets
# ==========================================================================

class Secret:
    label = b"secret"
    door_count = DOORS

    def __init__(self, name: str, passphrase: str):
        self.name = name.strip().lower()[:32]
        self.key = hashlib.scrypt(passphrase.encode("utf-8"),
                                  salt=b"talkshit:" + self.label + b":" + self.name.encode(),
                                  n=SCRYPT_N, r=8, p=1, dklen=32, maxmem=192 << 20)
        self.aead = AESGCM(self.key)
        # a short public tag for the room itself, so the index can tell two
        # rooms that picked the same name apart. derived from the key, which
        # already takes a scrypt run to reach, so it gives an attacker nothing
        # the doors did not already give them
        self.fingerprint = hashlib.sha256(b"talkshit:fp:" + self.key).hexdigest()[:12]
        self._doors: dict[int, list[OnionIdentity]] = {}
        self._door_lock = threading.Lock()

    def doors_at(self, epoch: int) -> list[OnionIdentity]:
        """The doors for one epoch. Cheap once derived - the expensive part
        was the scrypt run that produced the key, and that happened once."""
        with self._door_lock:
            have = self._doors.get(epoch)
            if have is None:
                have = [OnionIdentity(self.key, self.label, i, epoch)
                        for i in range(self.door_count)]
                self._doors[epoch] = have
                for old in [e for e in self._doors if abs(e - epoch) > 2]:
                    del self._doors[old]
            return have

    @property
    def identities(self) -> list[OnionIdentity]:
        return self.doors_at(door_epoch())

    def seal(self, obj: dict) -> bytes:
        nonce = os.urandom(12)
        return nonce + self.aead.encrypt(nonce, json.dumps(obj).encode("utf-8"), self.label)

    def open(self, blob: bytes) -> dict | None:
        try:
            obj = loads(self.aead.decrypt(blob[:12], blob[12:], self.label))
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None


class Room(Secret):
    label = b"room"


class PublicIndex(Secret):
    """Not secret at all - the constant is in this file, by design."""
    label = b"index"

    def __init__(self):
        super().__init__("public", INDEX_SECRET)


class Identity:
    """Ephemeral keys for this run. Generated in memory, never written down,
    gone when the process exits - which is what makes the traffic forward
    secret: a passphrase leaking later cannot decrypt anything recorded."""

    def __init__(self):
        self.x = X25519PrivateKey.generate()
        self.xpub = self.x.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.ed = Ed25519PrivateKey.generate()
        self.edpub = self.ed.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.fingerprint = hashlib.sha256(self.edpub).hexdigest()[:8]

    def sign(self, payload: bytes) -> bytes:
        return self.ed.sign(payload)


def _no_specials(text: str):
    """json accepts NaN and Infinity by default, and neither survives contact
    with the rest of this program: NaN compares false against everything, so a
    NaN timestamp slips straight through the replay window and then throws when
    the clock tries to format it, and Infinity overflows the headcount. No
    honest peer sends either, so refuse the whole body."""
    raise ValueError(f"refusing json constant {text}")


def loads(raw) -> object:
    return json.loads(raw, parse_constant=_no_specials)


def signed_bytes(obj: dict) -> bytes:
    """Canonical form that the signature covers - everything but the signature."""
    return json.dumps({k: v for k, v in sorted(obj.items()) if k != "sig"},
                      separators=(",", ":")).encode("utf-8")


def pad_body(raw: bytes) -> bytes:
    """Round every body up to a multiple of PAD_TO so lengths leak less. The
    separator counts towards the total, so the padding is measured from
    len(raw) + 1 - it was a byte out, and every body came off one short of a
    round number."""
    room = (-len(raw) - 1) % PAD_TO
    return raw + b"\n" + b"\0" * room


def unpad_body(raw: bytes) -> bytes:
    """Take the padding off the end rather than cutting at the first
    separator. Splitting on the first newline threw away everything after
    one, so any body containing 0x0a came back truncated. Nothing sends such
    a body today - compact json escapes its newlines - but a silent
    truncation in a primitive is a trap laid for whoever changes that. The
    trailing NULs are the padding; the newline before them is the separator;
    a body's own trailing NULs are safe behind it."""
    body = raw.rstrip(b"\0")
    return body[:-1] if body.endswith(b"\n") else body


def link_keys(private: X25519PrivateKey, mine: bytes, theirs: bytes,
              salt: bytes) -> tuple[AESGCM, AESGCM]:
    shared = private.exchange(X25519PublicKey.from_public_bytes(theirs))
    material = HKDF(algorithm=SHA256(), length=64, salt=salt,
                    info=b"talkshit link v1").derive(shared)
    first, second = AESGCM(material[:32]), AESGCM(material[32:])
    # both ends must agree which key is whose, so order by public key
    return (first, second) if mine < theirs else (second, first)


_PUBLIC: "PublicIndex | None" = None
_PUBLIC_LOCK = threading.Lock()


def public_index() -> "PublicIndex":
    """Derived from a constant, so it is worth computing only once - and it
    can be warmed up while tor is still booting."""
    global _PUBLIC
    with _PUBLIC_LOCK:
        if _PUBLIC is None:
            _PUBLIC = PublicIndex()
        return _PUBLIC


def new_passphrase(n: int = PASSPHRASE_LEN) -> str:
    rng = random.SystemRandom()
    return "".join(rng.choice(ALPHABET) for _ in range(n))


# ==========================================================================
# tor: find it, fetch it, run it
# ==========================================================================

class SocksError(OSError):
    def __init__(self, message: str, code: int = 0):
        super().__init__(message)
        self.code = code


# 0x01-0x08 are the standard replies. 0xF0 upwards are tor's own, which it
# only sends when the socks listener was opened with ExtendedErrors - and
# they are the difference between "nobody has ever published this address"
# and "somebody is there but the circuit did not come up".
SOCKS_ERRORS = {1: "general failure", 2: "not allowed", 3: "network unreachable",
                4: "host unreachable", 5: "refused", 6: "ttl expired",
                7: "command not supported", 8: "bad address type",
                0xF0: "onion descriptor not found",
                0xF1: "onion descriptor invalid",
                0xF2: "onion introduction failed",
                0xF3: "onion rendezvous failed",
                0xF4: "onion client auth missing",
                0xF5: "onion client auth wrong",
                0xF6: "onion address invalid",
                0xF7: "onion introduction timed out"}

# The only reply that means an address is genuinely unused. Everything else,
# including plain host-unreachable, may well be a live peer having a bad
# minute, and claiming its address would put two peers on one door.
NO_SUCH_ONION = {0xF0}
# The onion is there; the circuit to it did not complete. Rendezvous is the
# flakiest part of tor and fails like this routinely - tor's own client simply
# tries again. Treating these as "occupied, move on" meant a door with somebody
# behind it was written off on one bad attempt and never dialled again.
TRANSIENT_ONION = {0xF2, 0xF3, 0xF7}


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise SocksError("closed early")
        buf += chunk
    return buf


def socks5_connect(proxy_port: int, host: str, port: int = VIRTUAL_PORT,
                   timeout: float = 45.0,
                   auth: tuple | None = None,
                   on_socket=None) -> socket.socket:
    """Open a stream through tor.

    The credentials are not a password - tor does not check them. They pick
    which bundle of circuits the stream belongs to, because IsolateSOCKSAuth
    is on by default. Offering none put every room and the public index, which
    anybody at all may join, into one bundle sharing circuits: a relay on that
    circuit would see both, and being in two rooms at once would be one fact
    rather than two. A credential per mesh keeps them apart."""
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    if on_socket:
        on_socket(s)             # the wait is ahead of us, not behind: tor
    try:                         # builds the circuit during the negotiation
        if auth:
            user, password = (str(a).encode()[:255] for a in auth)
            s.sendall(b"\x05\x01\x02")
            if s.recv(2) != b"\x05\x02":
                raise SocksError("socks refused isolation credentials")
            s.sendall(b"\x01" + bytes([len(user)]) + user
                      + bytes([len(password)]) + password)
            reply = _recv_exact(s, 2)
            if reply[1] != 0:
                raise SocksError("socks rejected the isolation credentials")
        else:
            s.sendall(b"\x05\x01\x00")
            if s.recv(2) != b"\x05\x00":
                raise SocksError("socks handshake refused")
        name = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
        head = _recv_exact(s, 4)
        if head[1] != 0:
            raise SocksError(SOCKS_ERRORS.get(head[1], f"socks error {head[1]}"),
                             head[1])
        atyp = head[3]
        if atyp == 1:
            _recv_exact(s, 6)
        elif atyp == 3:
            _recv_exact(s, _recv_exact(s, 1)[0] + 2)
        elif atyp == 4:
            _recv_exact(s, 18)
        s.settimeout(None)
        return s
    except Exception:
        s.close()
        raise


class Control:
    def __init__(self, port: int, cookie_path: str):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=20)
        self.f = self.sock.makefile("rwb")
        with open(cookie_path, "rb") as fh:
            self.cmd("AUTHENTICATE " + fh.read().hex())

    def cmd(self, line: str) -> list[str]:
        self.f.write(line.encode() + b"\r\n")
        self.f.flush()
        out = []
        while True:
            raw = self.f.readline()
            if not raw:
                raise OSError("control connection closed")
            text = raw.decode(errors="replace").rstrip("\r\n")
            code, sep, rest = text[:3], text[3:4], text[4:]
            out.append(rest)
            if sep == " ":
                if not code.startswith("2"):
                    raise OSError(f"tor said: {text}")
                return out

    def add_onion(self, key: str, local_port: int) -> str:
        for line in self.cmd(f"ADD_ONION {key} Port={VIRTUAL_PORT},127.0.0.1:{local_port}"):
            if line.startswith("ServiceID="):
                return line.split("=", 1)[1] + ".onion"
        raise OSError("tor returned no service id")

    def del_onion(self, address: str) -> None:
        try:
            self.cmd("DEL_ONION " + address.replace(".onion", ""))
        except OSError:
            pass

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def ensure_home(path: str = "") -> str:
    """Create our directories at 0700. os.makedirs only applies its mode to
    the final component, so intermediate ones were coming out world readable."""
    target = path or HOME
    parts, made = os.path.normpath(target).split(os.sep), ""
    for part in parts:
        made = made + part + os.sep if made or not part else os.sep
        if made and not os.path.isdir(made):
            os.mkdir(made, 0o700)
    for candidate in (HOME, target):
        if os.path.isdir(candidate) and not sys.platform.startswith("win"):
            try:
                os.chmod(candidate, 0o700)
            except OSError:
                pass
    return target


def looks_like_tor(pid: int) -> bool:
    """Only true when the system positively says so.

    This decides whether to send a kill signal, and the pid comes out of a
    file that may be days old - with --keep-state it can outlive a reboot.
    Pids get reused. The old fallback assumed that no procfs meant the pid
    must be ours, which on windows and macos was every pid on the machine:
    a stale lock file would have taken an unrelated program down with it.
    Not knowing now means not signalling."""
    try:
        with open(f"/proc/{pid}/comm") as f:
            return "tor" in f.read().strip().lower()
    except OSError:
        if os.path.isdir("/proc"):
            return False                  # procfs exists and did not say tor
    except Exception:
        return False
    try:
        if sys.platform.startswith("win"):
            out = subprocess.run(["tasklist", "/FI", f"PID eq {int(pid)}", "/NH"],
                                 capture_output=True, text=True, timeout=15)
            return "tor.exe" in out.stdout.lower()
        out = subprocess.run(["ps", "-o", "comm=", "-p", str(int(pid))],
                             capture_output=True, text=True, timeout=15)
        return out.returncode == 0 and "tor" in out.stdout.strip().lower()
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def hold_in_job(pid: int) -> None:
    """Windows has no parent-death signal, so put tor in a job object that
    kills its members when the last handle closes - which happens when we
    exit, however abruptly."""
    try:
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.windll.kernel32
        job = k32.CreateJobObjectW(None, None)
        if not job:
            return

        class LIMITS(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                        ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
                        ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class EXTENDED(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", LIMITS),
                        ("IoInfo", ctypes.c_byte * 48),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        info = EXTENDED()
        info.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
        k32.SetInformationJobObject(job, 9, ctypes.byref(info),
                                    ctypes.sizeof(info))
        handle = k32.OpenProcess(0x1F0FFF, False, pid)
        if handle:
            k32.AssignProcessToJobObject(job, handle)
            k32.CloseHandle(handle)
        _WIN_HANDLERS.append(job)       # keep the job handle open
    except Exception:
        pass


def free_ports(count: int) -> list[int]:
    """Hold every socket open until all ports are chosen - picking them one
    at a time lets the OS hand out the same port twice, and tor exits if its
    two listeners collide."""
    held, ports = [], []
    try:
        for _ in range(count):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            held.append(s)
            ports.append(s.getsockname()[1])
    finally:
        for s in held:
            s.close()
    return ports


BRIDGE_FILE = os.path.join(HOME, "bridges")        # lines you supplied
AUTO_FILE = os.path.join(HOME, "bridges.auto")     # built-ins we fetched
BRIDGES_ON = os.path.join(HOME, "bridges.on")      # you asked for built-ins
MOAT = "https://bridges.torproject.org/moat/circumvention/builtin"
AUTO_MAX_AGE = 7 * 86400
PT_ORDER = ["obfs4", "webtunnel", "snowflake", "meek_lite"]
PT_NAMES = {"obfs4": ["lyrebird", "obfs4proxy"],
            "webtunnel": ["webtunnel-client", "webtunnel"],
            "snowflake": ["snowflake-client"],
            "meek_lite": ["lyrebird", "obfs4proxy"],
            "conjure": ["conjure-client"]}


BRIDGE_TOKEN = re.compile(r"^[A-Za-z0-9_.:/=+@,\[\]-]+$")


def clean_bridge(line: str) -> str | None:
    """A bridge line ends up in torrc, and torrc can run programs
    (ClientTransportPlugin ... exec). So a line that smuggles in a newline is
    remote code execution. Accept only a single line of plain tokens."""
    if not line or len(line) > 512:
        return None
    if any(c in line for c in "\r\n\x00"):
        return None
    tokens = line.split()
    # one token is legal when it is a bare address: 'Bridge 1.2.3.4:9001' is a
    # valid line, and the old floor of two silently rejected it
    if not 1 <= len(tokens) <= 12:
        return None
    if len(tokens) == 1 and not re.match(
            r"^[\d.]+:\d+$|^\[[0-9a-f:]+\]:\d+$", tokens[0].lower()):
        return None
    if not all(BRIDGE_TOKEN.match(tok) for tok in tokens):
        return None
    head = tokens[0].lower()
    if head not in PT_NAMES and not re.match(r"^[\d.]+:\d+$|^\[[0-9a-f:]+\]:\d+$", head):
        return None                      # a transport we know, or a bare ip:port
    return " ".join(tokens)


def clean_bridges(lines) -> list[str]:
    out = []
    for line in lines or []:
        if isinstance(line, str):
            safe = clean_bridge(line)
            if safe:
                out.append(safe)
    return out


def read_bridges() -> list[str]:
    if CLI_BRIDGES:
        return CLI_BRIDGES
    try:
        # errors="replace": a half-written file, a stray binary paste or a
        # bad sector left this raising UnicodeDecodeError out of every caller,
        # and the first caller is startup. Unreadable bytes become junk lines,
        # and clean_bridge throws those out on its own.
        with open(BRIDGE_FILE, encoding="utf-8", errors="replace") as f:
            return clean_bridges(l.strip() for l in f
                                 if l.strip() and not l.startswith("#"))
    except OSError:
        return []


def write_bridges(lines: list[str]) -> None:
    lines = clean_bridges(lines)
    ensure_home()
    with open(BRIDGE_FILE, "w") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    try:
        os.chmod(BRIDGE_FILE, 0o600)
    except OSError:
        pass


class SocksHandler(urllib.request.HTTPSHandler):
    """Routes a plain https fetch through our own tor, so refreshing the
    bridge list later never touches the network in the clear."""

    def __init__(self, port: int, auth: tuple | None = None):
        super().__init__()
        self.port = port
        self.auth = auth

    def https_open(self, req):
        import http.client, ssl

        outer = self

        class Connection(http.client.HTTPSConnection):
            def connect(self):
                self.sock = socks5_connect(outer.port, self.host,
                                           self.port or 443, auth=outer.auth)
                self.sock = ssl.create_default_context().wrap_socket(
                    self.sock, server_hostname=self.host)

        return self.do_open(Connection, req)


def bridges_on() -> bool:
    """Off unless asked for. Bridges hide the fact that you use tor and get
    you onto it from a network that blocks it, but the shared built-in ones
    are heavily blocked and often leave tor stalled part way through
    bootstrapping, so they are a fix to reach for rather than a default."""
    return bool(read_bridges()) or os.path.isfile(BRIDGES_ON)


def set_builtins(on: bool) -> None:
    ensure_home()
    if on:
        open(BRIDGES_ON, "w").close()
    elif os.path.isfile(BRIDGES_ON):
        os.remove(BRIDGES_ON)


def read_auto() -> list[str]:
    try:
        with open(AUTO_FILE, encoding="utf-8", errors="replace") as f:
            blob = json.load(f)
        if not isinstance(blob, dict):
            return []
        if time.time() - blob.get("fetched", 0) > AUTO_MAX_AGE:
            return []
        return clean_bridges(blob.get("lines", []))
    except (OSError, ValueError, TypeError, UnicodeDecodeError):
        return []


def fetch_builtin_bridges(socks_port: int | None = None) -> list[str]:
    """Ask the tor project which built-in bridges are current, the same way
    Tor Browser and OnionShare do. Hardcoding bridge lines into an open
    source file would get them enumerated and blocked, and would pile every
    user onto the same handful."""
    try:
        request = urllib.request.Request(
            MOAT, data=b"{}", headers={"Content-Type": "application/vnd.api+json"})
        opener = urllib.request.build_opener()
        if socks_port:                       # refresh over tor once we have it
            opener = urllib.request.build_opener(
                SocksHandler(socks_port,
                             (os.urandom(8).hex(), os.urandom(8).hex())))
        with opener.open(request, timeout=60) as r:
            blob = json.loads(r.read().decode())
    except Exception:
        return []

    lines: list[str] = []
    for kind in PT_ORDER:
        for key in (kind, kind.replace("_", "-")):
            for entry in blob.get(key, []) or []:
                if not isinstance(entry, str):
                    continue
                candidate = (entry if entry.split()[:1] and
                             entry.split()[0].lower() in PT_NAMES
                             else f"{kind} {entry}")
                safe = clean_bridge(candidate)
                if safe:
                    lines.append(safe)
    return lines


def save_auto(lines: list[str]) -> None:
    lines = clean_bridges(lines)
    ensure_home()
    try:
        with open(AUTO_FILE, "w") as f:
            json.dump({"fetched": time.time(), "lines": lines}, f)
        os.chmod(AUTO_FILE, 0o600)
    except OSError:
        pass


def active_bridges() -> list[str]:
    """What we will actually put in the torrc."""
    if read_bridges():
        return read_bridges()
    return read_auto() if os.path.isfile(BRIDGES_ON) else []


def usable_bridges(lines: list[str]) -> list[str]:
    """Keep only the lines whose transport we can actually run."""
    return [l for l in lines
            if l.split()[0].lower() not in PT_NAMES
            or find_transport(l.split()[0].lower())]


def find_transport(kind: str) -> str | None:
    """Pluggable transports ship inside the expert bundle, and distros package
    some of them separately."""
    for name in PT_NAMES.get(kind, []):
        found = shutil.which(name)
        if found:
            return found
        for base in (os.path.join(HOME, "tor", "pluggable_transports"),
                     os.path.join(HOME, "tor")):
            for suffix in ("", ".exe"):
                candidate = os.path.join(base, name + suffix)
                if os.path.isfile(candidate):
                    return candidate
    return None


def bridge_config(lines: list[str]) -> tuple[list[str], list[str]]:
    """Turn pasted bridge lines into torrc directives. Returns the directives
    and any transports we could not find a binary for."""
    kinds, missing, directives = [], [], []
    for line in lines:
        kind = line.split()[0].lower()
        if kind not in PT_NAMES:          # a plain ip:port bridge needs no PT
            continue
        if kind not in kinds:
            kinds.append(kind)
    for kind in kinds:
        binary = find_transport(kind)
        if binary:
            if any(c in binary for c in "\r\n\x00"):
                missing.append(kind)     # a transport path we will not write out
                continue
            directives.append(f"ClientTransportPlugin {kind} exec {binary}")
        else:
            missing.append(kind)
    directives += [f"Bridge {l}" for l in clean_bridges(lines)]
    if directives:
        directives.append("UseBridges 1")
    return directives, missing


def find_data_file(name: str) -> str:
    """Bundles put geoip data in different places on different platforms, and
    tor warns about a relative default path when it cannot find them."""
    roots = (tools_home(), HOME)
    for base in [os.path.join(r, sub) for r in roots
                 for sub in ("data", os.path.join("tor", "data"), "tor")] \
                + ["/usr/share/tor"]:
        candidate = os.path.join(base, name)
        if os.path.isfile(candidate):
            return candidate
    for root, _, files in os.walk(tools_home() if os.path.isdir(tools_home()) else HOME):
        if name in files:
            return os.path.join(root, name)
    return ""


def find_tor() -> str | None:
    candidates = [shutil.which("tor"), shutil.which("tor.exe")]
    # where our own download lands, and where the usual installers put it
    candidates += [os.path.join(tools_home(), "tor", "tor"),
                   os.path.join(tools_home(), "tor", "tor.exe"),
                   os.path.join(HOME, "tor", "tor"),
                   os.path.join(HOME, "tor", "tor.exe"),
                   os.path.join(HOME, "Tor", "tor.exe"),
                   "/usr/bin/tor", "/usr/local/bin/tor",
                   "/opt/homebrew/bin/tor",                      # apple silicon brew
                   "/usr/local/opt/tor/bin/tor",                 # intel brew
                   r"C:\Program Files\Tor\tor.exe",
                   r"C:\Program Files (x86)\Tor\tor.exe"]
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidates.append(os.path.join(local, "Programs", "Tor", "tor.exe"))
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def platform_tag() -> str | None:
    machine = platform.machine().lower()
    arch = {"x86_64": "x86_64", "amd64": "x86_64",
            "arm64": "aarch64", "aarch64": "aarch64"}.get(machine)
    if not arch:
        return None
    if sys.platform.startswith("linux"):
        return f"linux-{arch}"
    if sys.platform == "darwin":
        return f"macos-{arch}"
    if sys.platform.startswith("win"):
        return "windows-x86_64" if arch == "aarch64" else f"windows-{arch}"
    return None


ARCHIVE = "https://archive.torproject.org/tor-package-archive/torbrowser/"
MAX_DOWNLOAD = 200 << 20     # the bundle is about 20 MB. the checksum we check
MAX_UNPACKED = 600 << 20     # it against comes from the same server, so it is
                             # no defence against that server serving a bomb -
                             # these are, and they cost nothing


def _download(url: str, target: str, status) -> None:
    """Stream to disk with progress, so a slow link never looks like a freeze."""
    part = target + ".part"
    done = 0
    with urllib.request.urlopen(url, timeout=120) as response:
        total = int(response.headers.get("Content-Length") or 0)
        if total > MAX_DOWNLOAD:
            raise OSError(f"that download claims to be {total >> 20} MB; "
                          f"the bundle is about 20")
        with open(part, "wb") as out:
            while True:
                chunk = response.read(262144)
                if not chunk:
                    break
                out.write(chunk)
                done += len(chunk)
                if done > MAX_DOWNLOAD:
                    raise OSError("that download kept going well past the "
                                  "size of any tor bundle - stopping")
                if total:
                    status(f"  downloading tor  {done * 100 // total}%")
                else:
                    status(f"  downloading tor  {done // 1048576} MB")
    os.replace(part, target)


def _unpack(target: str, status) -> None:
    """Take the binary and its data, and nothing else. Expert bundles carry
    debug symbols many times the size of tor itself, and unpacking those is
    what makes this look like it has hung."""
    status("  reading the archive...")
    with tarfile.open(target) as tf:
        root = os.path.realpath(tools_home())
        members = [m for m in tf.getmembers()
                   if (m.isfile() or m.isdir())          # no symlinks or devices
                   and not m.name.startswith(("debug", "./debug"))
                   and ".debug" not in m.name
                   and safe_member(m.name, root)]
        total = len(members) or 1
        room = MAX_UNPACKED
        for i, member in enumerate(members, 1):
            room -= max(0, getattr(member, "size", 0))
            if room < 0:
                raise OSError("this archive unpacks to far more than a tor "
                              "bundle should - stopping")
            try:
                tf.extract(member, tools_home(), filter="data")   # python 3.12+
            except TypeError:
                tf.extract(member, tools_home())
            if i % 10 == 0 or i == total:
                status(f"  unpacking  {i * 100 // total}%")


def _digest(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _published_digest(version: str, name: str) -> str | None:
    """The checksum the tor project published beside the archive. This catches
    a corrupted or swapped file; it is not a signature check, so a distro
    package remains the stronger option."""
    try:
        with urllib.request.urlopen(
                f"{ARCHIVE}{version}/sha256sums-unsigned-build.txt", timeout=60) as r:
            for line in r.read().decode(errors="replace").splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1].lstrip("*") == name:
                    return parts[0].lower()
    except Exception:
        return None
    return None


def safe_member(name: str, root: str) -> bool:
    """Older pythons have no extraction filter, so check by hand that nothing
    in the archive can write outside our own directory."""
    if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
        return False
    target = os.path.realpath(os.path.join(root, name))
    return target == root or target.startswith(root + os.sep)


def _find_tor_under(root: str) -> str | None:
    for base, _, files in os.walk(root):
        for name in ("tor", "tor.exe"):
            if name in files:
                candidate = os.path.join(base, name)
                if os.path.isfile(candidate):
                    return candidate
    return None


def _works(binary: str) -> bool:
    env = dict(os.environ)
    key = ("DYLD_LIBRARY_PATH" if sys.platform == "darwin"
           else "PATH" if sys.platform.startswith("win") else "LD_LIBRARY_PATH")
    env[key] = os.path.dirname(binary) + os.pathsep + env.get(key, "")
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True,
                             timeout=60, env=env)
        return out.returncode == 0 and "Tor version" in (out.stdout + out.stderr)
    except (OSError, subprocess.SubprocessError):
        return False


def fetch_tor(status=print) -> str | None:
    """Best effort: pull the official expert bundle into the tools folder."""
    tag = platform_tag()
    if not tag:
        return None
    ensure_home(tools_home())
    target = os.path.join(tools_home(), "tor-bundle.tar.gz")
    try:
        for leftover in (target, target + ".part"):
            if os.path.exists(leftover):
                os.remove(leftover)          # a partial file from a cancelled run
        status("  looking up the current tor release...")
        with urllib.request.urlopen(ARCHIVE, timeout=60) as r:
            listing = r.read().decode(errors="replace")
        versions = sorted({m for m in re.findall(r'href="(\d+\.\d+(?:\.\d+)*)/"', listing)},
                          key=lambda v: [int(x) for x in v.split(".")])
        if not versions:
            return None
        version = versions[-1]
        name = f"tor-expert-bundle-{tag}-{version}.tar.gz"
        _download(f"{ARCHIVE}{version}/{name}", target, status)
        status("  checking the archive...")
        expected = _published_digest(version, name)
        actual = _digest(target)
        if expected and expected != actual:
            os.remove(target)
            status("  the download did not match the published checksum - stopping")
            return None
        if not expected:
            os.remove(target)
            status("  could not verify the download against the published")
            status("  checksums, so it will not be used. install tor instead:")
            print(install_hint())
            return None
        _unpack(target, status)
        os.remove(target)
    except Exception as exc:
        status(f"  automatic download failed ({exc})")
        return None

    # our freshly unpacked copy first: find_tor() would hand back the system
    # binary, which is exactly the one that just failed us
    binary = (_find_tor_under(os.path.join(tools_home(), "tor"))
              or _find_tor_under(tools_home()) or find_tor())
    if not binary:
        status("  the download did not contain a tor binary")
        return None
    if not sys.platform.startswith("win"):
        try:
            os.chmod(binary, 0o700)
        except OSError:
            pass
    status("  checking the download...")
    if not _works(binary):
        status("  the downloaded tor will not run here")
        return None
    return binary


def package_manager() -> tuple[str, str]:
    """Whatever this machine actually uses. Telling a windows user to run
    sudo apt is worse than saying nothing."""
    if sys.platform.startswith("win"):
        for tool, template in (("winget", "winget install {}"),
                               ("scoop", "scoop install {}"),
                               ("choco", "choco install {}")):
            if shutil.which(tool):
                return tool, template
        return "", ""
    if sys.platform == "darwin":
        return "brew", "brew install {}"
    for tool, template in (("apt-get", "sudo apt install {}"),
                           ("dnf", "sudo dnf install {}"),
                           ("pacman", "sudo pacman -S {}"),
                           ("zypper", "sudo zypper install {}"),
                           ("apk", "sudo apk add {}"),
                           ("emerge", "sudo emerge {}")):
        if shutil.which(tool):
            return tool, template
    return "", ""


def install_cmd(package: str) -> str:
    """The command for this machine, or an empty string if we cannot say.
    Package names differ per tool - winget wants a publisher id where scoop
    and chocolatey want a plain name."""
    tool, template = package_manager()
    if not template:
        return ""
    if sys.platform.startswith("win"):
        if package != "tor":
            return ""          # transports are not packaged for windows
        if tool == "winget":
            package = "TorProject.Tor"
    return template.format(package)


def transport_hint() -> str:
    """On windows and macos the transports are not in a package manager, but
    the expert bundle we can download carries them."""
    command = install_cmd("obfs4proxy")
    if command:
        return command
    return "let it download tor itself: delete the tor folder in " + HOME


def install_hint(package: str = "tor") -> str:
    command = install_cmd(package)
    if command:
        return f"  install it with:  {command}"
    return ("  install tor from https://www.torproject.org/download/tor/\n"
            "  and put it on your PATH")


def torrc_value(path: str) -> str:
    """Quote a path on its way into torrc.

    These come from the environment - LOCALAPPDATA, XDG_DATA_HOME, a home
    directory - and torrc can start programs, so a newline in one is a config
    line of somebody else's choosing. Spaces are ordinary on windows and need
    the quotes regardless."""
    if any(c in path for c in "\r\n\x00"):
        raise TorFailed("refusing a path with a line break in it: "
                        f"{path[:70]!r}. check HOME, XDG_DATA_HOME "
                        "and LOCALAPPDATA", [])
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


STALL_HINT = 45.0        # seconds on one bootstrap phase before we explain


def clear_screen() -> None:
    """Wipe the screen without a shell. os.system("clear") spawned one and
    looked up the command on PATH, which is a needless dependency on both -
    the terminal understands the escape itself."""
    try:
        sys.stdout.write("\x1b[2J\x1b[3J\x1b[H")
        sys.stdout.flush()
    except (OSError, ValueError):
        pass


def stall_advice(phase: int) -> list[str]:
    """75% is 'directory info loaded'; the step after it is connecting through
    a pluggable transport to a bridge. Sitting there means the bridge is not
    answering, which is worth saying rather than counting silently."""
    if phase >= 50 and bridges_on():
        source = "your own" if read_bridges() else "the built-in"
        snowflake = (install_cmd("snowflake-client")
                     or "let talk shit fetch tor - the bundle carries snowflake")
        out = [f"stuck at {phase}% - tor has what it needs and is now trying to",
               f"reach a bridge. {source} bridges are not answering.",
               "",
               "the built-in ones are shared by every tor user, so they are the",
               "first to be blocked or overloaded. any of these help:",
               ""]
        for command, why in (
                ("python3 talkshit.py bridges",
                 "paste your own from bridges.torproject.org"),
                (snowflake,
                 "a transport that needs no bridge address at all"),
                ("python3 talkshit.py bridges off",
                 "connect directly: faster, but your network sees tor")):
            out.append(f"  {command}")
            out.append(f"      {why}")
        return out
    if phase >= 50:
        return [f"stuck at {phase}% - tor cannot reach a guard relay.",
                "if tor is blocked here, 'python3 talkshit.py bridges' helps"]
    return [f"stuck at {phase}% - no route to the tor network yet.",
            "check the connection; this is usually not talk shit's doing"]


class TorFailed(OSError):
    def __init__(self, reason: str, output: list[str], phase: int = 0):
        super().__init__(reason)
        self.reason, self.output, self.phase = reason, list(output), phase

    def explain(self) -> str:
        """Translate the common failures into something actionable."""
        text = "\n".join(self.output).lower()
        if "another tor process" in text or "lock" in text and "already" in text:
            return ("another tor is using this data directory - "
                    "run 'python3 talkshit.py wipe' and try again")
        if "address already in use" in text or "could not bind" in text:
            return "the port tor picked was taken - just run it again"
        if "permission denied" in text:
            return (f"tor cannot write to {HOME} - check the permissions on it, "
                    "or run 'python3 talkshit.py wipe'")
        if "unrecognized" in text or "failed to parse" in text:
            return "this tor build rejected our config - please report the lines below"
        if self.phase >= 50:
            return "\n  ".join(stall_advice(self.phase))
        if "opened socks listener" in text and "bootstrapped 100" not in text:
            hint = ("tor started but could not reach the tor network - check your "
                    "internet connection")
            if not read_bridges():
                hint += (". if tor is blocked on this network, try "
                         "'python3 talkshit.py bridges'")
            return hint
        if not self.output:
            return "tor produced no output at all - is that file really a tor binary?"
        return ""


class Tor:
    def __init__(self, binary: str, status=print, label: str = ""):
        self.binary = binary
        self.status = status
        self.label = label
        self.proc: subprocess.Popen | None = None
        self.socks_port = 0
        self.control_port = 0
        self.data_dir = os.path.join(HOME, "tordata" + label)
        self.bootstrapped = False
        self.output: list[str] = []      # tor explains itself; keep the last of it
        self._poll: Control | None = None
        self.phase = 0                   # last bootstrap percentage seen
        self.phase_since = time.time()
        # ExtendedErrors makes tor distinguish "no such onion service" from
        # "that service is having a bad minute", which is the whole basis of
        # deciding whether a door is free. Every tor since 0.4.3 has it.
        self.extended = True

    def start(self, timeout: float = 240.0) -> None:
        try:
            self._start(timeout)
        except TorFailed as failure:
            text = "\n".join(failure.output).lower()
            if not self.extended or "extendederrors" not in text:
                raise
            # too old to know the flag. without it a probe cannot tell an
            # empty door from a slow one, so claiming falls back to asking
            # twice before believing it
            self.extended = False
            self._start(timeout)

    def _start(self, timeout: float) -> None:
        ensure_home(self.data_dir)
        if not sys.platform.startswith("win"):
            try:                       # tor refuses a data dir others can read
                os.chmod(self.data_dir, 0o700)
            except OSError:
                pass
        self.clear_stale_lock()
        self.bootstrapped = False
        self.output, self.phase, self.phase_since = [], 0, time.time()
        self.socks_port, self.control_port = free_ports(2)
        torrc = os.path.join(HOME, "torrc" + self.label)
        socks = f"SocksPort 127.0.0.1:{self.socks_port}"
        if self.extended:
            socks += " ExtendedErrors"
        lines = [socks,
                 f"ControlPort 127.0.0.1:{self.control_port}",
                 "CookieAuthentication 1",
                 "SafeLogging 1",
                 "Log notice stdout",
                 f"DataDirectory {torrc_value(self.data_dir)}",
                 "AvoidDiskWrites 1"]
        bridges = usable_bridges(active_bridges())
        if bridges:
            lines += bridge_config(bridges)[0]
        elif bridges_on():
            # bridges are the default; going direct has to be a choice, not
            # something that happens quietly because a binary was missing
            raise TorFailed(
                "bridges are on but none are usable here. install a transport "
                f"({transport_hint()}), run 'python3 talkshit.py bridges' to "
                "paste your own, or 'bridges off' to accept a direct, visible "
                "connection", [])
        for name, option in (("geoip", "GeoIPFile"), ("geoip6", "GeoIPv6File")):
            path = find_data_file(name)
            if path:
                lines.append(f"{option} {torrc_value(path)}")
        with open(torrc, "w") as f:
            f.write("\n".join(lines) + "\n")
        if not sys.platform.startswith("win"):
            try:
                os.chmod(torrc, 0o600)      # it was going out at 644
            except OSError:
                pass
        bindir = os.path.dirname(os.path.abspath(self.binary))
        env = dict(os.environ)
        # the expert bundle ships its libraries beside the binary; each platform
        # looks for them somewhere different
        if sys.platform == "darwin":
            var = "DYLD_LIBRARY_PATH"
        elif sys.platform.startswith("win"):
            var = "PATH"
        else:
            var = "LD_LIBRARY_PATH"
        env[var] = bindir + os.pathsep + env.get(var, "")
        kwargs = {}
        if sys.platform.startswith("win"):
            # otherwise a console window flashes up on every launch
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        elif sys.platform.startswith("linux"):
            # ask the kernel to send us-are-gone straight to the child
            def die_with_parent():
                try:
                    import ctypes
                    ctypes.CDLL("libc.so.6").prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG
                except Exception:
                    pass
            kwargs["preexec_fn"] = die_with_parent
        self.proc = subprocess.Popen([self.binary, "-f", torrc], env=env, cwd=bindir,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, bufsize=1, **kwargs)
        if self not in _LIVE_TORS:
            _LIVE_TORS.append(self)
        if sys.platform.startswith("win"):
            hold_in_job(self.proc.pid)
        threading.Thread(target=self._drain, daemon=True).start()
        end = time.time() + timeout
        last_report = hinted = 0.0
        while time.time() < end:
            if self.bootstrapped:
                return
            if time.time() - last_report > 3:
                last_report = time.time()
                phase = self.bootstrap_phase()
                if phase is not None:
                    if phase != self.phase:
                        self.phase, self.phase_since = phase, time.time()
                    self.status(f"  tor {phase}%")
                    if phase >= 100:
                        self.bootstrapped = True
                        return
            stuck = time.time() - self.phase_since
            if stuck > STALL_HINT and time.time() - hinted > STALL_HINT:
                hinted = time.time()
                print("")
                for line in stall_advice(self.phase):
                    print(f"  {line}")
            if self.proc.poll() is not None:
                self.stop()
                raise TorFailed("tor exited during startup", self.output, self.phase)
            time.sleep(0.4)
        self.stop()                     # never leave an orphan holding the lock
        raise TorFailed(f"tor stalled at {self.phase}% and gave up",
                        self.output, self.phase)

    def _drain(self) -> None:
        if not (self.proc and self.proc.stdout):
            return                       # a bare assert vanishes under -O
        for line in self.proc.stdout:
            line = line.rstrip()
            if line:
                self.output.append(line)
                del self.output[:-40]
            if "Bootstrapped" in line:
                pct = line.split("Bootstrapped", 1)[1].strip().split("%")[0].strip()
                self.status(f"  tor {pct}%")
                if pct == "100":
                    self.bootstrapped = True

    def bootstrap_phase(self) -> int | None:
        """Ask tor directly rather than trusting its log format. Reuses one
        control connection: opening a new one for every poll makes tor log a
        line each time, which buries the message we actually need."""
        for attempt in (1, 2):
            try:
                if self._poll is None:
                    self._poll = self.control()
                for line in self._poll.cmd("GETINFO status/bootstrap-phase"):
                    match = re.search(r"PROGRESS=(\d+)", line)
                    if match:
                        return int(match.group(1))
                return None
            except (OSError, ValueError):
                if self._poll:
                    self._poll.close()
                self._poll = None
                if attempt == 2:
                    return None
        return None

    def control(self) -> Control:
        return Control(self.control_port,
                       os.path.join(self.data_dir, "control_auth_cookie"))

    def clear_stale_lock(self) -> None:
        """A run that crashed, or a window closed with the X, leaves tor still
        running. It holds this directory and, on windows, its own exe, so the
        next run can neither start nor replace it. The directory is ours
        alone, so whatever holds it is our own leftover: end it."""
        lock = os.path.join(self.data_dir, "lock")
        if not os.path.isfile(lock):
            return
        try:
            with open(lock) as f:
                pid = int((f.read().strip() or "0"))
        except (OSError, ValueError):
            pid = 0
        alive = False
        if pid > 1 and pid != os.getpid() and looks_like_tor(pid):
            try:
                os.kill(pid, 0)
                alive = True
            except OSError:
                alive = False
        if alive:
            self.status(f"  ending a leftover tor (pid {pid})...")
            for sig in (signal.SIGTERM, getattr(signal, "SIGKILL", signal.SIGTERM)):
                try:
                    os.kill(pid, sig)
                except OSError:
                    break               # already gone
                for _ in range(20):
                    time.sleep(0.25)
                    try:
                        os.kill(pid, 0)
                    except OSError:
                        break
                else:
                    continue
                break
        try:
            os.remove(lock)
        except OSError:
            pass

    def stop(self) -> None:
        if self in _LIVE_TORS:
            _LIVE_TORS.remove(self)
        if self._poll:
            self._poll.close()
            self._poll = None
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class Transport:
    """Onion services live only as long as the control connection that made
    them, so a dropped connection would silently delete every room this peer
    is hosting. Keep the set and restore it."""

    def __init__(self, tor: Tor):
        self.tor = tor
        self.socks_port = tor.socks_port
        self.extended = tor.extended
        self._ctl: Control | None = None
        self._published: dict[str, tuple[str, int]] = {}   # key -> (address, port)
        self._lock = threading.Lock()
        self.stop = threading.Event()
        threading.Thread(target=self._watchdog, daemon=True).start()

    def connect(self, address: str, timeout: float = 45.0,
                auth: tuple | None = None, on_socket=None) -> socket.socket:
        return socks5_connect(self.socks_port, address, VIRTUAL_PORT, timeout,
                              auth, on_socket)

    def publish(self, control_key: str, local_port: int) -> str:
        with self._lock:
            address = self._publish_locked(control_key, local_port)
            self._published[control_key] = (address, local_port)
            return address

    def _publish_locked(self, control_key: str, local_port: int) -> str:
        if self._ctl is None:
            self._ctl = self.tor.control()
        return self._ctl.add_onion(control_key, local_port)

    def unpublish(self, address: str) -> None:
        with self._lock:
            for key, (addr, _) in list(self._published.items()):
                if addr == address:
                    del self._published[key]
            if self._ctl:
                self._ctl.del_onion(address)

    def _watchdog(self) -> None:
        """Republish everything if tor's control connection ever drops."""
        while not self.stop.wait(60):
          try:
            with self._lock:
                if not self._published:
                    continue
                try:
                    if self._ctl is None:
                        raise OSError("no control connection")
                    self._ctl.cmd("GETINFO version")
                    continue
                except OSError:
                    pass
                if self._ctl:
                    self._ctl.close()
                self._ctl = None
                for key, (_, port) in list(self._published.items()):
                    try:
                        # same key, so the address is unchanged
                        self._published[key] = (self._publish_locked(key, port), port)
                    except OSError:
                        break
          except Exception:
            continue             # our onions vanish with this thread; the
                                 # mesh is not reachable from here to report it

    def close(self) -> None:
        self.stop.set()
        with self._lock:
            self._published.clear()
            if self._ctl:
                self._ctl.close()
                self._ctl = None


def ensure_bridges(status=print) -> None:
    """Never reaches for the built-in list on its own.

    Bridges exist for exactly one purpose: to keep whoever runs your network
    from seeing that you use tor. Fetching the built-in list is a plain https
    request to bridges.torproject.org, made before tor is running, over the
    very connection you are trying to hide from - and the hostname alone says
    what you are about to do. Doing that quietly, at startup, on the one path
    where somebody has told us the network is hostile, would give the game
    away at the moment it matters most. So it is never automatic."""
    if not os.path.isfile(BRIDGES_ON) or read_bridges() or read_auto():
        return
    print("\n  bridges are on, but none are cached.")
    print("\n  fetching the built-in list means connecting straight to")
    print("  bridges.torproject.org, in the clear, before tor starts. Anyone")
    print("  watching your connection would see it, and that is the one thing")
    print("  bridges are for hiding - so this is not done for you.")
    print("\n  get bridges somewhere out of the way and paste them in:")
    print("      python3 talkshit.py bridges")
    print("  by email  : bridges@torproject.org, body 'get transport obfs4'")
    print("  in browser: Tor Browser > Settings > Connection > Bridges")
    print("\n  or fetch them anyway, knowing what it shows:")
    print("      python3 talkshit.py bridges auto\n")


def refresh_bridges_over_tor(transport: "Transport") -> None:
    if not os.path.isfile(BRIDGES_ON) or read_bridges():
        return
    lines = fetch_builtin_bridges(transport.socks_port)
    if lines:
        save_auto(lines)


def start_tor(status=print, label: str = "") -> Transport:
    ensure_home()
    Tor(find_tor() or "", status, label).clear_stale_lock()  # before any download
    ensure_bridges(status)
    system = find_tor()
    if not system:
        if NO_DOWNLOAD:
            hint = install_cmd("tor") or (
                "download it from https://www.torproject.org/download/tor/")
            print(f"\n  tor is not installed and --no-download is set.\n  {hint}\n")
            sys.exit(1)
        hint = install_cmd("tor")
        if hint:
            # there is a package manager here, so the tidy route exists and
            # should be offered first: installing tor leaves us with no
            # folder of our own at all
            print("\n  tor is not installed. installing it yourself is tidier -")
            print("  talk shit then keeps nothing on disk whatsoever:\n")
            print(f"      {hint}\n")
            print(f"  otherwise a copy can be fetched into {tools_home()}")
            print("  (the program only: no state, no settings, no room history).")
            try:
                answer = input("\n  fetch a copy now? [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = ""
            if not answer.startswith("y"):
                print(f"\n  ok - run '{hint}' and start again.\n")
                sys.exit(1)
        else:
            # nothing to install it with, so fetching is the only way in
            print("\n  tor is not installed and this machine has no package")
            print("  manager to install it. the download is a plain connection")
            print("  to the tor project - it cannot go over tor, since tor is")
            print("  what is missing - so your network will see it happen.")
            print(f"  fetching a copy (about 20 MB,")
            print(f"  once) into {tools_home()}.")
            print("  that folder holds the program only - no state, no settings,")
            print("  nothing about rooms you have used. 'wipe' removes it.\n")
    binary = system or fetch_tor(status)
    if not binary:
        print("\n  tor is needed and could not be downloaded automatically.")
        print(install_hint())
        sys.exit(1)

    tor = Tor(binary, status, label)
    try:
        tor.start()
        transport = Transport(tor)
        threading.Thread(target=refresh_bridges_over_tor, args=(transport,),
                         daemon=True).start()
        return transport
    except TorFailed as first:
        bundled = os.path.join(HOME, "tor", "tor")
        if system and binary == system and not os.path.isfile(bundled):
            # the installed tor would not run for us; ours might
            print(f"\r  the installed tor did not start ({first.reason})")
            own = fetch_tor(status)
            if own:
                try:
                    tor = Tor(own, status, label)
                    tor.start()
                    return Transport(tor)
                except TorFailed as second:
                    first = second
        report_tor_failure(first)
        sys.exit(1)


def report_tor_failure(failure: TorFailed) -> None:
    print(f"\n  could not start tor: {failure.reason}")
    hint = failure.explain()
    if hint:
        print(f"  {hint}")
    complaints = [l for l in failure.output
                  if "[warn]" in l or "[err]" in l]
    shown = complaints[-6:] or failure.output[-6:]
    if shown:
        print("\n  tor said:")
        for line in shown:
            print(f"    {line}")
    if not hint:
        print("\n  if that mentions a missing library, install tor with your")
        print("  package manager and try again:")
        print(install_hint())


# ==========================================================================
# mesh
# ==========================================================================

class Link:
    """One tor circuit to one peer.

    Two layers of encryption ride it. The outer one uses the room key, so
    only passphrase holders can speak at all. Inside that sits a session
    layer keyed by an ephemeral X25519 exchange, which is what gives forward
    secrecy - those keys exist only in memory and die with the process.
    Bodies are signed, so nobody holding the passphrase can wear someone
    else's handle.
    """

    def __init__(self, sock: socket.socket, mesh: "Mesh", address: str = ""):
        self.sock, self.mesh, self.address = sock, mesh, address
        self.alive = True
        self._tx: AESGCM | None = None
        self._rx: AESGCM | None = None
        self._pending: list[dict] = []
        self.out: queue.Queue = queue.Queue()
        self.seen_here: collections.deque = collections.deque()
        self.fresh: collections.deque = collections.deque()
        self.keys_here: dict[str, list] = {}
        self.opened = self.last_heard = time.time()
        self.useful = False          # has anything ever arrived over this?
        self.lock = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._write, daemon=True).start()
        self.handshake()

    # -- key agreement -----------------------------------------------------

    def handshake(self) -> None:
        me = self.mesh.ident
        self._room_send({"kind": "kx", "v": PROTOCOL,
                         "epk": base64.b64encode(me.xpub).decode()})

    def _on_kx(self, obj: dict) -> None:
        if self._tx is not None:
            return                   # keys are agreed once; ignore any re-offer
        if obj.get("v") != PROTOCOL:
            # they hold the passphrase, so this is a different build rather
            # than a stranger. say so instead of failing quietly later
            self.mesh.mismatched += 1
            self.drop()
            return
        try:
            epk = base64.b64decode(obj.get("epk", ""))
            if len(epk) != 32:
                raise ValueError("bad key length")
            me = self.mesh.ident
            if epk == me.xpub:
                raise ValueError("that is our own key")
            tx, rx = link_keys(me.x, me.xpub, epk, self.mesh.secret.key)
        except Exception:
            self.drop()
            return
        with self.lock:
            self._tx, self._rx = tx, rx
            queued, self._pending = self._pending, []
        for obj in queued:
            self.send(obj)

    @property
    def ready(self) -> bool:
        return self._tx is not None

    # -- sending -----------------------------------------------------------

    def _room_send(self, obj: dict) -> None:
        if self.alive and self.out.qsize() < MAX_QUEUE:
            self.out.put(self.mesh.secret.seal(obj))

    def send(self, obj: dict) -> None:
        """Queue an application object. Never blocks: a stalled circuit must
        not freeze the keyboard."""
        if not self.alive:
            return
        if self.out.qsize() >= MAX_QUEUE:
            self.drop()              # this circuit is not draining; let it go
            return
        with self.lock:
            if self._tx is None:
                if len(self._pending) < MAX_QUEUE:
                    self._pending.append(obj)
                return
            tx = self._tx
        body = dict(obj)
        body.setdefault("ts", time.time())
        # name the room inside the signature: without it a signed message
        # lifted from one room verifies perfectly well in another
        body.setdefault("rm", self.mesh.secret.fingerprint)
        if "from" not in body:
            me = self.mesh.ident
            body["from"] = base64.b64encode(me.edpub).decode()
            body["sig"] = base64.b64encode(me.sign(signed_bytes(body))).decode()
        nonce = os.urandom(12)
        sealed = nonce + tx.encrypt(nonce, pad_body(
            json.dumps(body, separators=(",", ":")).encode("utf-8")),
            self.mesh.secret.label)
        self.out.put(self.mesh.secret.seal(
            {"e": base64.b64encode(sealed).decode()}))

    def _write(self) -> None:
        while True:
            blob = self.out.get()
            if blob is None:
                return
            try:
                self.sock.sendall(base64.b64encode(blob) + b"\n")
            except OSError:
                self.drop()
                return

    # -- receiving ---------------------------------------------------------

    def _read(self) -> None:
        try:
            stream = self.sock.makefile("rb")
            while True:
                line = stream.readline(MAX_FRAME)
                if not line:
                    return
                if not line.endswith(b"\n"):
                    return           # oversized frame: hang up rather than buffer
                try:
                    blob = base64.b64decode(line.strip())
                except Exception:
                    continue
                self.last_heard = time.time()
                outer = self.mesh.secret.open(blob)
                if outer is None:
                    self.drop()          # wrong room key: not one of us
                    return
                if outer.get("kind") == "kx":
                    self._on_kx(outer)
                    continue
                obj = self._unseal(outer)
                if obj is not None:
                    try:
                        self.mesh._dispatch(obj, self)
                    except Exception:
                        # bodies come from strangers. one that trips something
                        # unexpected costs us that message, not the circuit -
                        # and an unhandled error here would print a traceback
                        # across the chat window on its way out
                        continue
        except OSError:
            pass
        finally:
            self.drop()

    def saturated(self) -> bool:
        """A limit per identity is not enough on its own: an attacker can mint
        a fresh key whenever they hit it. One circuit gets a ceiling too, set
        far above what a busy room of real people produces."""
        now = time.time()
        with self.lock:
            window = self.seen_here
            while window and now - window[0] >= RATE_WINDOW:
                window.popleft()     # a queue, not a list rebuilt per body.
            if len(window) >= LINK_RATE_LIMIT:   # it used to cost more the
                return True                      # harder it was flooded
            window.append(now)
            return False

    def minting(self, sender: str) -> bool:
        """A per-identity limit is not a limit when identities are free. Hold
        the circuit responsible instead: it may carry only so many distinct
        keys, and a key nobody has heard of before gets a small allowance
        until it has been around long enough to be a real person."""
        if not sender:
            return False
        now = time.time()
        with self.lock:
            entry = self.keys_here.get(sender)
            if entry is None:
                intro = self.fresh
                while intro and now - intro[0] >= RATE_WINDOW:
                    intro.popleft()
                if len(intro) >= NEW_KEYS_PER_WINDOW:
                    return True          # a key mill, not a room filling up
                if len(self.keys_here) >= MAX_ROSTER:
                    for k in [k for k, e in self.keys_here.items()
                              if now - e[1] > RATE_WINDOW * 6]:
                        del self.keys_here[k]
                    if len(self.keys_here) >= MAX_ROSTER:
                        return True
                intro.append(now)
                entry = self.keys_here[sender] = [now, now, collections.deque()]
            entry[1] = now
            window = entry[2]
            while window and now - window[0] >= RATE_WINDOW:
                window.popleft()
            # a key we have only just met gets a small allowance until it has
            # been around long enough to be a person rather than a disposable
            settled = now - entry[0] >= RATE_WINDOW * 3
            if len(window) >= (RATE_LIMIT if settled else NEW_KEY_BUDGET):
                return True
            window.append(now)
            return False

    def _unseal(self, outer: dict) -> dict | None:
        with self.lock:
            rx = self._rx
        if rx is None:
            return None
        try:
            sealed = base64.b64decode(outer.get("e", ""))
            raw = unpad_body(rx.decrypt(sealed[:12], sealed[12:],
                                        self.mesh.secret.label))
            obj = loads(raw)
        except Exception:
            return None
        if not isinstance(obj, dict) or not verify(obj):
            return None
        if obj.get("rm") != self.mesh.secret.fingerprint:
            return None              # signed for somewhere else
        return obj

    def drop(self) -> None:
        if not self.alive:
            return
        self.alive = False
        self.out.put(None)
        try:
            self.sock.close()
        except OSError:
            pass
        self.mesh._on_drop(self)


def verify(obj: dict) -> bool:
    """A body is only accepted if it carries a signature by the key that
    claims to have sent it. Relaying preserves this, so a middle peer cannot
    rewrite what it passes on."""
    try:
        sender = base64.b64decode(obj.get("from", ""))
        sig = base64.b64decode(obj.get("sig", ""))
        Ed25519PublicKey.from_public_bytes(sender).verify(sig, signed_bytes(obj))
        return True
    except Exception:            # any malformed field means "not verified"
        return False


# What gets relayed to the whole room. "hello" deliberately does not: it is
# a greeting for one circuit, and relaying it made every link anyone opened
# into a room-wide flood - which is quadratic in the headcount and never
# settles, because links churn. An arrival is announced once, as "join".
RELAYED = ("msg", "join", "bye", "room", "drop", "ping")


class Mesh:
    """Everyone holding the same secret meets here. Nobody coordinates.

    The passphrase derives a fixed handful of doors. They are how a room is
    entered and nothing else: a peer that gets one publishes it, a peer that
    does not publishes an address of its own, and every peer passes the
    addresses it knows to the peers it is linked to. So the cost of joining
    is the number of doors, which never changes, while the number of people
    inside is limited only by what tor will carry.
    """

    def __init__(self, transport, secret: Secret, on_object=None,
                 hello: dict | None = None, ident: "Identity | None" = None,
                 publish: bool = True, adjacent_epochs: bool = True):
        self.transport, self.secret = transport, secret
        self.ident = ident or Identity()
        self.publish = publish          # False: join without hosting at all
        # Whether an empty sweep is worth chasing into neighbouring epochs. A
        # room may be two people, so one of them having a wrong clock is worth
        # sixty four extra lookups. The public index is everybody at once: if
        # a single one of them has the right time we meet on the current
        # epoch, and paying that cost on every startup where nobody happens
        # to be online is what made the room list feel dead for minutes.
        self.adjacent_epochs = adjacent_epochs
        self.on_object = on_object or (lambda obj, link: None)
        self.hello = hello or {"kind": "hello"}
        self.links: list[Link] = []
        self.known: dict[str, float] = {}    # address -> when we last heard of it
        self.gossiped: dict[str, list] = {}  # source -> when it spent its budget
        self.vouched: dict[str, set] = {}    # address -> who has vouched for it
        self.cold: dict[str, float] = {}     # address -> when to try it again
        self.misses: dict[str, int] = {}     # address -> consecutive refusals
        self.dialing: set = set()
        self.dials: collections.deque = collections.deque()
        # our own corner of tor's circuit pool - see socks5_connect
        self.socks_auth = (os.urandom(8).hex(), os.urandom(8).hex())
        self._inflight: set = set()          # sockets still negotiating
        # what each door said, last time we knocked. kept so a failure to
        # find anybody can be answered with evidence rather than a guess
        self.probe_notes: collections.OrderedDict = collections.OrderedDict()
        self.seen: collections.OrderedDict = collections.OrderedDict()
        self.rates: dict[str, collections.deque] = {}
        self.address: str | None = None      # what we publish, door or our own
        self.claimed: str | None = None      # set only if that is a door
        self.slot: int | None = None         # which door, so we can follow it
        self.claiming = threading.Lock()     # only one door, however many
                                             # probes come back free at once
        self.retiring: list = []             # old doors, kept up a little longer
        self.verifying = threading.Lock()    # one door check at a time
        self.epoch = door_epoch()
        self.probing = False
        self.mismatched = 0             # peers speaking another wire format
        self.sweeps = 0
        # A loop here that throws every time would otherwise carry on failing
        # in silence for as long as the room is open, and silent degradation
        # in a chat program reads to the user as nobody talking.
        self.faults: dict = {}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(64)
        self.local_port = self.listener.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    # -- joining -----------------------------------------------------------

    def start(self) -> None:
        """Return immediately. Finding peers takes tor a while, and there is
        no reason to make someone stare at a blank screen for it."""
        threading.Thread(target=self._join, daemon=True).start()

    def fault(self, where: str, exc: BaseException) -> None:
        count, _ = self.faults.get(where, (0, ""))
        self.faults[where] = (count + 1, f"{type(exc).__name__}: {exc}"[:120])

    def complaints(self) -> list[str]:
        return [f"{where} has failed {n} time(s): {last}"
                for where, (n, last) in sorted(self.faults.items())]

    def crowded(self) -> bool:
        """Count peers, not sockets. The index doors are computable by anyone
        holding this file, so a stranger can open connections and go quiet;
        counting those towards the cap lets them shut the room list out of
        reach without ever proving they belong here."""
        with self.lock:
            return sum(1 for l in self.links
                       if l.alive and l.ready) >= MAX_LINKS

    def _enough(self) -> bool:
        """Connectivity is capped at FANOUT no matter how big the room is.
        A thousand person room would otherwise need every peer to hold nine
        hundred and ninety nine circuits, which tor cannot carry - messages
        reach everyone by being relayed across a sparse graph instead."""
        return sum(1 for l in self.links if l.alive) >= FANOUT

    def _join(self) -> None:
        self.probing = True
        self.epoch = door_epoch()
        doors = list(self.secret.doors_at(self.epoch))
        random.shuffle(doors)
        free: list[OnionIdentity] = []
        try:
            for i in range(0, len(doors), JOIN_WAVE):
                if self._enough():
                    break
                free += self._probe(doors[i:i + JOIN_WAVE])
                if self.links:
                    self.ready.set()    # usable now; keep looking in background
                # Take a door the moment one is known free, rather than after
                # proving all of them are. Proving a descriptor does not exist
                # is the slowest thing tor does - every directory responsible
                # for it has to be asked and every one has to come back empty -
                # so the first peer into a room was spending minutes proving
                # forty eight addresses were empty before publishing any of
                # them, and was unreachable for every second of it. A door
                # claimed too eagerly is not a problem: _verify_claim dials it
                # back and stands down if somebody else got there too.
                if self.publish and not self.address and free:
                    self._take_door(free)
                    free = []
            if not self.links and self.adjacent_epochs:
                # Not "and not self.address": claiming a door says nothing
                # about whether anyone is here. A joiner finds a free door
                # long before a rendezvous to a live one completes, so gating
                # this on the address meant the adjacent epochs were never
                # looked at, and a peer with a slow clock became invisible.
                # Both directions, two epochs out. A clock that runs slow
                # puts us behind everyone else and a fast one puts us ahead,
                # and either way the answer must not be a private room of one.
                # One epoch each way only covers skew under the hour reliably:
                # between one and two hours it depends where in the hour you
                # happen to be, which is not a thing to leave to chance.
                # This runs behind the chat window, and stops the moment
                # anybody answers.
                last = []
                for step in (-1, 1, -2, 2):
                    last += list(self.secret.doors_at(self.epoch + step))
                for i in range(0, len(last), JOIN_WAVE):
                    if self.links:
                        break
                    self._probe(last[i:i + JOIN_WAVE])
            if self.publish and not self.address and free:
                self._take_door(free)
            if self.publish and not self.address:
                self._publish_own()
        finally:
            self.probing = False
            self.ready.set()
        threading.Thread(target=self._refresh_loop, daemon=True).start()
        threading.Thread(target=self._gossip_loop, daemon=True).start()

    def rescan(self, force: bool = False) -> None:
        """Top the connection count back up. Word of mouth first, because it
        costs the same whether the room holds six people or six thousand;
        the doors are only consulted when that turns nothing up, and then
        with a backoff, since knocking on all of them is the expensive part."""
        if self._enough():
            return
        live = {l.address for l in self.links if l.alive}
        now = time.time()
        with self.lock:
            self.cold = {a: t for a, t in self.cold.items() if t > now}
            fresh = [a for a, seen in self.known.items()
                     if a not in live and a != self.address
                     and now - seen < KNOWN_TTL]
            warm = [a for a in fresh if a not in self.cold]
            todo = warm or fresh     # rather sit idle than try nothing at all
        random.shuffle(todo)
        doors = {d.address for d in self.secret.doors_at(door_epoch())}
        # an address only one peer has ever mentioned sorts to the back: it is
        # tried, but after everything that somebody else has also vouched for
        todo.sort(key=lambda a: (a in doors,
                                 len(self.vouched.get(a, ())) < CORROBORATED))
        # dial a couple more than the shortfall: some of these will be doors
        # that are already full, and will turn us away
        need = max(1, FANOUT - sum(1 for l in self.links if l.alive)) + 2
        self._dial(todo[:need])
        if self._enough():
            return
        self.sweeps += 1
        if self.links and not force and self.sweeps % DOOR_BACKOFF:
            return                  # we are in; no need to hammer the doors.
                                    # somebody who pressed refresh is asking
                                    # for exactly that, though, so they skip it
        candidates = [d for d in self.secret.doors_at(door_epoch())
                      if d.address not in live and d.address != self.address]
        random.shuffle(candidates)
        free = self._probe(candidates[:PROBE_WAVE])
        if self.publish and not self.address and free:
            self._take_door(free)
        if self.publish and not self.address:
            self._publish_own()

    def _probe(self, identities, timeout: float = PROBE_TIMEOUT) -> list[OnionIdentity]:
        """Returns the doors that are genuinely unpublished.

        A failed connection is not the same as an empty door. An onion that
        is merely slow, or that is rotating its introduction points, fails in
        exactly the way one that was never published does - and claiming on
        that mistake puts two peers on one address, which forks the room in
        half with neither side aware. So a door counts as free only when tor
        says outright that no descriptor exists. Where tor is too old to draw
        that distinction, it counts as free only after failing twice.
        """
        was_probing = self.probing      # restore, do not clobber: a periodic
        self.probing = True             # rescan used to leave this stuck on
        free: list[OnionIdentity] = []
        lock = threading.Lock()
        flaky: list[OnionIdentity] = []

        def probe(identity, unsure):
            try:
                sock = self._connect(identity.address, timeout)
                self._forget_socket(sock)
            except SocksError as exc:
                early = False
                with lock:
                    if exc.code in NO_SUCH_ONION:
                        free.append(identity)
                        early = self.publish and not self.address
                        note = "free (0xF0)"
                    elif exc.code in TRANSIENT_ONION:
                        flaky.append(identity)   # worth another try, never free
                        note = f"busy, retrying (0x{exc.code:02X})"
                    elif exc.code == 0 or not self.transport.extended:
                        unsure.append(identity)
                        note = "no answer, will confirm"
                    else:
                        note = f"occupied (0x{exc.code:02X})"
                self._note_probe(identity.address, note)
                if early:
                    # one door known free is enough to open a room. waiting for
                    # a verdict on the other fifteen means running at the speed
                    # of the slowest lookup, which is where the minute went
                    self._take_door([identity])
                return
            except OSError as exc:
                with lock:
                    unsure.append(identity)
                self._note_probe(identity.address, f"socket error: {exc}"[:48])
                return
            except Exception as exc:
                self._note_probe(identity.address,
                                 f"{type(exc).__name__}: {exc}"[:48])
                return               # a probe thread dying quietly is how a
                                     # peer becomes unable to find anybody
            if self._enough():
                # every door was dialled at once so that a live one answers
                # early rather than behind a queue of empties. that is about
                # finding somebody quickly, not about keeping everybody: past
                # FANOUT these are surplus, and holding them would double what
                # this peer relays for the rest of the room. remember where it
                # was and hang up.
                with self.lock:
                    self.known[identity.address] = time.time()
                try:
                    sock.close()
                except OSError:
                    pass
                return
            self._note_probe(identity.address, "answered - linked")
            self._adopt(sock, identity.address)

        def sweep(targets, bucket, wait):
            threads = []
            for identity in targets:
                t = threading.Thread(target=probe, args=(identity, bucket),
                                     daemon=True)
                t.start()
                threads.append(t)
            for t in threads:
                t.join(timeout=wait + 10)

        unsure: list[OnionIdentity] = []
        sweep(identities, unsure, timeout)
        if unsure:
            confirmed: list[OnionIdentity] = []
            sweep(unsure, confirmed, CONFIRM_TIMEOUT)
            with lock:
                free += confirmed
        # A door that answered with a failed rendezvous has somebody behind
        # it, so it is dialled again - but its result is thrown away rather
        # than added to free. Twice unreachable still does not mean empty,
        # and claiming it would put two peers on one address.
        for _ in range(2):
            with lock:
                again, flaky[:] = list(flaky), []
            if not again or self._enough():
                break
            sweep(again, [], CONFIRM_TIMEOUT)
        self.probing = was_probing
        return free

    def _take_door(self, free: list[OnionIdentity]) -> None:
        with self.claiming:
            if self.address:
                return                  # another probe got there first
            self._take_door_locked(free)

    def _take_door_locked(self, free: list[OnionIdentity]) -> None:
        random.shuffle(free)
        for door in free:
            if door.epoch != door_epoch():
                continue                # never take a door that has expired
            try:
                self.address = self.claimed = self.transport.publish(
                    door.control_key, self.local_port)
                self.slot = door.slot
                self.ready.set()        # we are reachable; the room exists
            except OSError:
                continue
            threading.Thread(target=self._verify_claim, daemon=True).start()
            return

    def _rotate(self) -> None:
        """Doors move to fresh addresses on a schedule the passphrase and the
        clock agree on, with no coordination between peers.

        This is what stops a squat being permanent. Anyone who walks out still
        holding the passphrase can take every door and shut newcomers out -
        people already inside are unaffected, since they find each other by
        word of mouth, but nobody new can get a foot in the door. Rotation
        does not make that impossible; it makes it a thing that has to be
        maintained forever rather than done once and abandoned.

        Whoever holds a door keeps the same slot across the change, so the
        holders map onto the new set without racing each other for it."""
        epoch = door_epoch()
        if epoch == self.epoch:
            return
        self.epoch = epoch
        if self.slot is None or not self.publish:
            return
        door = self.secret.doors_at(epoch)[self.slot]
        previous = self.claimed
        try:
            self.address = self.claimed = self.transport.publish(
                door.control_key, self.local_port)
        except OSError:
            return                      # keep the old one; try again next tick
        if previous and previous != self.claimed:
            # leave the old address up a while: somebody may be mid-dial on it,
            # and a tor circuit takes long enough that cutting it is rude. the
            # loop that already runs every half minute retires it - a thread
            # per rotation would outlive its own usefulness, and pile up for
            # good if the overlap were ever set longer than the epoch
            self.retiring.append((previous, time.time() + DOOR_OVERLAP))

    def _retire(self) -> None:
        now = time.time()
        due = [a for a, when in self.retiring if when <= now]
        self.retiring = [(a, when) for a, when in self.retiring if when > now]
        for address in due:
            self.transport.unpublish(address)

    def _forget_stale(self) -> None:
        """Addresses go quiet - a peer leaves, a door rotates away - and
        nothing was dropping them until the table hit its cap. Since gossip
        samples from this table, a peer that had been running a while spent
        its time telling everyone about addresses that no longer answer."""
        now = time.time()
        with self.lock:
            for address in [a for a, seen in self.known.items()
                            if now - seen > KNOWN_TTL]:
                del self.known[address]
                self.vouched.pop(address, None)
            if len(self.seen) > MAX_SEEN // 4:
                self._forget_seen()
            for who in [k for k, when in self.cold.items() if when < now]:
                del self.cold[who]
                # the refusal count outlived the cooldown that used it, and
                # gossip churns through addresses forever, so it was the one
                # table here with nothing to stop it growing
                if who not in self.known:
                    self.misses.pop(who, None)
            if len(self.misses) > MAX_KNOWN:
                self.misses = {a: n for a, n in self.misses.items()
                               if a in self.known or a in self.cold}

    def _forget_seen(self) -> None:
        """Drop old message ids. Age alone was not enough: everything inside
        the window was kept, so a busy room simply held more of them, without
        limit. Caller holds the lock.

        Who gets evicted matters as much as how many. Dropping the oldest
        meant a flood could push everybody else's ids out of the table, and
        an id that is no longer remembered can be replayed - so shouting was
        a way of un-remembering other people's messages. Each speaker keeps
        an equal share of the room instead, and a flooder crowds out only
        itself."""
        cut = time.time() - CLOCK_SLACK
        while self.seen:                 # oldest first; ids go in as they
            _, when = next(iter(self.seen.items()))   # arrive, so insertion
            if when > cut:                            # order is time order
                break
            self.seen.popitem(last=False)
        keep = MAX_SEEN * 3 // 4
        if len(self.seen) <= keep:
            return
        share = collections.Counter(who for who, _ in self.seen)
        fair = max(1, keep // max(1, len(share)))
        kept: collections.Counter = collections.Counter()
        for key in reversed(list(self.seen)):     # newest of each speaker
            who = key[0]                          # is the one worth keeping
            if kept[who] < fair:
                kept[who] += 1
            else:
                del self.seen[key]
        while len(self.seen) > keep:     # a room of one or two speakers
            self.seen.popitem(last=False)

    def _publish_own(self) -> None:
        """Every door was taken, which above a handful of people is the normal
        case. Publish an address of our own instead and let it travel by word
        of mouth. It is not derived from the passphrase, so it is reachable
        only by people who were told - which is to say, by the room."""
        try:
            self.address = self.transport.publish(
                private_identity().control_key, self.local_port)
        except OSError:
            self.publish = False        # take part as a client instead

    def _verify_claim(self) -> None:
        """Two peers can decide the same door is free in the same moment, and
        tor will let both publish it - the room then quietly forks. So dial
        the door back once our descriptor has had time to land. Reaching
        ourselves fails at key agreement, because the far end offers our own
        key; a handshake that completes means somebody else is on it too. In
        that case keep the link we just made, stand down, and take an address
        of our own instead."""
        if not self.verifying.acquire(blocking=False):
            return                       # one already running
        try:
            self._verify_claim_locked()
        finally:
            self.verifying.release()

    def _verify_claim_locked(self) -> None:
        door = self.claimed
        if not door:
            return
        if self.stop.wait(random.uniform(*CLAIM_SETTLE)):
            return                       # the room closed while we waited
        try:
            sock = self._connect(door, CONFIRM_TIMEOUT)
            self._forget_socket(sock)
        except OSError:
            return                      # nothing answered: the door is ours
        link = Link(sock, self, door)
        deadline = time.time() + 30
        while time.time() < deadline and link.alive and not link.ready:
            if self.stop.wait(0.5):
                link.drop()
                return
        if not link.ready:
            link.drop()
            return
        greeting = dict(self.hello)
        greeting["id"] = os.urandom(8).hex()
        link.send(greeting)
        link.send({"kind": "peers", "a": self._sample(),
                   "id": os.urandom(8).hex()})
        with self.lock:
            self.links.append(link)
        self.ready.set()
        self.transport.unpublish(door)
        self.address = self.claimed = self.slot = None
        if self.publish:
            self._publish_own()

    # -- word of mouth -----------------------------------------------------

    def _chill(self, address: str) -> None:
        """Pass over an address that turned us away - for a little while at
        first, then longer each time. A flat penalty was the wrong shape: a
        door that happened to be full for a second was shunned for as long as
        one that had gone for good, and a peer short of links could burn
        through everything it knew inside a minute and then sit idle."""
        with self.lock:
            misses = self.misses[address] = self.misses.get(address, 0) + 1
            self.cold[address] = time.time() + min(COLD_MAX,
                                                   COLD_FOR * (2 ** (misses - 1)))

    def _warm(self, address: str) -> None:
        with self.lock:
            self.misses.pop(address, None)
            self.cold.pop(address, None)

    def _sample(self, n: int = PEER_SAMPLE) -> list[str]:
        """Who we are actually talking to, first.

        Drawing uniformly from everything we had ever heard of meant repeating
        other people's hearsay in preference to first-hand knowledge, and a
        dead address deleted by one peer was gossiped straight back by the next
        - so the table filled with addresses nobody could reach and the sample
        got steadily less useful. What we are connected to right now cannot be
        stale: it is answering."""
        with self.lock:
            firsthand = [l.address for l in self.links if l.alive and l.ready
                         and l.address and l.address != self.address]
            hearsay = [a for a in self.known
                       if a != self.address and a not in firsthand]
        random.shuffle(firsthand)
        random.shuffle(hearsay)
        out = (firsthand + hearsay)[:n]
        if self.address:
            out.append(self.address)
        return out

    def _learn(self, addresses, source: str = "") -> None:
        """Word of mouth is how a room grows past its doors, which is also what
        makes it the way to be lied to. One peer reciting thousands of made-up
        addresses would push every real one out and leave us dialling ghosts.
        So each source gets a budget, and an address is only trusted enough to
        be preferred once more than one source has offered it."""
        if not isinstance(addresses, list):
            return
        now = time.time()
        with self.lock:
            spent = [t for t in self.gossiped.get(source, [])
                     if now - t < GOSSIP_WINDOW]
            allowance = GOSSIP_PER_PEER - len(spent)
            for a in addresses[:PEER_SAMPLE * 2]:
                if allowance <= 0:
                    break                # this one has said enough for a while
                if not isinstance(a, str) or a == self.address:
                    continue
                if not valid_onion(a):
                    continue
                if a not in self.known:
                    allowance -= 1
                    spent.append(now)
                    self.known[a] = now
                # an address already on the list keeps the time we first heard
                # of it. refreshing it here made hearsay look like evidence:
                # peers gossip from this table, so dead addresses were quoting
                # each other back into freshness and never ageing out. only
                # actually reaching one counts, and _adopt does that.
                if source:
                    who = self.vouched.setdefault(a, set())
                    if len(who) < CORROBORATED * 4:
                        who.add(source)
            if source:
                self.gossiped[source] = spent
                if len(self.gossiped) > MAX_KNOWN:
                    self.gossiped = {k: v for k, v in self.gossiped.items()
                                     if v and now - v[-1] < GOSSIP_WINDOW}
            if len(self.known) > MAX_KNOWN:
                # least corroborated goes first, then stalest. an invention has
                # exactly one voucher, so a flooder evicts its own lies
                order = sorted(self.known.items(),
                               key=lambda kv: (len(self.vouched.get(kv[0], ())),
                                               kv[1]))
                for a, _ in order[:len(self.known) - MAX_KNOWN]:
                    del self.known[a]
                    self.vouched.pop(a, None)

    def _connect(self, address: str, timeout: float):
        """Dial, remembering the socket while it is still being set up.

        Leaving a room set the stop flag, but a probe already waiting on tor
        stays waiting - up to a minute and a half of it - holding the closed
        room and a circuit the whole time. Hop between rooms and the one you
        left is still spending your circuits. Closing the socket is the only
        thing that ends that wait."""
        def remember(sock):
            with self.lock:
                self._inflight.add(sock)
            if self.stop.is_set():
                try:
                    sock.close()             # closed while we were dialling
                except OSError:
                    pass
        try:
            return self.transport.connect(address, timeout, self.socks_auth,
                                          remember)
        except TypeError:
            return self.transport.connect(address, timeout, self.socks_auth)

    def _note_probe(self, address: str, outcome: str) -> None:
        with self.lock:
            self.probe_notes[address] = (outcome, time.time())
            self.probe_notes.move_to_end(address)
            while len(self.probe_notes) > 64:
                self.probe_notes.popitem(last=False)

    def _forget_socket(self, sock) -> None:
        with self.lock:
            self._inflight.discard(sock)

    def _may_dial(self, address: str) -> bool:
        """The budget is for hearsay only.

        Spending it on everything meant somebody could empty it with a pile of
        invented addresses and leave us unable to reach our actual peers -
        trading a nuisance to strangers for a partition of ourselves. An
        address more than one peer has vouched for is dialled freely; one that
        rests on a single voice is what the budget is for."""
        now = time.time()
        with self.lock:
            if len(self.vouched.get(address, ())) >= CORROBORATED:
                return True
            while self.dials and now - self.dials[0] >= DIAL_WINDOW:
                self.dials.popleft()
            if len(self.dials) >= DIAL_BUDGET:
                return False
            self.dials.append(now)
            return True

    def _dial(self, addresses: list[str]) -> None:
        threads = []
        for address in addresses:
            if not self._may_dial(address):
                continue                 # told about more than we will chase
            with self.lock:
                if address in self.dialing:
                    continue
                self.dialing.add(address)
            t = threading.Thread(target=self._dial_one, args=(address,),
                                 daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=PROBE_TIMEOUT + 10)

    def _dial_one(self, address: str) -> None:
        try:
            sock = self._connect(address, PROBE_TIMEOUT)
            self._forget_socket(sock)
        except Exception:
            with self.lock:
                self.dialing.discard(address)
            self._chill(address)
            return
        with self.lock:
            self.dialing.discard(address)
        self._warm(address)
        self._adopt(sock, address)

    def _gossip_loop(self) -> None:
        while not self.stop.wait(GOSSIP_EVERY * random.uniform(0.8, 1.2)):
            try:
                self.broadcast({"kind": "peers", "a": self._sample(),
                                "id": os.urandom(8).hex()})
            except Exception as exc:
                self.fault("gossip", exc)

    def reap(self) -> None:
        """Close links that have gone quiet. Everyone heartbeats, so silence
        this long means the far end is gone - and without this a room left
        open for days keeps every circuit anyone ever opened to it."""
        now = time.time()
        cutoff = now - LINK_IDLE
        with self.lock:
            stale = [l for l in self.links if l.alive and l.last_heard < cutoff]
            # a peer that answers, agrees keys and then says nothing at all is
            # not a peer. holding the passphrase is enough to sit on a door and
            # swallow whoever knocks on it, so give up and go somewhere else
            mute = [l for l in self.links if l.alive and not l.useful
                    and now - l.opened > DOOR_PATIENCE]
            # never agreed keys at all: not a peer having a bad minute, just
            # somebody holding a socket open. these go far sooner
            mute += [l for l in self.links if l.alive and not l.ready
                     and now - l.opened > KX_PATIENCE and l not in mute]
            for link in mute:
                if link.address:
                    self.misses[link.address] = self.misses.get(link.address, 0) + 1
                    self.cold[link.address] = now + COLD_MAX
        for link in stale + mute:
            link.drop()

    def _refresh_loop(self) -> None:
        # a peer that published after our first sweep is invisible until we
        # look again, so keep looking
        tick = 0
        while not self.stop.wait(RESCAN_EVERY if self._enough()
                                 else RESCAN_EVERY / 3):
            tick += 1
            try:
                self._rotate()
                self._retire()
                self._forget_stale()
                self.reap()
                self.rescan()
                if self.claimed and not tick % DOOR_BACKOFF:
                    # In its own thread. Checking a door means a settle, a
                    # dial with a minute and a half of patience, and a wait
                    # for key agreement - well over two minutes with the
                    # wind against it. Run here, that is two minutes in
                    # which nothing rotates, retires, reaps or reconnects,
                    # every few ticks, for as long as the room is open.
                    if not self.verifying.locked():
                        threading.Thread(target=self._verify_claim,
                                         daemon=True).start()
            except Exception as exc:
                self.fault("connection upkeep", exc)

    # -- links -------------------------------------------------------------

    def _accept_loop(self) -> None:
        while not self.stop.is_set():
            try:
                sock, _ = self.listener.accept()
            except OSError:
                return
            try:
                self._adopt(sock, "")
            except Exception:
                try:             # losing this loop makes us unreachable for
                    sock.close() # the rest of the session, silently
                except OSError:
                    pass

    def _adopt(self, sock: socket.socket, address: str) -> None:
        if not address and self.crowded():
            threading.Thread(target=self._redirect, args=(sock,),
                             daemon=True).start()
            return
        link = Link(sock, self, address)
        with self.lock:
            self.links.append(link)
            if address:
                self.known[address] = time.time()
        self.ready.set()
        greeting = dict(self.hello)
        greeting["id"] = os.urandom(8).hex()
        link.send(greeting)      # queued until key agreement finishes
        link.send({"kind": "peers", "a": self._sample(),
                   "id": os.urandom(8).hex()})

    def _redirect(self, sock: socket.socket) -> None:
        """We are already relaying to as many peers as we should be. Hanging
        up would be the end of it for whoever just arrived: at any size, most
        arrivals reach a door that is already full, and a door is the only
        thing they can compute. So hand over a fistful of addresses first and
        then close. A door is a signpost as much as an entrance."""
        link = Link(sock, self, "")
        try:
            deadline = time.time() + 30
            while time.time() < deadline and link.alive and not link.ready:
                if self.stop.wait(0.2):
                    return
            if link.ready:
                link.send({"kind": "peers", "a": self._sample(PEER_SAMPLE * 2),
                           "id": os.urandom(8).hex()})
                self.stop.wait(3.0)      # let it reach the wire, but not past
                                         # the room closing under us
        finally:
            link.drop()

    def _on_drop(self, link: Link) -> None:
        with self.lock:
            if link in self.links:
                self.links.remove(link)
            fresh = link.address and time.time() - link.opened < FRESH_DROP
        if fresh:
            self._chill(link.address)

    # -- messages ----------------------------------------------------------

    def _flooding(self, sender: str) -> bool:
        """Counted per identity, over bodies we had not already seen. Relayed
        copies and other people's messages never count against you."""
        if not sender:
            return False
        now = time.time()
        with self.lock:
            recent = self.rates.get(sender)
            if recent is None:
                recent = self.rates[sender] = collections.deque()
            while recent and now - recent[0] >= RATE_WINDOW:
                recent.popleft()
            if len(self.rates) > MAX_ROSTER * 2:
                self.rates = {k: v for k, v in self.rates.items()
                              if v and now - v[-1] < RATE_WINDOW}
            if len(recent) >= RATE_LIMIT:
                return True
            recent.append(now)
            return False

    def broadcast(self, obj: dict, skip: Link | None = None) -> None:
        with self.lock:
            links = [l for l in self.links if l.alive and l is not skip]
        for link in links:
            link.send(obj)

    def _dispatch(self, obj: dict, link: Link) -> None:
        try:                         # refuse bodies from outside the window,
            stamp = float(obj.get("ts", time.time()))   # which is what a
        except (TypeError, ValueError, OverflowError):  # replayed capture
            return                                      # looks like
        if not math.isfinite(stamp) or abs(stamp - time.time()) > CLOCK_SLACK:
            return
        sender = str(obj.get("from", ""))
        mid = str(obj.get("id", ""))
        if mid:
            # Keyed on who said it as well as what they called it. On the id
            # alone, any member could silence anybody: relaying shows you the
            # id, and rebroadcasting your own body under that id fills the
            # slot everywhere it reaches first, so the real message is dropped
            # as a duplicate on paths that never went near the attacker. You
            # cannot take somebody else's slot without their signing key.
            fresh = (sender, mid)
            with self.lock:          # several link threads prune this at once
                if fresh in self.seen:
                    return           # a relayed copy, not new traffic
                self.seen[fresh] = time.time()
                if len(self.seen) > MAX_SEEN:
                    self._forget_seen()
        if self._flooding(sender) or link.saturated() or link.minting(sender):
            return           # one identity, one circuit, or a mill of both
        link.useful = True
        if obj.get("kind") == "peers":
            # never relayed: addresses spread because every peer tells its own
            # neighbours, which reaches everyone without flooding anything
            self._learn(obj.get("a"), sender)
            return
        self.on_object(obj, link)
        if obj.get("kind") in RELAYED:
            # the signature travels with the body, so a relay cannot alter it
            self.broadcast(obj, skip=link)

    def close(self) -> None:
        self.stop.set()
        with self.lock:
            links = list(self.links)
        for link in links:
            link.drop()
        with self.lock:                  # end any dial still waiting on tor
            waiting, self._inflight = list(self._inflight), set()
        for sock in waiting:
            try:
                # shutdown, not just close: closing a socket does not wake a
                # thread already blocked reading it, so the dial would sit
                # there to its full timeout regardless
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        try:
            # closing a listening socket does not reliably wake a thread that
            # is already blocked in accept(), so knock on it once. without
            # this every room left a thread behind still holding the whole
            # closed mesh - a leak that only shows if you leave and rejoin
            socket.create_connection(("127.0.0.1", self.local_port),
                                     timeout=2).close()
        except OSError:
            pass
        try:
            self.listener.close()
        except OSError:
            pass
        for address, _ in self.retiring:
            self.transport.unpublish(address)     # never leave one published
        self.retiring = []
        if self.address:
            self.transport.unpublish(self.address)
            self.address = self.claimed = None


# ==========================================================================
# the public room list
# ==========================================================================

class Index:
    def __init__(self, transport, ident=None, publish: bool = True):
        self.secret = public_index()
        self.entries: dict[str, tuple[int, float]] = {}   # name -> (count, seen)
        self.fingerprints: dict[str, str] = {}            # name -> which room owns it
        self.claims: dict[str, dict[str, set]] = {}       # name -> fp -> announcers
        self.announcers: dict[str, set] = {}              # name -> keys announcing it
        self.by_key: dict[str, set] = {}                  # key -> names it announces
        self.mine: str | None = None
        # Six dicts, mutated by every link thread that carries an
        # announcement and read by whoever is drawing the room list. Wrapping
        # the odd iteration in list() was not enough: one uncopied line is a
        # crash, and there is always one more. Reentrant because the handlers
        # below call each other - _on_object into _compact into _forget.
        self.lock = threading.RLock()
        self.started = time.time()
        self.fp = ""
        self.count_fn = lambda: 0
        self.stop = threading.Event()
        self.mesh = Mesh(transport, self.secret, self._on_object,
                         hello={"kind": "hello"}, ident=ident or Identity(),
                         publish=publish, adjacent_epochs=False)

    def start(self) -> None:
        self.started = time.time()
        self.mesh.start()
        self.mesh.broadcast({"kind": "rooms?", "id": os.urandom(8).hex()})
        threading.Thread(target=self._announce_loop, daemon=True).start()

    def entry_ttl(self) -> float:
        """Follows the announce interval, which widens as the list grows."""
        return announce_interval(len(self.entries)) * 4.0

    def _forget(self, name: str) -> None:
        with self.lock:
            self.entries.pop(name, None)
            self.fingerprints.pop(name, None)
            self.claims.pop(name, None)
            for key in self.announcers.pop(name, set()):
                self.by_key.get(key, set()).discard(name)

    def _compact(self) -> None:
        """Drop expired rooms, then any announcer left with nothing to its
        name. The caps used to be enforced by clearing one table outright,
        which left the others pointing at rooms that no longer existed."""
        with self.lock:
            now, ttl = time.time(), self.entry_ttl()
            for name in [n for n, (_, seen) in list(self.entries.items())
                         if now - seen >= ttl and n != self.mine]:
                self._forget(name)
            for key in [k for k, names in list(self.by_key.items()) if not names]:
                del self.by_key[key]

    def rooms(self) -> list[tuple[str, int]]:
        now, ttl = time.time(), self.entry_ttl()
        with self.lock:
            for name in [n for n, (_, seen) in list(self.entries.items())
                         if now - seen >= ttl]:
                self._forget(name)
            return sorted((n, c) for n, (c, _) in self.entries.items()
                          if c > 0)

    def refresh(self) -> None:
        """Look for index peers again, then ask everyone what they know."""
        self.mesh.rescan(force=True)
        self.mesh.broadcast({"kind": "rooms?", "id": os.urandom(8).hex()})

    def find(self, query: str) -> None:
        """Above a few hundred rooms nobody holds the whole list, so a search
        has to be asked rather than filtered locally."""
        with self.lock:
            if query:
                self.mesh.broadcast({"kind": "find", "q": query[:24],
                                     "id": os.urandom(8).hex()})

    def publish(self, name: str, count_fn, fingerprint: str = "") -> None:
        with self.lock:
            self.mine, self.count_fn, self.fp = name, count_fn, fingerprint
            self.fingerprints[name] = fingerprint
            self._announce()

    def unpublish(self, last_one_out: bool) -> None:
        with self.lock:
            name, self.mine = self.mine, None
            if name and last_one_out:
                self.entries.pop(name, None)
                self.mesh.broadcast({"kind": "drop", "room": name,
                                     "id": os.urandom(8).hex()})

    def _announce(self) -> None:
        if not self.mine:
            return
        count = max(1, min(ROOM_LIMIT, self.count_fn()))
        with self.lock:
            name = self.mine
            if not name:
                return
            self.entries[name] = (count, time.time())
            mine = base64.b64encode(self.mesh.ident.edpub).decode()
            self.announcers.setdefault(name, set()).add(mine)
            self.by_key.setdefault(mine, set()).add(name)
        self.mesh.broadcast({"kind": "room", "room": name, "n": count,
                             "fp": self.fp, "id": os.urandom(8).hex()})

    def _announce_loop(self) -> None:
        while not self.stop.wait(announce_interval(len(self.entries))):
            try:
                self._announce()
            except Exception as exc:     # stop announcing and the room falls
                self.mesh.fault("listing", exc)   # off the list while people
                                                  # are still standing in it

    def _push_list(self, link: Link, query: str = "") -> None:
        """A sample, not the whole list: with thousands of rooms open, handing
        the lot to every arrival is a flood in its own right. Repeated gossip
        fills the rest in, and an explicit search asks for what is missing."""
        now, ttl = time.time(), self.entry_ttl()
        with self.lock:
            pool = [(n, c, sorted(self.announcers.get(n, ()))[:1],
                     self.fingerprints.get(n, ""))
                    for n, (c, seen) in self.entries.items()
                    if now - seen < ttl and (not query or query in n)]
        random.shuffle(pool)
        for name, count, said_by, fingerprint in pool[:PUSH_SAMPLE]:
            # marked as hearsay. this is us repeating what somebody else said,
            # under our own signature, and an unmarked copy would make us look
            # like an announcer of a room we have never been in - which is why
            # a room used to outlive everyone in it
            link.send({"kind": "room", "room": name, "n": count, "fwd": True,
                       "by": said_by[0] if said_by else "",
                       "fp": fingerprint,
                       "id": os.urandom(8).hex()})

    def _on_object(self, obj: dict, link: Link) -> None:
        with self.lock:
            kind = obj.get("kind")
            if kind == "hello":
                # whoever just arrived gets a sample of our list, and we ask for theirs
                self._push_list(link)
                link.send({"kind": "rooms?", "id": os.urandom(8).hex()})
            elif kind == "rooms?":
                self._push_list(link)
            elif kind == "find":
                self._push_list(link, clean_name(str(obj.get("q", ""))))
            elif kind == "room":
                # a name from the network is printed to a terminal, so strip it
                # here rather than trusting whoever announced it
                name = clean_name(str(obj.get("room", "")))
                try:
                    count = int(obj.get("n", 0) or 0)
                except (TypeError, ValueError, OverflowError):
                    return
                if not name or not 0 < count <= ROOM_LIMIT or name == self.mine:
                    return
                if obj.get("fwd"):
                    # hearsay seeds a room we had not heard of, and nothing more.
                    # it never refreshes one we already hold, or the room would be
                    # kept alive by people merely repeating each other, and it
                    # never counts as a claim on the name
                    now = time.time()
                    if name not in self.entries and len(self.entries) < MAX_ENTRIES:
                        self.entries[name] = (count, now)
                        # carry whoever actually announced it, so the room can
                        # still be retired by them. without this a room learned
                        # second hand had no owner on record and nothing could
                        # ever take it off the list but the clock
                        said_by = str(obj.get("by", ""))[:64]
                        if said_by:
                            # recorded so the room can still be retired by whoever
                            # opened it - but NOT charged against their quota. this
                            # field comes from whoever forwarded the listing, and
                            # letting hearsay spend someone else's allowance let a
                            # stranger fill it with junk and silence their real
                            # rooms. a quota may only count what a peer said itself
                            self.announcers.setdefault(name, set()).add(said_by)
                    return
                sender = str(obj.get("from", ""))[:64]
                if sender not in self.by_key and len(self.by_key) >= MAX_ENTRIES:
                    self._compact()
                    if len(self.by_key) >= MAX_ENTRIES:
                        return
                mine = self.by_key.setdefault(sender, set())
                if name not in mine and len(mine) >= INDEX_PER_KEY:
                    return                   # one announcer, a handful of rooms
                fp = str(obj.get("fp", ""))[:16]
                # A name goes to the room with the most people announcing it, not
                # simply to whoever spoke first: otherwise one stranger could bind
                # every good name before a real room ever appeared.
                if name not in self.claims and len(self.claims) >= MAX_ENTRIES:
                    self._compact()
                    if name not in self.claims and len(self.claims) >= MAX_ENTRIES:
                        return               # cap the tally, not just the listing
                claims = self.claims.setdefault(name, {})
                if fp not in claims and len(claims) >= 4:
                    return
                holders = claims.setdefault(fp, set())
                if len(holders) < 64:
                    holders.add(sender)
                # A live room keeps its name. Counting announcers looked like the
                # fair way to settle a clash, but signing keys are free to mint -
                # forty of them took the name off a real room, replaced its
                # headcount with a lie, and had the room's own updates refused
                # from then on as the weaker claim. Incumbency cannot be minted.
                incumbent = self.fingerprints.get(name)
                last = self.entries.get(name, (0, 0.0))[1]
                live = bool(incumbent) and time.time() - last < self.entry_ttl()
                if live:
                    if incumbent != fp:
                        return           # somebody is still standing in that room
                else:
                    # nobody holds it, so the tally decides - and on a tie the
                    # newcomer takes it, or a name would stay pinned to a room
                    # that has been empty for hours
                    winner = max(list(claims),
                                 key=lambda f: (len(claims[f]), f != incumbent))
                    if fp != winner:
                        return
                self.fingerprints[name] = fp
                if name not in self.entries and len(self.entries) >= MAX_ENTRIES:
                    # evict the stalest rather than refusing every new room, which
                    # would let one flooder freeze the whole list
                    self._compact()
                    if name not in self.entries and len(self.entries) >= MAX_ENTRIES:
                        # fewest announcers first, staleness only as a tiebreak.
                        # evicting purely by age throws out a real room having a
                        # quiet minute in favour of a flooder's freshest invention
                        others = [(len(self.announcers.get(n, ())), seen, n)
                                  for n, (_, seen) in self.entries.items()
                                  if n != self.mine]
                        if not others:
                            return
                        self._forget(min(others)[2])
                self.entries[name] = (count, time.time())
                self.announcers.setdefault(name, set()).add(sender)
                mine.add(name)
            elif kind == "drop":
                name = clean_name(str(obj.get("room", "")))
                sender = str(obj.get("from", ""))
                # a drop only retires the sender's own claim. anyone can announce a
                # room, so treating a drop as deletion would let a stranger clear
                # the list by announcing a room and immediately dropping it
                holders = self.announcers.get(name)
                if not holders or sender not in holders:
                    return
                holders.discard(sender)
                self.by_key.get(sender, set()).discard(name)
                if not holders:
                    self._forget(name)

    def close(self) -> None:
        self.stop.set()
        self.mesh.close()


# ==========================================================================
# a room
# ==========================================================================

class Chat:
    def __init__(self, transport, room: Room, nick: str, ident=None,
                 publish: bool = True):
        self.room, self.nick = room, nick
        # a fresh key per room, so being in two rooms cannot be correlated
        self.ident = ident or Identity()
        self.inbox: queue.Queue = queue.Queue()
        self.nicks: dict[str, float] = {nick: time.time()}
        self.expect = 0                         # headcount the listing claimed
        self.created = False                    # we made this room deliberately
        self.shown: dict[str, str] = {}         # signing key -> handle we display
        self.owner: dict[str, str] = {}         # handle -> key that got it first
        self.stop = threading.Event()
        self.wake = threading.Event()           # someone arrived; speak up early
        self._count, self._counted = 1, 0.0     # the roster is walked at most
        # every link thread writes the roster and the heartbeat rebuilds it,
        # so a rebuild could catch a write mid-flight and die on the spot
        self.roster = threading.Lock()
        self.unsent: list = []               # typed before anyone could hear
        self.greeted: dict[str, float] = {}     # keys we have announced
        self.mesh = Mesh(transport, room, self._on_object,
                         hello={"kind": "hello", "nick": nick}, ident=self.ident,
                         publish=publish)

    def start(self) -> None:
        self.mesh.start()
        threading.Thread(target=self._heartbeat, daemon=True).start()
        threading.Thread(target=self._announce, daemon=True).start()

    def _announce(self) -> None:
        """Tell the room we are here. The per-link greeting says who we are to
        the peer at the other end of one circuit; this says it to everybody.

        Once. Anyone who links to us after this hears about it a better way:
        a circuit they opened to us is itself the news that they arrived, and
        a circuit we opened to them means they were already here. Repeating
        this to cover the gap cost four floods per arrival, which in a room
        that fills all at once is four times the burst for nothing."""
        # Wait for somebody to tell, not merely for the mesh to be usable.
        # Holding a door makes us reachable and sets that flag within seconds,
        # long before any peer answers - announcing then broadcasts to nought
        # links and the arrival is simply never heard.
        for _ in range(240):
            if self.stop.is_set():
                return
            if any(l.alive and l.ready for l in self.mesh.links):
                break
            time.sleep(0.5)
        else:
            return                       # nobody here to hear it
        if self.stop.wait(1.0):          # let the first links agree keys
            return
        self.mesh.broadcast({"kind": "join", "nick": self.nick,
                             "id": os.urandom(8).hex()})

    def _prune(self) -> None:
        """Drop people who have been gone a while. Without this a room left
        open for days fills its roster with handles nobody is using."""
        with self.roster:
            cut = time.time() - presence_ttl(len(self.nicks))
            self.nicks = {n: when for n, when in self.nicks.items()
                          if when > cut or n == self.nick}
            live = set(self.nicks)
            self.shown = {key: label for key, label in self.shown.items()
                          if label in live}
            folk = {folded(n) for n in live}
            self.owner = {look: key for look, key in self.owner.items()
                          if look in folk}
            gone = time.time() - presence_ttl(len(self.nicks)) * 2
            self.greeted = {k: w for k, w in self.greeted.items() if w > gone}

    def _heartbeat(self) -> None:
        """Without this the roster only decays on a clean goodbye, so a peer
        that vanished would keep a room looking occupied.

        The interval widens with the room, so the presence traffic each peer
        carries does not grow with the headcount. A new arrival would then
        wait a long time to see anyone, so a hello wakes everybody early -
        with a scatter, or a thousand people would answer at once."""
        while not self.stop.is_set():
            woken = self.wake.wait(presence_interval(len(self.nicks)))
            if self.stop.is_set():
                return
            if woken:
                self.wake.clear()
                time.sleep(random.uniform(0.5, 5.0))
                if self.stop.is_set():
                    return
            try:
                if self.unsent:
                    self._flush_unsent()
                self._prune()
                with self.roster:
                    self.nicks[self.nick] = time.time()
                self.mesh.broadcast({"kind": "ping", "nick": self.nick,
                                     "id": os.urandom(8).hex()})
            except Exception as exc:     # if this stops, the room looks empty
                self.mesh.fault("presence", exc)   # to everyone else, for as
                                                   # long as it stays open

    @property
    def hosting(self) -> bool:
        return self.mesh.address is not None

    @property
    def peers(self) -> set:
        with self.roster:
            cut = time.time() - presence_ttl(len(self.nicks))
            return {n for n, t in list(self.nicks.items()) if t > cut}

    @property
    def alone(self) -> bool:
        return self.peers <= {self.nick}

    @property
    def count(self) -> int:
        """Walking a four thousand name roster seven times a second, to put one
        number in a title bar, is work nobody asked for. Once a second is well
        inside how fast presence actually changes."""
        now = time.time()
        if now - self._counted > 1.0:
            self._count, self._counted = len(self.peers), now
        return self._count

    def say(self, text: str) -> None:
        obj = {"kind": "msg", "nick": self.nick, "text": printable(text, MAX_TEXT),
               "ts": time.time(), "id": os.urandom(8).hex()}
        with self.mesh.lock:     # our own copy comes back to us relayed
            self.mesh.seen[(base64.b64encode(self.ident.edpub).decode(),
                            obj["id"])] = time.time()
        self.inbox.put({"type": "msg", "nick": self.nick, "text": obj["text"],
                        "ts": obj["ts"]})
        # Sent to whoever is here, which may be nobody - the headcount in the
        # title bar says which. But "nobody here" and "somebody who is still
        # agreeing keys" look the same from here, and the second lasts a few
        # seconds after a peer appears. A message typed in that window went
        # nowhere at all. So it waits, briefly and only briefly: a message
        # delivered minutes later to whoever wandered in would be a different
        # thing from the one that was typed.
        self.mesh.broadcast(obj)          # queues on any link still settling
        if not any(l.alive and l.ready for l in self.mesh.links):
            with self.roster:
                if len(self.unsent) < MAX_QUEUE:
                    self.unsent.append((time.time(), obj))

    def _flush_unsent(self) -> None:
        """Send anything typed while the first link was still settling."""
        with self.roster:
            waiting, self.unsent = self.unsent, []
        if not waiting:
            return
        now, keep = time.time(), []
        for when, obj in waiting:
            if now - when > SETTLE_HOLD:
                self.inbox.put({"type": "sys",
                                "text": "nobody became reachable in time; "
                                        "that message was not sent"})
            elif any(l.alive and l.ready for l in self.mesh.links):
                self.mesh.broadcast(obj)
            else:
                keep.append((when, obj))
        if keep:
            with self.roster:
                self.unsent = keep + self.unsent

    def _greet(self, sender: str) -> bool:
        """True the first time a key announces itself, so the four repeats of
        one arrival are reported once."""
        if not sender:
            return False
        now = time.time()
        with self.roster:
            when = self.greeted.get(sender)
            if when is not None and now - when < presence_ttl(len(self.nicks)):
                return False
            self.greeted[sender] = now
            return True

    def _label(self, claimed: str, sender: str) -> str:
        """A handle belongs to the key that used it first. Anyone else asking
        for the same one - by accident or on purpose - gets shown with their
        fingerprint attached, so two people are never one name on screen."""
        if not sender:
            return claimed
        warn = ""
        with self.roster:            # never held while this is called, so the
            if sender in self.shown: # two never nest and cannot deadlock
                return self.shown[sender]
            mine = base64.b64encode(self.ident.edpub).decode()
            look = folded(claimed)
            taken = self.owner.get(look,
                                   mine if look == folded(self.nick) else None)
            if taken and taken != sender:
                try:
                    tag = hashlib.sha256(base64.b64decode(sender)).hexdigest()[:4]
                except Exception:
                    tag = "????"
                label = f"{claimed}~{tag}"
                warn = (f"another person is using the handle {claimed}; "
                        f"showing them as {label}")
            else:
                label = claimed
                self.owner[look] = sender
            if len(self.shown) < MAX_ROSTER:
                self.shown[sender] = label
            if len(self.owner) > MAX_ROSTER * 2:  # keys are free to mint, so
                self.owner.clear()                 # this cannot grow forever
        if warn:                     # queued outside the lock: the inbox has
            self.inbox.put({"type": "sys", "text": warn})   # a lock of its own
        return label

    def _on_object(self, obj: dict, link: Link) -> None:
        if self.unsent:                  # somebody is reachable now
            self._flush_unsent()
        kind = obj.get("kind")
        claimed = clean_handle(obj.get("nick", DEFAULT_NICK)) or DEFAULT_NICK
        sender = str(obj.get("from", ""))
        if len(self.nicks) >= MAX_ROSTER or len(self.shown) >= MAX_ROSTER:
            self._prune()            # make room before turning anyone away
        nick = self._label(claimed, sender)
        with self.roster:
            if len(self.nicks) >= MAX_ROSTER and nick not in self.nicks:
                return               # a memory guard, not a limit on the room
            if kind != "bye":
                self.nicks[nick] = time.time()
        if kind == "msg":
            self.inbox.put({"type": "msg", "nick": nick,
                            "text": printable(obj.get("text", ""), MAX_TEXT),
                            # when it got here, not when the sender says it
                            # left. the claimed stamp is theirs to choose
                            # anywhere inside the replay window, which put a
                            # time on screen that nobody could vouch for
                            "ts": time.time()})
        elif kind == "hello":
            # Who dialled whom is the whole of it. A circuit opened towards us
            # is somebody turning up; one we opened is somebody who was here
            # already. No flood, no repeats, and it cannot miss a late arrival
            # the way a single broadcast at the start did.
            if not link.address and nick != self.nick and self._greet(sender):
                self.inbox.put({"type": "sys", "text": f"{nick} has joined"})
                self.wake.set()
            link.send({"kind": "here", "nick": self.nick,
                       "id": os.urandom(8).hex()})
        elif kind == "join":
            # Not "is this nick new to the roster": their per-link greeting
            # arrives first and puts them in it, so that test was always false
            # by the time this ran and an arrival was never announced. Track
            # who we have greeted instead, keyed on the signing key.
            if nick != self.nick and self._greet(sender):
                self.inbox.put({"type": "sys", "text": f"{nick} has joined"})
                # a joiner should not have to wait out a whole heartbeat to
                # find out the room is not empty
                self.wake.set()
        elif kind == "bye":
            with self.roster:
                self.nicks.pop(nick, None)
            with self.roster:
                self.greeted.pop(sender, None)   # so a return is announced
            if nick != self.nick:
                self.inbox.put({"type": "sys", "text": f"{nick} has left"})

    def fingerprints(self) -> str:
        with self.roster:
            by_label = {label: key for key, label in list(self.shown.items())}
        parts = []
        for nick in sorted(self.peers):
            if nick == self.nick:
                parts.append(f"{nick} ({self.ident.fingerprint})")
                continue
            key = by_label.get(nick)
            if key:
                try:
                    parts.append(f"{nick} ({hashlib.sha256(base64.b64decode(key)).hexdigest()[:8]})")
                    continue
                except Exception:
                    pass
            parts.append(nick)
        return ", ".join(parts)

    def close(self) -> None:
        self.stop.set()
        self.wake.set()
        try:
            self.mesh.broadcast({"kind": "bye", "nick": self.nick,
                                 "id": os.urandom(8).hex()})
            time.sleep(0.3)          # let the goodbye reach the wire
        except Exception:
            pass
        self.mesh.close()
        self.nicks.clear()
        self.shown.clear()
        self.owner.clear()


# ==========================================================================
# terminal ui
# ==========================================================================

# Yotsuba B, as closely as a terminal palette allows. The 256 colour cube
# has no exact match for any of these, so each is the nearest cell to the
# real hex value; on an 8 colour terminal it falls back to plain contrasts.
YOTSUBA = {
    "bg": 189,        # #d6daf0  page
    "text": 16,       # #000000  post text
    "name": 29,       # #117743  poster name
    "green": 106,     # #789922  greentext
    "link": 17,       # #0f0c5d  subject and links
    "border": 146,    # #b7c5d9  rules and bars
    "quiet": 60,      # timestamps and asides
}

def pick_glyphs() -> dict:
    """Windows consoles are not always on a unicode code page, and a packaged
    exe is where that bites. Fall back to plain characters rather than drawing
    a screen full of question marks. TALKSHIT_ASCII=1 forces it."""
    fancy = {"rule": "─", "cursor": "›", "dot": "·", "ellipsis": "…",
             "mask": "•", "up": "↑", "down": "↓"}
    plain = {"rule": "-", "cursor": ">", "dot": "-", "ellipsis": "...",
             "mask": "*", "up": "^", "down": "v"}
    if os.environ.get("TALKSHIT_ASCII"):
        return plain
    encoding = (getattr(sys.stdout, "encoding", None)
                or locale.getpreferredencoding(False) or "ascii")
    try:
        "".join(fancy.values()).encode(encoding)
        return fancy
    except (LookupError, UnicodeEncodeError):
        return plain


GLYPH = pick_glyphs()

GOLDEN = (1 + 5 ** 0.5) / 2
WIDE = 100               # columns past which a line is worth reining in

PAIR_TEXT, PAIR_NAME, PAIR_GREEN, PAIR_LINK = 1, 2, 3, 4
PAIR_QUIET, PAIR_BAR, PAIR_ME, PAIR_ALERT = 5, 6, 7, 8
RICH = False


def _setup_colors() -> None:
    """Paint the whole screen, not just the glyphs: yotsuba is a background
    as much as a palette."""
    global RICH
    try:
        curses.start_color()
        curses.use_default_colors()
    except curses.error:
        RICH = False
        return
    RICH = curses.COLORS >= 256
    if RICH:
        c = YOTSUBA
        curses.init_pair(PAIR_TEXT, c["text"], c["bg"])
        curses.init_pair(PAIR_NAME, c["name"], c["bg"])
        curses.init_pair(PAIR_GREEN, c["green"], c["bg"])
        curses.init_pair(PAIR_LINK, c["link"], c["bg"])
        curses.init_pair(PAIR_QUIET, c["quiet"], c["bg"])
        curses.init_pair(PAIR_BAR, c["link"], c["border"])
        curses.init_pair(PAIR_ME, c["link"], c["bg"])
        curses.init_pair(PAIR_ALERT, c["bg"], c["link"])
    else:
        curses.init_pair(PAIR_TEXT, -1, -1)
        curses.init_pair(PAIR_NAME, curses.COLOR_GREEN, -1)
        curses.init_pair(PAIR_GREEN, curses.COLOR_GREEN, -1)
        curses.init_pair(PAIR_LINK, curses.COLOR_BLUE, -1)
        curses.init_pair(PAIR_QUIET, curses.COLOR_CYAN, -1)
        curses.init_pair(PAIR_BAR, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(PAIR_ME, curses.COLOR_WHITE, -1)
        curses.init_pair(PAIR_ALERT, curses.COLOR_BLACK, curses.COLOR_CYAN)


def paint(stdscr) -> None:
    if RICH:
        try:
            stdscr.bkgd(" ", curses.color_pair(PAIR_TEXT))
        except curses.error:
            pass


def char_width(ch: str) -> int:
    """Columns one character occupies. A CJK glyph takes two and a combining
    mark none, so counting characters lets wide text overrun the line."""
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def cell_width(text: str) -> int:
    return sum(char_width(ch) for ch in text)


def wrap_cells(text: str, width: int) -> list[str]:
    """Greedy wrap by display width, breaking a word that cannot fit. The same
    walk as wrap_styled below, with the colours thrown away - system lines are
    one colour throughout, so they only need the text back."""
    return ["".join(t for t, _ in line)
            for line in wrap_styled([(w, PAIR_TEXT) for w in text.split(" ")],
                                    width)]


def body_style(text: str) -> int:
    """Greentext is any line opening with a single >. Two or more is a quote
    of another post, which the site colours as a link instead."""
    stripped = text.lstrip()
    if stripped.startswith(">>"):
        return PAIR_LINK
    if stripped.startswith(">"):
        return PAIR_GREEN
    return PAIR_TEXT


def styled_words(text: str) -> list[tuple[str, int]]:
    """Split a body into words, each carrying the colour it should be drawn in.

    Greentext begins at the first > that opens a word and runs to the end of
    the message, because that is how it reads - the quote is the rest of what
    you said, not just the first word of it. A bare > on its own does not
    start it, so 'a > b' stays a comparison rather than turning the line
    green from the middle."""
    style = PAIR_TEXT
    out: list[tuple[str, int]] = []
    for word in text.split(" "):
        if style == PAIR_TEXT and len(word) > 1 and word.startswith(">"):
            style = PAIR_LINK if word.startswith(">>") else PAIR_GREEN
        out.append((word, style))
    return out


def wrap_styled(words: list[tuple[str, int]],
                width: int) -> list[list[tuple[str, int]]]:
    """Greedy wrap that keeps each word's colour with it."""
    width = max(4, width)
    lines: list[list[tuple[str, int]]] = []
    line: list[tuple[str, int]] = []
    used = 0
    for word, style in words:
        piece, span = word, cell_width(word)
        while span > width:                       # a word wider than the line
            # Walk it once, carrying the width along. Rebuilding the candidate
            # and remeasuring the whole of it for every character made a
            # message with no spaces in it cost a reader a hundred and eighty
            # times an ordinary one - a lever worth taking away from anybody
            # who fancied holding it.
            took = cut = 0
            for ch in piece:
                w = char_width(ch)
                if took + w > width:
                    break
                took += w
                cut += 1
            if line:
                lines.append(line)
                line, used = [], 0
            lines.append([(piece[:cut], style)])
            piece, span = piece[cut:], span - took
        if line and used + span + 1 > width:
            lines.append(line)
            line, used = [(piece, style)], span
        elif line:
            line.append((" " + piece, style))
            used += span + 1
        else:
            line, used = [(piece, style)], span
    if line or not lines:
        lines.append(line)
    return lines


def _render(messages: list[dict], width: int, me: str) -> list[list[tuple[str, int]]]:
    """A line is a run of coloured pieces: the time, the name, then the body.
    The name is green as on the site, and a body opening with > is greentext."""
    out: list[list[tuple[str, int]]] = []
    width = max(24, width)
    for m in messages:
        if m["type"] == "sys":
            quiet = curses.color_pair(PAIR_QUIET) | curses.A_DIM
            for i, line in enumerate(wrap_cells(f"-- {m['text']}", width)):
                out.append([(line if i == 0 else "   " + line, quiet)])
            continue

        stamp = time.strftime("%H:%M", time.localtime(m.get("ts", time.time())))
        name = f"{m['nick']}: "
        head = f"{stamp} "
        name_attr = curses.color_pair(PAIR_NAME)
        if m["nick"] == me:
            name_attr |= curses.A_BOLD
        # A golden measure. Typography has known for centuries that a line
        # running the full width of a wide page is hard to read back - the eye
        # loses its place returning to the left. On a wide terminal the body is
        # held to width/phi and the remainder left as margin; on a narrow one
        # there is nothing to give away, so it takes the lot.
        measure = int(width / GOLDEN) if width >= WIDE else width
        room_for_body = max(10, measure - cell_width(head) - cell_width(name))
        wrapped = wrap_styled(styled_words(m["text"]), room_for_body)
        first = [(t, curses.color_pair(p)) for t, p in wrapped[0]]
        out.append([(head, curses.color_pair(PAIR_QUIET)),
                    (name, name_attr)] + first)
        pad = " " * (len(head) + len(name))
        for extra in wrapped[1:]:
            out.append([(pad, curses.color_pair(PAIR_TEXT))]
                       + [(t, curses.color_pair(p)) for t, p in extra])
    return out


def draw_line(stdscr, row: int, segments, cols: int) -> None:
    column = 0
    for text, attr in segments:
        if column >= cols - 1:
            return
        while cell_width(text) > cols - 1 - column:      # trim by columns
            text = text[:-1]
        try:
            stdscr.addnstr(row, column, text, cols - 1 - column, attr)
        except curses.error:
            return
        column += cell_width(text)


def chat_ui(stdscr, chat: Chat) -> None:
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    _setup_colors()
    paint(stdscr)
    stdscr.timeout(150)
    stdscr.clear()

    messages = [{"type": "sys",
                 "text": f"you are {chat.nick}   {GLYPH['dot']}   type to talk"
                         f"   {GLYPH['dot']}   /who  /faults  /leave"}]
    if not chat.hosting:
        messages.append({"type": "sys", "text": "client only: you reach others, "
                                                "they cannot dial you directly"})
    buf, cur, scroll = "", 0, 0
    told = set()
    # messages only ever arrive at the end, so wrapping the whole backlog on
    # every redraw was throwing away the same work seven times a second
    drawn: list = []
    wrapped_upto, wrapped_at = 0, -1

    while True:
        if not chat.mesh.probing and "settled" not in told:
            told.add("settled")
            if not chat.mesh.links and chat.expect:
                messages.append({"type": "sys",
                                 "text": f"nobody answered, though the list showed "
                                         f"{chat.expect} here - the passphrase is "
                                         f"probably wrong. /leave and try again"})
            elif not chat.mesh.links and not chat.hosting:
                messages.append({"type": "sys",
                                 "text": "nobody reachable yet - someone who can "
                                         "host has to be in the room"})
            elif chat.mesh.mismatched and not chat.mesh.links:
                messages.append({"type": "sys",
                                 "text": f"{chat.mesh.mismatched} peer(s) here "
                                         f"have the passphrase but speak a "
                                         f"different version of talk shit - "
                                         f"one of you is on an older build"})
            elif not chat.mesh.links and not chat.created:
                # a wrong passphrase derives a different set of doors, so it
                # opens a second room wearing the same name rather than
                # failing. from in here the two look identical, and the only
                # honest thing is to say so rather than pick one
                messages.append({"type": "sys",
                                 "text": "nobody here yet. either you are first, "
                                         "or the passphrase differs from theirs "
                                         "- a wrong one quietly opens a "
                                         "different room of the same name"})
                messages.append({"type": "sys",
                                 "text": f"this room is #{chat.room.fingerprint}"
                                         f" - if that does not match what /who "
                                         f"shows them, you are not in the same "
                                         f"room"})
        if chat.mesh.faults and "faults" not in told:
            told.add("faults")
            messages.append({"type": "sys",
                             "text": "something is going wrong in the "
                                     "background - /faults for what"})
        while True:
            try:
                messages.append(chat.inbox.get_nowait())
            except queue.Empty:
                break
        if len(messages) > 500:
            del messages[:-500]
            drawn, wrapped_upto = [], 0      # the front moved; start again

        rows, cols = stdscr.getmaxyx()
        stdscr.erase()
        # in, or still looking. probing stays true for the whole background
        # sweep, so reading it here left the bar saying "connecting" at
        # somebody who was already talking
        settled = chat.mesh.address or chat.mesh.links
        state = f"{chat.count} here" if settled else "connecting"
        mode = "tor" if chat.hosting else "tor/client"
        head = f" talk shit  /{chat.room.name}/  {chat.nick}  {state}  {mode} "
        stdscr.addnstr(0, 0, head.ljust(cols), cols - 1,
                       curses.color_pair(PAIR_BAR) | curses.A_BOLD)

        body_h = max(1, rows - 3)
        if cols - 1 != wrapped_at:
            drawn, wrapped_upto, wrapped_at = [], 0, cols - 1
        if wrapped_upto < len(messages):
            drawn += _render(messages[wrapped_upto:], wrapped_at, chat.nick)
            wrapped_upto = len(messages)
        lines = drawn
        scroll = max(0, min(scroll, max(0, len(lines) - body_h)))
        start = max(0, len(lines) - body_h - scroll)
        for i, segments in enumerate(lines[start:start + body_h]):
            draw_line(stdscr, 1 + i, segments, cols)
        try:
            stdscr.addnstr(rows - 2, 0, GLYPH["rule"] * (cols - 1), cols - 1,
                           curses.color_pair(PAIR_LINK) | curses.A_DIM)
        except curses.error:
            pass

        prompt = "> "
        avail = max(4, cols - len(prompt) - 1)
        left = max(0, cur - avail + 1)
        typing = buf[left:left + avail]
        stdscr.addnstr(rows - 1, 0, prompt, cols - 1, curses.color_pair(PAIR_QUIET))
        stdscr.addnstr(rows - 1, len(prompt), typing, cols - 1 - len(prompt),
                       curses.color_pair(body_style(buf)))
        try:
            stdscr.move(rows - 1, len(prompt) + (cur - left))
        except curses.error:
            pass
        stdscr.refresh()

        try:
            ch = stdscr.get_wch()
        except curses.error:
            continue
        except KeyboardInterrupt:
            return

        if isinstance(ch, int):
            if ch in (curses.KEY_BACKSPACE, 8, 127):
                ch = "\x7f"
            elif ch == curses.KEY_LEFT:
                cur = max(0, cur - 1); continue
            elif ch == curses.KEY_RIGHT:
                cur = min(len(buf), cur + 1); continue
            elif ch == curses.KEY_HOME:
                cur = 0; continue
            elif ch == curses.KEY_END:
                cur = len(buf); continue
            elif ch == curses.KEY_PPAGE:
                scroll += body_h // 2; continue
            elif ch == curses.KEY_NPAGE:
                scroll = max(0, scroll - body_h // 2); continue
            elif ch == curses.KEY_DC:
                buf = buf[:cur] + buf[cur + 1:]; continue
            elif ch == curses.KEY_ENTER:
                ch = "\n"
            elif ch == curses.KEY_RESIZE:
                try:                       # pdcurses on windows needs telling
                    curses.resize_term(*stdscr.getmaxyx())
                except (curses.error, AttributeError):
                    pass
                stdscr.clear()
                continue
            else:
                continue

        if ch in ("\n", "\r"):
            line, buf, cur = buf.strip(), "", 0
            scroll = 0
            if not line:
                continue
            if line in ("/leave", "/quit", "/q", "/exit"):
                for m in messages:       # drop the transcript on the way out
                    m.clear()
                messages.clear()
                try:
                    curses.curs_set(0)
                except curses.error:
                    pass
                return
            if line == "/faults":
                trouble = chat.mesh.complaints()
                messages.append({"type": "sys",
                                 "text": "; ".join(trouble) if trouble
                                         else "nothing has failed"})
                continue
            if line == "/who":
                role = "" if chat.hosting else "  (you are client only)"
                messages.append({"type": "sys",
                                 "text": "here: " + chat.fingerprints() + role})
                messages.append({"type": "sys",
                                 "text": f"room {chat.room.name} is "
                                         f"#{chat.room.fingerprint} - if that "
                                         f"differs on the other machine, the "
                                         f"passphrases do not match"})
                continue

            if line.startswith("/"):
                messages.append({"type": "sys",
                                 "text": "just /who, /faults and /leave"})
                continue
            chat.say(line)
        elif ch in ("\x7f", "\x08"):     # DEL and BS: which one arrives
            if cur:                         # depends on the terminal
                buf, cur = buf[:cur - 1] + buf[cur:], cur - 1
        elif ch == "\x15":
            buf, cur = buf[cur:], 0
        elif ch == "\x17":
            cut = buf[:cur].rstrip().rfind(" ") + 1
            buf, cur = buf[:cut] + buf[cur:], cut
        elif ch in ("\x03", "\x04"):
            return
        elif isinstance(ch, str) and ch.isprintable():
            buf, cur = buf[:cur] + ch + buf[cur:], cur + 1


# ==========================================================================
# launcher
# ==========================================================================

# The passphrases people reach for first, folded to letters so that
# Password1, PASSWORD, and p@ssword collapse together. Not a serious wordlist
# - an attacker has a hundred million of these - but it turns away the handful
# that a determined guesser would try in the first second, and refusing them
# to the person's face is the only moment we can.
_COMMON = frozenset("""
password passwort letmein welcome admin administrator qwerty qwertyuiop
monkey dragon master shadow superman batman trustno flower hottie loveme
zaqwsx football baseball soccer hockey iloveyou sunshine princess starwars
whatever passphrase secret changeme default temp test testing example
correcthorsebatterystaple abc money freedom ninja access mustang michael
""".split())


def _fold_leet(text: str) -> str:
    # 4 and 3 were transposed here, so this mapped 'p4ssw0rd' to 'pessword'
    # and the whole common-phrase list could be walked past by anybody who
    # typed a number instead of a letter
    table = str.maketrans("@43105$+", "aaelosst")
    return "".join(c for c in text.lower().translate(table) if c.isalnum())


def _repeated_unit(text: str) -> str:
    """The shortest piece that, repeated, makes the whole thing. 'abcabcabc'
    is 'abc'. Saying a weak word twice does not make it a strong one, but it
    did make it long enough to pass, and unrecognisable to a word list."""
    for size in range(1, len(text) // 2 + 1):
        if len(text) % size == 0 and text[:size] * (len(text) // size) == text:
            return text[:size]
    return text


def _forms(text: str) -> set:
    """Every shape a guesser would try. Folding leet before stripping digits
    was turning the '12345' on the end into letters, so the strip found
    nothing and 'g3n3ral12345' sailed past a check meant to catch exactly
    that. Fold and strip in both orders, and compare against the lot."""
    plain = "".join(c for c in text.lower() if c.isalnum())
    out = set()
    for step in (plain, plain.rstrip("0123456789"), plain.lstrip("0123456789")):
        for shape in (step, _fold_leet(step)):
            out.add(shape)
            out.add(shape.rstrip("0123456789"))
            out.add(shape.lstrip("0123456789"))
    shapes = {v for v in out if v}
    # Never hand back nothing. A name made only of separators stripped down
    # to an empty string, and an empty set meant every comparison below it
    # quietly passed - the check was skipped rather than failed.
    return shapes or {text.strip().casefold()}


def weak_passphrase(passphrase: str, room: str = "") -> str | None:
    """The only thing standing between a room and the world. Checked here
    rather than in the menu, because every way into a room comes through
    open_room and a check in one branch protects only that branch."""
    if len(passphrase) < MIN_PASSPHRASE:
        return f"too short - use {MIN_PASSPHRASE} characters or more"
    if len(set(passphrase)) < 5:
        return "too repetitive - a few distinct characters at least"
    shapes = _forms(passphrase)
    units = {_repeated_unit(v) for v in shapes}
    if (shapes | units) & _COMMON:
        return "that is one of the first phrases anyone would guess - pick another"
    if any(u != v and len(u) < MIN_PASSPHRASE
           for v in shapes for u in (_repeated_unit(v),)):
        return "that is a short phrase said twice - it is as easy to guess as once"
    if room:
        # The room name is the salt and it is published. Anyone grinding this
        # room starts with the name itself, then the name with a few things
        # stuck on. None of that is worth the scrypt it would cost them.
        names = _forms(room)
        derived = False
        for shape in shapes:
            unit = _repeated_unit(shape)
            if shape in names or unit in names:
                derived = True
                break
            if any(len(shape) - len(n) <= 6
                   and (shape.startswith(n) or shape.endswith(n))
                   for n in names):
                derived = True
                break
        if derived:
            return ("that is the room name with a little on the end - the "
                    "name is public, so it is where anyone would start")
    if len(set(_fold_leet(passphrase))) < 4 and passphrase.isalnum():
        return "too predictable - mix in a few more different characters"
    return None


def bridges_command(args: list[str]) -> None:
    """Bridges hide the fact that you use tor, and get you onto it from a
    network that blocks it. They cost bootstrap speed, so they are opt in."""
    current = read_bridges()
    if args and args[0] == "off":
        set_builtins(False)
        write_bridges([])
        print("bridges off - tor connects directly, which is the default.")
        print("faster and more reliable; your network can see that you use tor.")
        return
    if args and args[0] == "auto":
        print("\n  this connects to bridges.torproject.org in the clear, before")
        print("  tor is running. whoever runs your network will see it, and")
        print("  will be able to tell what you are about to do - which is the")
        print("  thing bridges are meant to prevent. it is worth doing only if")
        print("  your network is merely nosy rather than hostile.")
        print("\n  the built-in bridges are also the most widely blocked ones.")
        print("  bridges you were given privately work far better.")
        try:
            if not input("\n  fetch them anyway? [y/N]: ").strip().lower().startswith("y"):
                print("\n  nothing changed. 'python3 talkshit.py bridges' takes"
                      " lines you paste.\n")
                return
        except (EOFError, KeyboardInterrupt):
            print()
            return
        set_builtins(True)
        write_bridges([])
        lines = fetch_builtin_bridges()
        if lines:
            save_auto(lines)
        print(f"using {len(lines)} built-in bridges" if lines
              else "could not fetch the built-in list; will retry on next start")
        return
    print(f"\n  mode: {'bridges' if bridges_on() else 'direct (the default)'}")
    if not current and read_auto():
        print(f"  using {len(read_auto())} built-in bridges fetched from the tor project")
    if current:
        print(f"\n  {len(current)} bridge line(s) of your own:")
        for line in current:
            print(f"    {line.split()[0]}  {' '.join(line.split()[1:2])} ...")
        print("\n  'talkshit.py bridges off' to stop using them\n")

    print("\n  tor connects directly by default. bridges hide that you use tor")
    print("  and get you onto it where it is blocked, at the cost of speed and")
    print("  reliability. 'bridges auto' uses the built-in list, 'bridges off'")
    print("  returns to direct.")
    print("  get your own lines from https://bridges.torproject.org")
    print("  (or Tor Browser: Settings > Connection > Bridges > Share)")
    print("  paste them one per line, blank line when done:\n")
    lines = []
    while True:
        try:
            line = input("  ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            break
        if len(line.split()) < 2:
            print("  that does not look like a bridge line - skipped")
            continue
        lines.append(line)
    if not lines:
        print("  nothing changed")
        return
    set_builtins(False)          # your own lines take precedence

    _, missing = bridge_config(lines)
    if missing:
        print(f"\n  warning: no binary found for {', '.join(missing)}.")
        print(f"  {transport_hint()}, or tor will refuse to start.")
    write_bridges(lines)
    print(f"\n  saved {len(lines)} bridge line(s) to {BRIDGE_FILE}")
    print("  expect a slower start; bridges are less direct than public relays")


def wipe() -> None:
    """Remove the downloaded tor, and any kept state. By default there is
    nothing else: state lives in a temp directory that goes with the process."""
    removed = []
    for target in {stored_home(), tools_home()}:
        if os.path.isdir(target):
            shutil.rmtree(target, ignore_errors=True)
            removed.append(target)
    if removed:
        for target in removed:
            print(f"removed {target}")
    else:
        print("nothing to remove - talk shit keeps nothing between runs")
    print("message history was never written anywhere to begin with")


def socks_verdict(transport, address: str, timeout: float) -> tuple:
    """Dial an address and report what tor said, as a raw code. Everything in
    the door logic rests on being able to tell "nobody has ever published
    this" apart from "somebody has, and the circuit did not come up"."""
    start = time.time()
    try:
        transport.connect(address, timeout).close()
        return None, "reachable", time.time() - start
    except SocksError as exc:
        return exc.code, str(exc), time.time() - start
    except OSError as exc:
        return 0, str(exc), time.time() - start


def check_empty_door(transport, probe: "Room") -> None:
    # an epoch far enough out that nobody has ever had reason to publish it
    # Looking up a descriptor that does not exist is the slow case: tor has
    # to ask every responsible directory and wait for all of them to come back
    # empty. Straight after bootstrap that can outrun our patience, which is
    # not the same thing as tor answering wrongly - so ask more than once.
    spare = probe.doors_at(door_epoch() + 4096)[0]
    tries = []
    for attempt in range(3):
        code, said, took = socks_verdict(transport, spare.address, PROBE_TIMEOUT)
        tries.append("ok" if code is None else
                     f"0x{code:02X}" if code else "no reply")
        if code is None or code in NO_SUCH_ONION:
            break
        time.sleep(5)
    print(f"  empty door    : {tries[-1]} - {said}  ({took:.0f}s)"
          f"{'   attempts: ' + ' '.join(tries) if len(tries) > 1 else ''}")
    if code is None:
        print("                  IMPOSSIBLE - something answered an address that")
        print("                  has never been published. do not trust this run")
    elif code in NO_SUCH_ONION:
        print("                  correct - an unused door reads as free")
    elif code == 0:
        print("                  no reply at all within the timeout, rather than")
        print("                  a wrong one. the lookup is just slow here, so a")
        print("                  door is only judged free after a second probe -")
        print("                  correct, but it makes joining an empty room slow")
    elif transport.extended:
        print("                  WRONG - extended errors are on, but an unused")
        print("                  door reports something other than 0xF0. no door")
        print("                  will be claimed, so no room can be opened")
    else:
        print("                  plain reply, as expected without extended")
        print("                  errors - doors fall back to a second probe")


def check_round_trip(transport, probe: "Room") -> None:
    """Publish a door and dial it back through tor. The time this takes is the
    number PROBE_TIMEOUT has to be comfortably larger than."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = listener.getsockname()[1]
    stop = threading.Event()
    held: list = []

    def accept():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            # hold it open. closing the instant tor connects sends an RST,
            # which tor reports back as a refusal - the real mesh keeps the
            # socket and runs a handshake on it, so it never looks like this
            held.append(conn)

    threading.Thread(target=accept, daemon=True).start()
    try:
        socket.create_connection(("127.0.0.1", port), timeout=5).close()
        print(f"  local listener: accepting on 127.0.0.1:{port}")
    except OSError as exc:
        print(f"  local listener: NOT reachable - {exc}")
        print("                  nothing else can work until this does")
    door = probe.identities[0]
    try:
        onion = transport.publish(door.control_key, listener.getsockname()[1])
    except OSError as exc:
        print(f"  publishing    : failed - {exc}")
        stop.set(); listener.close()
        return
    print(f"  publishing    : works, address well formed ({valid_onion(onion)})")
    if onion != door.address:
        print(f"                  MISMATCH: tor published {onion[:16]}... but the")
        print(f"                  passphrase derives {door.address[:16]}...")
        print("                  peers would compute a different address to ours")
    start = time.time()
    seen_codes = []
    for _ in range(6):
        code, said, _ = socks_verdict(transport, onion, PROBE_TIMEOUT)
        seen_codes.append("ok" if code is None else f"0x{code:02X}")
        if code is None:
            took = time.time() - start
            print(f"  round trip    : reachable after {took:.0f}s"
                  f"  (PROBE_TIMEOUT is {PROBE_TIMEOUT:.0f}s)")
            print(f"                  attempts: {' '.join(seen_codes)}")
            if took > PROBE_TIMEOUT * 0.6:
                print("                  that is close to the timeout - raise")
                print("                  PROBE_TIMEOUT, or joins will miss peers")
            break
        time.sleep(5)
    else:
        print(f"  round trip    : never reachable - last reply {said}")
        print(f"                  attempts: {' '.join(seen_codes)}")
        last = seen_codes[-1]
        if last == "0x05":
            print("                  the descriptor published and a client found")
            print("                  it - the rendezvous worked. what failed is")
            print("                  this machine connecting to its own listener,")
            print("                  so suspect a local firewall on loopback")
        elif last in ("0xF0", "0xF1"):
            print("                  the descriptor never reached the directories,")
            print("                  so no peer could ever dial us. this is fatal")
        else:
            print("                  tor accepted the onion but dialling it back")
            print("                  did not complete")
    stop.set()
    for conn in held:
        try:
            conn.close()
        except OSError:
            pass
    transport.unpublish(onion)
    listener.close()


def doctor() -> None:
    print("checking tor...")
    print(f"  tor binary : {find_tor() or 'not found (will be downloaded)'}")
    print(f"  data dir   : {HOME}")
    print("  files it writes, and nothing outside them:")
    for path in (HOME, os.path.join(HOME, "tordata"), os.path.join(HOME, "torrc"),
                 os.path.join(HOME, "tor"), BRIDGE_FILE, AUTO_FILE, BRIDGES_ON):
        mark = "present" if os.path.exists(path) else "-"
        print(f"    {path}  ({mark})")
    if not bridges_on():
        print("  bridges    : off (default) - your network can see you use tor")
    else:
        print(f"  bridges    : {len(usable_bridges(active_bridges()))} usable"
              f" ({'your own' if read_bridges() else 'built-in'})")
    transport = start_tor()
    print("  bootstrapped")
    print(f"  socks errors  : {'extended' if transport.extended else 'plain'}"
          f" ({'doors are read exactly' if transport.extended else 'doors need two probes'})")
    probe = Room("doctor", new_passphrase())
    print(f"  doors derived : {len(probe.identities)} unlisted addresses,"
          f" rotating every {DOOR_EPOCH / 60:.0f} min")
    check_empty_door(transport, probe)
    check_round_trip(transport, probe)
    transport.close()
    transport.tor.stop()


def _await(what, seconds: float, note: str = "") -> float:
    """Wait for a condition and report how long it took, or -1 if it never
    came. Every number this self test prints is one of these. It counts out
    loud, because proving a door is empty can take a minute on its own and a
    silent terminal is indistinguishable from a hang."""
    start = time.time()
    while time.time() - start < seconds:
        if what():
            if note:
                print(f"\r    {' ' * 58}\r", end="", flush=True)
            return time.time() - start
        if note:
            print(f"\r    {note}  {int(time.time() - start)}s of {int(seconds)}s ",
                  end="", flush=True)
        time.sleep(0.5)
    if note:
        print(f"\r    {' ' * 58}\r", end="", flush=True)
    return -1.0


def selftest() -> None:
    """Two independent tor instances, one real room, real messages.

    The round trip in 'doctor' publishes and dials from a single tor, which
    may answer out of its own descriptor cache without ever asking the
    directories - so it cannot prove that anybody else could find the onion.
    Two tors share no cache and no guards, so the second has to fetch the
    descriptor the way a stranger would. It is not two networks, but for an
    onion service that is the part that does not matter: both ends dial
    outward through tor either way, whatever is between them and the world.
    """
    print("\n  two tor instances, one room. allow ten minutes: most of it is")
    print("  tor proving that sixteen addresses are unpublished, which is the")
    print("  slowest thing it does.\n")
    print("  starting the first tor...")
    first = start_tor(lambda m: print(f"\r    a{m}   ", end="", flush=True), "-a")
    print("\r    a: ready                    ")
    print("  starting the second tor (its own guards, its own cache)...")
    second = start_tor(lambda m: print(f"\r    b{m}   ", end="", flush=True), "-b")
    print("\r    b: ready                    ")

    name = "selftest-" + os.urandom(3).hex()
    passphrase = new_passphrase(16)
    print(f"\n  room #{name}, a fresh 80 bit passphrase")
    room = Room(name, passphrase)
    print(f"  fingerprint   : #{room.fingerprint}")
    print(f"  doors derived : {len(room.identities)} addresses, epoch {door_epoch()}")

    alice = Chat(first, room, "alice")
    bob = Chat(second, room, "bob")
    ok = True
    try:
        alice.start()
        took = _await(lambda: alice.mesh.address, 420,
                      "alice is looking for a free door")
        print("  alice publishes a door        : "
              + (f"yes, {took:.0f}s" if took >= 0 else "NEVER - fatal"))
        ok &= took >= 0

        print(f"  the door alice took           : slot {alice.mesh.slot}, "
              f"{(alice.mesh.address or '?')[:24]}...")
        print("  bob is now looking for it, with no cached descriptor...")
        bob.start()
        found = _await(lambda: any(l.alive and l.ready for l in bob.mesh.links),
                       420, "bob is knocking on the doors")
        print("  bob reaches alice             : "
              + (f"yes, {found:.0f}s" if found >= 0 else "NEVER - fatal"))
        if found < 0:
            # Say what actually happened rather than leaving it to guesswork.
            wanted = alice.mesh.address or ""
            doors = [d.address for d in room.doors_at(door_epoch())]
            print(f"\n  bob derived the same {len(doors)} doors as alice : "
                  f"{wanted in doors}")
            if wanted and wanted not in doors:
                print("    the two of them are not looking in the same place,")
                print("    which is a derivation or clock problem, not tor")
            notes = dict(bob.mesh.probe_notes)
            said = notes.get(wanted)
            print(f"  what bob saw at alice's door  : "
                  f"{said[0] if said else 'never knocked on it'}")
            print(f"  what bob saw at the other {len(doors) - 1:>2}  :")
            tally: dict = {}
            for door in doors:
                if door == wanted:
                    continue
                tally[notes.get(door, ("not reached", 0))[0]] = tally.get(
                    notes.get(door, ("not reached", 0))[0], 0) + 1
            for outcome, n in sorted(tally.items(), key=lambda kv: -kv[1]):
                print(f"      {n:>2} x {outcome}")
            print(f"  bob took a door of his own    : "
                  f"{bob.mesh.claimed is not None}")
            print(f"  still sweeping when it gave up: {bob.mesh.probing}")
        ok &= found >= 0

        if found >= 0:
            for sender, receiver, who in ((alice, bob, "alice -> bob"),
                                          (bob, alice, "bob -> alice")):
                token = "ping-" + os.urandom(4).hex()
                start = time.time()
                sender.say(token)
                got = -1.0
                while time.time() - start < 90:
                    try:
                        item = receiver.inbox.get(timeout=0.5)
                    except queue.Empty:
                        continue
                    if item.get("type") == "msg" and item.get("text") == token:
                        got = time.time() - start
                        break
                verdict = (f"arrived in {got:.1f}s" if got >= 0
                           else "NEVER ARRIVED - fatal")
                print(f"  message {who:<14}      : " + verdict)
                ok &= got >= 0
            seen = _await(lambda: alice.count >= 2 and bob.count >= 2, 180,
                          "waiting for both rosters")
            print("  both rosters show two people  : "
                  + (f"yes, {seen:.0f}s" if seen >= 0 else "no"))
    finally:
        alice.close()
        bob.close()
        first.close()
        second.close()
        first.tor.stop()
        second.tor.stop()

    if ok:
        print("\n  PASS - descriptors reach the directories, and a peer holding no")
        print("         cache of its own can find them. two machines on two")
        print("         networks exercise nothing further about the onion path.")
    else:
        print("\n  FAIL - see the fatal line above. this is exactly the thing the")
        print("         loopback harness was never able to tell you.")


def printable(raw: str, limit: int) -> str:
    """Handles and message bodies are written straight to a terminal, so a
    peer could otherwise send escape sequences and repaint the screen. Room
    names were already filtered; these two were not."""
    if not isinstance(raw, str):
        return ""
    out: list = []
    marks = 0
    for ch in raw:
        if not (ch.isprintable() or ch == " "):
            continue
        if unicodedata.combining(ch):
            # A combining mark occupies no columns, so a heap of them sits in
            # a single cell and paints over whatever is drawn around it - the
            # screen repainted without one escape sequence, which is the thing
            # this function is here to stop. Written scripts stack two or
            # three of these; nothing legitimate stacks two hundred.
            if not out or marks >= MAX_MARKS:
                continue
            marks += 1
        else:
            marks = 0
        out.append(ch)
    return "".join(out).strip()[:limit]


def folded(name: str) -> str:
    """What a handle looks like to a reader, rather than what it is in bytes.

    A cyrillic a and a latin a are different strings and identical glyphs, so
    comparing raw text lets somebody wear a handle that is already taken and
    never trip the warning. Three passes: decompose and drop the combining
    marks, so an accent cannot hide a letter; map the cyrillic, greek and
    armenian letters that are drawn like latin ones; and fold the digits that
    get typed for letters. Still not the whole confusables table - that is a
    file of its own - but it now covers the alphabets people actually reach
    for, and whatever slips past still carries a fingerprint on screen."""
    text = unicodedata.normalize("NFKD", name).casefold()
    text = "".join(c for c in text if not unicodedata.combining(c))
    return "".join(_CONFUSABLE.get(ch, ch) for ch in text)


_CONFUSABLE = {
    # cyrillic
    "\u0430": "a", "\u0432": "b", "\u0435": "e", "\u0451": "e", "\u043a": "k",
    "\u043c": "m", "\u043d": "h", "\u043e": "o", "\u043f": "n", "\u0440": "p",
    "\u0441": "c", "\u0442": "t", "\u0443": "y", "\u0445": "x", "\u0455": "s",
    "\u0456": "i", "\u0457": "i", "\u0458": "j", "\u04cf": "i", "\u0461": "w", "\u0475": "v",
    "\u04bb": "h", "\u0501": "d", "\u051b": "q", "\u051d": "w",
    # greek
    "\u03b1": "a", "\u03b2": "b", "\u03b3": "y", "\u03b5": "e", "\u03b7": "n",
    "\u03b9": "i", "\u03ba": "k", "\u03bc": "u", "\u03bd": "v", "\u03bf": "o",
    "\u03c1": "p", "\u03c3": "s", "\u03c2": "s", "\u03c4": "t", "\u03c5": "u",
    "\u03c7": "x",
    # armenian and the odd latin
    "\u0585": "o", "\u0578": "n", "\u057d": "u", "\u0561": "w",
    "\u0131": "i", "\u0237": "j", "\u0142": "i", "\u00f8": "o", "\u0111": "d",
    "\u0261": "g", "\u1d0f": "o", "\u01dd": "e",
    # digits typed for letters
    "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    # 1, l and i are one another in most terminal fonts, and folding the digit
    # to just one of them left the other wide open - adm1n went unnoticed
    # beside admin. All three become the same letter.
    "1": "i", "l": "i", "|": "i", "!": "i",
    # punctuation that is decoration rather than identity
    "\u2013": "", "\u2014": "", "\u2019": "", "_": "", "-": "", ".": "",
    " ": "",
}


def clean_handle(raw: str, limit: int = 20) -> str:
    """A handle is drawn as '<handle>: ' in front of what was said, so a colon
    inside one lets a single message carry two speakers and read as though
    somebody else said the rest of the line. Nobody needs a colon in a name."""
    return printable(raw, limit).replace(":", "").strip()


def clean_name(raw: str) -> str:
    """Room names are typed by people, sent over the wire by other peers, and
    then printed to a terminal. Anything but plain characters gets dropped:
    an escape sequence in a name could repaint the room list or clear the
    screen. Applied wherever a name enters, not just where one is typed."""
    if not isinstance(raw, str):
        return ""
    name = "".join(c for c in raw.strip().lower()
                   if (c.isalnum() and c.isascii()) or c in "-_ ")
    return " ".join(name.split())[:24]


def shortlist(rooms: list[tuple[str, int]], query: str) -> list[tuple[str, int]]:
    """Busiest first - at a few hundred rooms that is the order people want."""
    if query:
        rooms = [r for r in rooms if query in r[0]]
    return sorted(rooms, key=lambda r: (-r[1], r[0]))


def prompt(stdscr, label: str, allow_empty: bool = True,
           hidden: bool = False) -> str | None:
    """One line at the foot of the screen. Returns None if escaped."""
    rows, cols = stdscr.getmaxyx()
    buf = ""
    while True:
        stdscr.move(rows - 1, 0)
        stdscr.clrtoeol()
        shown = GLYPH["mask"] * len(buf) if hidden else buf
        stdscr.addnstr(rows - 1, 0, f" {label} {shown}", cols - 1,
                       curses.color_pair(PAIR_LINK) | curses.A_BOLD)
        stdscr.clrtoeol()
        stdscr.refresh()
        try:
            ch = stdscr.get_wch()
        except curses.error:
            continue
        except KeyboardInterrupt:
            return None
        if isinstance(ch, int):
            if ch in (curses.KEY_BACKSPACE, 8, 127):
                buf = buf[:-1]
            continue
        if ch in ("\n", "\r"):
            if buf or allow_empty:
                return buf
        elif ch in ("\x7f", "\x08"):
            buf = buf[:-1]
        elif ch == "\x1b":
            return None
        elif ch == "\x15":
            buf = ""
        elif ch.isprintable() and len(buf) < 256:
            buf += ch


def notice(stdscr, text: str, pause: bool = False) -> None:
    rows, cols = stdscr.getmaxyx()
    hint = "  [enter]" if pause else ""
    # trim the message, never the hint: a prompt the reader cannot see is
    # the same as no prompt at all
    room = max(10, cols - len(hint) - 2)
    body = (text if len(text) <= room
            else text[:room - len(GLYPH["ellipsis"])] + GLYPH["ellipsis"])
    stdscr.move(rows - 1, 0)
    stdscr.clrtoeol()
    stdscr.addnstr(rows - 1, 0, f" {body}{hint}", cols - 1,
                   curses.color_pair(PAIR_ALERT) | curses.A_BOLD)
    stdscr.refresh()
    if pause:
        # Anything typed before this appeared must not dismiss it. Enter for
        # the previous prompt, or a keypress made out of momentum, was landing
        # in the buffer and skipping the message the instant it was drawn.
        stdscr.nodelay(True)
        guard = time.time() + PAUSE_GUARD
        while time.time() < guard:
            try:
                stdscr.get_wch()        # discard, including anything typed
            except (curses.error, KeyboardInterrupt):
                pass                    # during this short guard
            time.sleep(0.03)
        stdscr.nodelay(False)
        stdscr.timeout(-1)              # pdcurses honours this more reliably
        waited = time.time() + PAUSE_LIMIT
        while time.time() < waited:
            try:
                stdscr.get_wch()        # now wait for a key meant for us
                break
            except curses.error:
                time.sleep(0.05)        # windows-curses raises with nothing
            except KeyboardInterrupt:   # pending, so keep waiting rather
                break                   # than treating it as a keypress
        stdscr.timeout(BROWSE_TICK)     # or the browser blocks forever after


def alert(stdscr, text: str) -> None:
    """Anything that happened - an error, an outcome - holds the screen until
    it is acknowledged. Only the ambient line describing the current state is
    allowed to change on its own; a message that flashes past for a third of
    a second may as well not have been shown."""
    notice(stdscr, text, pause=True)


def draw_browser(stdscr, rooms, query, cursor, status) -> list:
    rows, cols = stdscr.getmaxyx()
    found = shortlist(rooms, query)
    body = max(1, rows - 6)
    top = max(0, min(cursor - body + 1, max(0, len(found) - body)))
    stdscr.erase()

    people = sum(c for _, c in rooms)
    header = f" talk shit"
    tally = f"{len(rooms)} rooms {GLYPH['dot']} {people} online "
    stdscr.addnstr(0, 0, header.ljust(cols), cols - 1,
                   curses.color_pair(PAIR_BAR) | curses.A_BOLD)
    if cols > len(tally) + len(header) + 2:
        stdscr.addnstr(0, cols - len(tally) - 1, tally, len(tally),
                       curses.color_pair(PAIR_BAR) | curses.A_BOLD)

    if not found:
        stdscr.addnstr(2, 2, "no rooms yet - ctrl+n makes one, ctrl+o joins "
                       "one by name" if not query
                       else f"nothing matching '{query}'", cols - 3,
                       curses.color_pair(PAIR_QUIET))
    for i, (name, count) in enumerate(found[top:top + body]):
        line = top + i
        mark = GLYPH["cursor"] if line == cursor else " "
        attr = (curses.color_pair(PAIR_ALERT) if line == cursor
                else curses.color_pair(PAIR_LINK))
        # The row is held to the same golden measure as the chat body, so on a
        # wide terminal the name and its headcount stay together instead of
        # drifting a hundred columns apart. On a normal one there is nothing
        # to give away and the row uses the full width, as it always did.
        span = max(24, int((cols - 1) / GOLDEN) if cols - 1 >= WIDE else cols - 1)
        text = f" {mark} /{name}/".ljust(span - 7)[:span - 7] + f"{count:>5}  "
        try:
            stdscr.addnstr(2 + i, 0, text, cols - 1, attr)
        except curses.error:
            pass

    foot = rows - 4
    dot = GLYPH["dot"]
    keys = (f" {GLYPH['up']}{GLYPH['down']} pick {dot} enter join {dot} ctrl+n new"
            f" {dot} ctrl+o by name {dot} ctrl+r refresh {dot} esc back")
    if cell_width(keys) > cols - 1:      # narrow terminal: the rarer ones go
        keys = (f" {GLYPH['up']}{GLYPH['down']} pick {dot} enter join"
                f" {dot} ctrl+n new {dot} ctrl+o by name")
    search = f" search: {query}" if query else " type to search"
    try:
        stdscr.addnstr(foot, 0, GLYPH["rule"] * (cols - 1), cols - 1,
                       curses.color_pair(PAIR_LINK) | curses.A_DIM)
        stdscr.addnstr(foot + 1, 0, search, cols - 1,
                       curses.color_pair(PAIR_NAME) | curses.A_BOLD if query
                       else curses.color_pair(PAIR_QUIET))
        stdscr.addnstr(foot + 2, 0, keys, cols - 1,
                       curses.color_pair(PAIR_QUIET))
        # its own row. it used to share one with the keys above, and cleared
        # them on the way past, so the hints were only ever visible in the
        # moment before there was anything to say
        stdscr.move(rows - 1, 0)
        stdscr.clrtoeol()
        if status:
            stdscr.addnstr(rows - 1, 0, f" {status}", cols - 1,
                           curses.color_pair(PAIR_QUIET))
    except curses.error:
        pass                             # a terminal too small to hold a footer
    stdscr.refresh()
    return found


def browser(stdscr, transport, index: Index, client_only: bool) -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    _setup_colors()
    paint(stdscr)
    stdscr.timeout(BROWSE_TICK)
    query, cursor, status = "", 0, ""
    asked, asked_at = "", 0.0
    refreshing = threading.Event()

    while True:
        rooms = index.rooms()
        # nobody holds the whole list once there are thousands of rooms, so a
        # search that finds little locally is put to the network as well
        if query and query != asked and time.time() - asked_at > FIND_EVERY:
            asked, asked_at = query, time.time()
            index.find(query)
        if not status:
            links = sum(1 for l in index.mesh.links if l.alive)
            waited = int(time.time() - index.started)
            if refreshing.is_set():
                status = "sweeping for rooms..."
            elif index.mesh.probing and not links:
                status = f"looking for other people...  {waited}s"
            elif not links:
                # nobody else is running it: that is a finished answer, not a
                # state we are still working towards
                status = "nobody else online - ctrl+n opens the first room"
            elif not rooms:
                status = f"with {links} others - no rooms open right now"
        found = draw_browser(stdscr, rooms, query, cursor, status)
        status = ""
        cursor = max(0, min(cursor, max(0, len(found) - 1)))

        try:
            ch = stdscr.get_wch()
        except curses.error:
            continue
        except KeyboardInterrupt:
            return

        if isinstance(ch, int):
            if ch == curses.KEY_UP:
                cursor = max(0, cursor - 1)
            elif ch == curses.KEY_DOWN:
                cursor = min(max(0, len(found) - 1), cursor + 1)
            elif ch in (curses.KEY_BACKSPACE, 8, 127):
                query = query[:-1]
            elif ch == curses.KEY_ENTER:
                ch = "\n"
            elif ch == curses.KEY_RESIZE:
                stdscr.clear()
            if not isinstance(ch, str):
                continue

        if ch in ("\n", "\r"):
            if not found:
                continue
            name, count = found[cursor]
            passphrase = prompt(stdscr, f"passphrase for #{name}:",
                                allow_empty=False, hidden=True)
            if passphrase is None:
                continue
            open_room(stdscr, transport, index, name, passphrase,
                      client_only, expect=count)
        elif ch == "\x0e":                      # ctrl+n
            make_room(stdscr, transport, index, client_only)
        elif ch == "\x0f":                      # ctrl+o
            join_by_name(stdscr, transport, client_only)
        elif ch == "\x12":                      # ctrl+r
            # a sweep takes up to half a minute of onion lookups, so it runs
            # behind the ui rather than freezing the keyboard. the sweeping
            # line is a state, not an event, so it does not need dismissing
            if not refreshing.is_set():
                refreshing.set()

                def sweep():
                    try:
                        index.refresh()
                    finally:
                        refreshing.clear()

                threading.Thread(target=sweep, daemon=True).start()
        elif ch == "\x1b":                      # esc
            if query:
                query, cursor = "", 0
            else:
                return
        elif ch in ("\x03", "\x04"):
            return
        elif ch in ("\x7f", "\x08"):
            query = query[:-1]
        elif ch.isprintable():
            query, cursor = (query + ch)[:24], 0


def join_by_name(stdscr, transport, client_only: bool) -> None:
    """For a room that is not in the list, because whoever opened it never
    announced it, or because a squatter is sitting on the doors and hiding it.

    Nothing is announced on the way in. A name handed to you privately stays
    private: listing it here would push it into the public list and undo the
    very thing it was given to you in confidence for."""
    typed = prompt(stdscr, "room name:", allow_empty=False)
    if typed is None:
        return
    name = clean_name(typed)
    if not name:
        alert(stdscr, "a room name needs letters or numbers in it")
        return
    passphrase = prompt(stdscr, f"passphrase for #{name}:",
                        allow_empty=False, hidden=True)
    if passphrase is None:
        return
    open_room(stdscr, transport, Unlisted(), name, passphrase, client_only)


def make_room(stdscr, transport, index: Index, client_only: bool) -> None:
    typed = prompt(stdscr, "room name:", allow_empty=False)
    if typed is None:
        return                    # escaped out
    name = clean_name(typed)
    if not name:
        alert(stdscr, "a room name needs letters or numbers in it")
        return
    if name in dict(index.rooms()):
        alert(stdscr, f"#{name} already exists - pick it from the list instead")
        return
    passphrase = prompt(stdscr, "passphrase (blank makes one up):", hidden=True)
    if passphrase is None:
        return
    passphrase = passphrase or new_passphrase()
    # tell them now rather than after showing the passphrase; open_room still
    # enforces it, this is only so the complaint arrives at the right moment
    complaint = weak_passphrase(passphrase, name)
    if complaint:
        alert(stdscr, f"passphrase {complaint}")
        return
    notice(stdscr, f"#{name} passphrase: {passphrase}  -  share it, "
                   f"nobody without it can find the room", pause=True)
    return open_room(stdscr, transport, index, name, passphrase,
                     client_only, created=True)


def open_room(stdscr, transport, index: Index, name: str, passphrase: str,
              client_only: bool, expect: int = 0, created: bool = False) -> None:
    """Everything that reaches a room comes through here, so this is where
    the passphrase gets checked."""
    name = clean_name(name)
    if not name:
        alert(stdscr, "that room name has nothing usable in it")
        return
    complaint = weak_passphrase(passphrase, name)
    if complaint:
        alert(stdscr, f"passphrase {complaint}")
        return

    # deriving the room key is deliberately expensive (half a second of
    # scrypt, which is what makes a passphrase costly to guess). Start it now
    # and let it run while they type, rather than after.
    derived: dict = {}
    worker = threading.Thread(
        target=lambda: derived.setdefault("room", Room(name, passphrase)),
        daemon=True)
    worker.start()

    handle = prompt(stdscr, "your handle:")
    if handle is None:
        return
    handle = clean_handle(handle) or DEFAULT_NICK

    notice(stdscr, f"connecting to #{name}...")
    worker.join()
    room = derived["room"]
    chat = Chat(transport, room, handle, publish=not client_only)
    chat.expect, chat.created = expect, created
    chat.start()

    # show it counting rather than sitting frozen, and let esc give up
    stdscr.timeout(300)
    started = time.time()
    deadline = started + JOIN_PATIENCE
    while time.time() < deadline:
        if any(l.alive and l.ready for l in chat.mesh.links):
            break                       # somebody is on the other end
        if chat.mesh.address:
            # we hold a door: the room exists and people can reach us, which
            # is the whole of what this wait was for. the rest of the sweep
            # keeps looking for peers behind the chat window - waiting it out
            # here meant sitting on a working room for two more minutes
            break
        if not chat.mesh.probing and chat.mesh.ready.is_set():
            break                       # every door answered; nobody is home
        waited = int(time.time() - started)
        rows, cols = stdscr.getmaxyx()
        stdscr.move(rows - 1, 0)
        stdscr.clrtoeol()
        held = "" if waited < 20 else "  -  tor can take a minute or two"
        stdscr.addnstr(rows - 1, 0,
                       f" knocking on {DOORS} doors for #{name}...  {waited}s"
                       f"{held}   esc to give up",
                       cols - 1, curses.A_DIM)
        stdscr.refresh()
        try:
            key = stdscr.get_wch()
        except curses.error:
            continue                     # nothing typed in this tick
        except KeyboardInterrupt:
            key = "\x03"                 # ctrl+c was being swallowed here, so
                                         # the only way out of a slow join was
                                         # esc or killing the terminal
        if key in ("\x1b", "\x03"):
            chat.close()
            stdscr.timeout(BROWSE_TICK)
            alert(stdscr, f"gave up connecting to #{name}")
            return
    stdscr.timeout(BROWSE_TICK)

    def settle():
        """Only list a room once we know it is real: a mistyped passphrase
        derives different doors, and would otherwise show up as a second
        room of the same name with one confused person in it. Holding a door
        is proof enough - waiting for the whole sweep kept a new room off the
        list for minutes after it had opened."""
        for _ in range(int(JOIN_PATIENCE * 2)):
            if chat.stop.is_set():
                return
            if chat.mesh.links:
                break
            if created and chat.mesh.address:
                break            # a new room is real as soon as we hold a door
            # a joiner holds a door within seconds, well before it reaches
            # anyone. breaking on that too meant a joiner never announced the
            # room it had joined, so the listing rested on its founders alone
            if not chat.mesh.probing:
                break
            time.sleep(0.5)
        if created or chat.mesh.links:
            index.publish(name, lambda: chat.count, room.fingerprint)

    threading.Thread(target=settle, daemon=True).start()
    try:
        chat_ui(stdscr, chat)
    finally:
        index.unpublish(last_one_out=chat.alone)
        chat.close()
        stdscr.clear()
    return


class Unlisted:
    """Stands in for the public index when a room is entered by name. Nothing
    is announced, so the room never shows up in the list and the passphrase is
    the only way to it - which is also what makes it the honest way to test
    whether two machines can find each other at all."""

    def rooms(self) -> list:
        return []

    def publish(self, *_a, **_k) -> None:
        pass

    def unpublish(self, *_a, **_k) -> None:
        pass

    def refresh(self) -> None:
        pass

    def find(self, _query: str) -> None:
        pass

    def close(self) -> None:
        pass


def join_command(name: str, client_only: bool = False) -> None:
    room = clean_name(name)
    if not room:
        sys.exit("  give a room name: talkshit.py join somename")
    try:
        passphrase = getpass.getpass("  passphrase: ")
    except (EOFError, KeyboardInterrupt):
        raise SystemExit(0)
    complaint = weak_passphrase(passphrase, room)
    if complaint:
        sys.exit(f"  passphrase {complaint}")
    print("\n  starting tor, one moment...")
    transport = start_tor(lambda msg: print(f"\r{msg}   ", end="", flush=True))
    print("\r  tor ready              ")
    index = Unlisted()
    try:
        curses.wrapper(lambda stdscr: open_room(
            stdscr, transport, index, room, passphrase, client_only))
    finally:
        transport.close()
        transport.tor.stop()
        clear_screen()


def menu(client_only: bool = False) -> None:
    threading.Thread(target=public_index, daemon=True).start()
    print("\n  starting tor, one moment...")
    transport = start_tor(lambda msg: print(f"\r{msg}   ", end="", flush=True))
    print("\r  tor ready              ")

    index = Index(transport, publish=not client_only)
    index.start()          # the browser opens straight away and fills in

    try:
        curses.wrapper(browser, transport, index, client_only)
    finally:
        index.close()
        transport.close()
        transport.tor.stop()
        # the bootstrap output would otherwise sit in the scrollback
        clear_screen()


def main() -> None:
    watch_for_exit()
    p = argparse.ArgumentParser(description="serverless encrypted chatrooms over tor")
    p.add_argument("cmd", nargs="?",
                   choices=["doctor", "selftest", "wipe", "bridges", "join"])
    p.add_argument("rest", nargs="*",
                   help="join: the room name. bridges: 'auto' for built-ins, "
                        "'off' for a direct connection")
    p.add_argument("-k", "--keep-state", action="store_true",
                   help="keep tor's state and a downloaded tor between runs, "
                        "in the platform's app-data folder. off by default: "
                        "normally nothing is written outside a temp directory "
                        "that is deleted on exit")
    p.add_argument("--purge-on-exit", action="store_true",
                   help="also delete a downloaded tor when the program ends, "
                        "so nothing at all is left; costs the download again "
                        "next time")
    p.add_argument("--no-download", action="store_true",
                   help="never fetch tor; use only an installed one")
    p.add_argument("--bridge", action="append", metavar="LINE", default=[],
                   help="a bridge line to use for this run only, repeatable")
    p.add_argument("-c", "--client", action="store_true",
                   help="take part without hosting an onion service "
                        "(for phones, locked-down networks, or when publishing fails)")
    args = p.parse_args()
    global NO_DOWNLOAD, PURGE_TOR
    NO_DOWNLOAD, PURGE_TOR = args.no_download, args.purge_on_exit
    use_storage(keep=args.keep_state)
    for line in args.bridge:
        safe = clean_bridge(line)
        if safe:
            CLI_BRIDGES.append(safe)
        else:
            sys.exit(f"that does not look like a bridge line: {line[:60]}")
    if args.cmd == "doctor":
        doctor()
    elif args.cmd == "selftest":
        selftest()
    elif args.cmd == "wipe":
        wipe()
    elif args.cmd == "bridges":
        bridges_command(args.rest)
    elif args.cmd == "join":
        join_command(" ".join(args.rest), client_only=args.client)
    else:
        menu(client_only=args.client)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nbye")
    except TorFailed as failure:
        report_tor_failure(failure)
        sys.exit(1)
    finally:
        release_storage()
