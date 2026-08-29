# talk shit ![tests](https://github.com/Hostu404/talkshit/actions/workflows/tests.yml/badge.svg)

**Encrypted chatrooms with no server, no accounts, and no address to hand out. One Python file.**

You and a friend type the same passphrase. Your computers work out where to meet, and meet there.
Nobody hosts it. Nobody else can find it. When you close the window there's nothing left — no
transcript, no room name, no keys, not even in your scrollback.

```
python3 talkshit.py
```
<img width="634" height="404" alt="image" src="https://github.com/user-attachments/assets/6522c10d-4549-4c6f-a4af-0d39e82e7d6f" />

---

## The idea

Every other private messenger hands you an identifier. An address, a QR code, an invite link, a
username — something you have to send someone before you can talk. That identifier exists whether
you use it or not, and anyone who sees it knows where to knock.

talk shit doesn't have one. A room's passphrase *is* its location: run it through scrypt, derive
sixteen Tor onion addresses, and everyone holding that passphrase computes the same sixteen. The
first people online claim them; everyone else knocks and gets let in.

So a room isn't just private. Without the passphrase you can't compute a single address — there's
nothing to scan for, nothing to enumerate, nothing sitting in a directory waiting to be subpoenaed.
The room doesn't exist until someone who knows the phrase opens it.

## Try it

```
pip install cryptography          # Windows also: pip install windows-curses
python3 talkshit.py
```

Python 3.10+. Tor is used if you have it and offered as a download if you don't — installing it
yourself is tidier, because then talk shit keeps nothing on disk at all.

Hit `ctrl+n`, pick a name, take the generated passphrase, send it to someone. They hit `ctrl+o`,
type the name and phrase, and they're in.

```
 talk shit  /basement/  anon  4 here  tor
 14:22 anon: has anyone actually read the thing
 14:22 jules: >implying
 14:23 anon: fair
```

## What you get

- **No server.** No host, no relay operator, no account, no signup, no bootstrap node.
- **Rooms you can't find.** Addresses come from the passphrase. No passphrase, nothing to look for.
- **Forward secrecy.** A fresh key per connection, inside the room key. Traffic captured today stays
  unreadable even if the passphrase leaks next year.
- **Nobody can wear your name.** Every message is signed. Someone taking your handle shows up with a
  fingerprint stapled to it — including lookalikes, like a Cyrillic `а` in `аdmin`.
- **No IPs.** Everyone meets through Tor circuits, and each room gets its own.
- **Nothing on disk.** No history, no config, no trace. The chat draws on the terminal's alternate
  screen, so it isn't in your scrollback either.
- **A public room list**, if you want one. Searchable, and rooms drop off it seconds after the last
  person leaves. Optional — rooms joined by name are never listed.
- **Doors that move.** Entry addresses rotate hourly, so nobody can camp on them.
- **Greentext**, obviously.

## Usage

```
python3 talkshit.py               browse rooms, search, create or join
python3 talkshit.py join NAME     straight into a room by name, unlisted
python3 talkshit.py doctor        check your Tor and report what works
python3 talkshit.py selftest      two Tor instances, a real room, a real message
python3 talkshit.py bridges       bridge settings, for networks that block Tor
python3 talkshit.py wipe          remove anything it put on disk
```

| Flag | |
|---|---|
| `-c`, `--client` | join without hosting — phones, locked-down networks |
| `-k`, `--keep-state` | keep Tor's state between runs |
| `--purge-on-exit` | delete a downloaded Tor on the way out |
| `--no-download` | never fetch Tor, use only an installed one |
| `--bridge LINE` | a bridge line for this run only |

**Room list:** `↑↓` pick · `enter` join · `ctrl+n` new · `ctrl+o` join by name · `ctrl+r` refresh ·
`esc` back

**In a room:** `/who` · `/faults` · `/leave`

Three ways in, differing in what they tell the world:

| | Listed publicly? | For |
|---|---|---|
| `enter` on a room in the list | already public | joining something open |
| `ctrl+n` | yes | opening a room you want found |
| `ctrl+o` or `join NAME` | **no** | a name someone gave you privately |

## How it works

**Doors.** The passphrase goes through scrypt to derive a room key, and the key derives sixteen onion
addresses — the room's *doors*. You knock on all sixteen at once. Free one? Publish it. All taken?
Publish an address of your own and let the people inside pass it around.

Doors are the way in, not the size of the room. Joining costs sixteen probes whether six people are
inside or six thousand.

**Word of mouth.** Once you're in, peers trade each other's addresses over the encrypted link. That's
what lets a room outgrow its doors, and those addresses never leave the room's own encryption.

**A relay mesh.** Each peer keeps about eight connections and passes on what it receives. A
thousand-person room costs roughly eight thousand circuits instead of the million a full mesh needs.

**Flat presence.** The heartbeat interval widens as a room fills, so background traffic per peer stays
roughly constant however many people show up.

**Rotation.** Doors move to fresh addresses every hour, on a schedule the passphrase and the clock
agree on with no coordination between anyone. Whoever holds a door keeps its slot across the change,
and the old address stays up for ten minutes so nobody is cut off mid-dial.

### Cryptography

| | |
|---|---|
| Room key | scrypt, N=2¹⁶, r=8, p=1, salted with the room name |
| Session keys | ephemeral X25519 per link → HKDF-SHA256 → two AES-256-GCM keys |
| Authenticity | Ed25519 on every message, with the room's fingerprint inside the signature |
| Padding | bodies padded to a multiple of 256 bytes |
| Doors | Ed25519, derived per slot per hour |
| Circuits | one SOCKS isolation bundle per room, so rooms don't share circuits |

Session keys live only in memory and die with the process. That's what makes the traffic forward
secret.

## What's been tested

**End to end over real Tor** — two independent Tor instances with no shared cache or guards, finding
a room from nothing but its passphrase (`selftest`):

| | |
|---|---|
| First peer publishes a door | 6–47s |
| Second peer finds it, no cached descriptor | 13–112s |
| Message latency, each way | 0.1–1.3s |

Those spreads are real, measured on one machine across nine runs. Tor varies enormously: the same
code found a peer in 13s on one run and 112s on another, with nothing changed between them.

Two of those nine runs failed outright, and both were bugs that no amount of loopback testing had
found:

- A message sent in the moment after a peer appears, while key agreement was still finishing, went
  nowhere at all — "nobody is here" and "not ready yet" were being treated as the same thing.
- A door was written off after a single failed rendezvous. Tor reports that as a distinct error from
  "no such onion", but the code lumped it in with "occupied, move on" and never knocked again — so
  the one door with somebody behind it was abandoned while the other fifteen were re-checked.

Both are fixed, and `selftest` now prints what every door said when it fails, so the next surprise
comes with evidence attached instead of guesswork. On Linux and Windows, `doctor` confirms extended SOCKS errors, unused
doors reporting `0xF0` in 4–7s, and published addresses matching what the passphrase derives.

**A test suite** of 342 tests in `tests/` — helpers, crypto, protocol, state, CLI, concurrency,
security, plus Hypothesis property tests. Targeted mutation testing detects 18/18 deliberate bugs.

**In a loopback harness** running the real mesh, links and crypto:

- 30 peers in a room — every message reached every peer, complete roster, zero door collisions
- A four-peer room across 19 door rotations with churn: threads, file handles and roster steady
- 25/25 cryptographic properties: tampering, forgery, key substitution, per-link key independence
- 8/8 adversarial checks: identity minting, gossip flooding, eviction order, socket squatting,
  lookalike handles, large rooms uncapped
- ~80,000 hostile inputs through every parser and message handler, no unhandled exception
- No thread, socket or onion-service leaks across repeated join/leave cycles
- Clocks up to two hours apart still find the same room

**Not yet tested:** two machines on two networks. `selftest` covers the onion path with two
independent Tor instances, but nobody has run it across real machines. And anything above 30 peers —
the harness runs every peer in one process and can't tell protocol trouble from thread starvation
past that. Coverage of the Tor bootstrap and the curses UI is thin for the same reason: neither can
be driven without a real Tor and a real terminal.

## Known limits

Worth knowing before you lean on it.

**This is a new protocol and nobody adversarial has reviewed it.** The primitives are standard and
correctly assembled, and it's been tested hard, but novel protocols are exactly where real attacks
live. If being wrong would have consequences for you, use Signal.

**The passphrase is the whole boundary.** Room names are public salts, so a weak one can be ground
out offline. Generated ones are 60 bits, and each guess costs an attacker a 64 MB scrypt — about four
centuries for someone with a hundred thousand GPUs. Hand-picked phrases are the soft spot: obvious
ones are refused, but a wordlist this small can't catch everything, so take the generated one.
Anyone holding the phrase is a member forever — removing someone means a new passphrase.

**Timing leaks.** Contents and lengths are hidden; *when* bytes move is not. Someone watching many
points in the network at once can correlate your bursts against everyone else's. Tor doesn't defend
against this either — it's outside its threat model rather than a gap here. Doing it properly needs
constant-rate cover traffic, which this doesn't do.

**The public room list is deliberately unauthenticated.** Anyone can read it, list fake rooms, or
squat its doors and an unused name. A name in use can't be taken — a live room keeps it — but nothing
stops someone claiming a name nobody is standing in. It's a noticeboard, not a security boundary.
Rooms themselves need the passphrase and are unaffected.

**A member can take a door off you.** Doors are surrendered on collision so two honest peers never
split a room in half, and someone holding the passphrase can trigger that deliberately.

**A member who took every door could control what newcomers see.** A newcomer links to whoever
answers the doors — several of them, normally, so no single one decides what it hears. Take all
sixteen and that stops being true. It doesn't let anyone forge messages, but it does let them decide
which ones arrive.

**A member can replay a message to someone who arrived later**, within the clock window, making an
old line look freshly said. Peers who already saw it aren't fooled — each speaker keeps an equal
share of the duplicate-detection table, so shouting can't push somebody else's messages out of it.

**Handles are first come, first served.** There's no registration, so someone can take a name — or a
lookalike of one — before its usual owner arrives. Whoever came second is shown with a fingerprint
attached, which tells you a clash happened but not who deserves the name.

**Relays can drop messages silently.** There are no acknowledgements. A member can also refuse to
pass yours on, which costs you the peers behind them.

**A flood can cost you connections.** Relaying fills the outbound queue to each neighbour, and a
neighbour whose queue fills is dropped. Rate limits bound how fast this can be driven, but a
determined member can make you shed links.

**A listed room's fingerprint is a free guess-checker.** The public list carries a tag derived from
the room key, so someone testing candidate passphrases against a listed room can check each guess
offline instead of querying Tor. scrypt still costs them ~0.5s and 64 MB per guess, so this only
matters for weak, hand-picked passphrases.

**Anything fetched before Tor is running goes over the clear net**, because there's no Tor yet to
send it through. Downloading Tor itself is one. Fetching the built-in bridge list is the other, and
that one is never done for you — it would connect to `bridges.torproject.org` in front of the network
you're using bridges to hide from. You're told how to get bridges out of band instead, and
`bridges auto` asks before it reaches out.

**The bundled Tor download is checksum-verified, not signature-verified**, and the checksum comes from
the same server as the archive — it catches corruption, not a compromised mirror. Installing Tor from
your distro is better and the program says so.

Also: your shell history records that you ran this, and Python strings can't be wiped, so a memory
dump of a running process could recover a passphrase.

## Prior art

Good company in this space, worth knowing about:

- **[Ricochet Refresh](https://ricochetrefresh.net)** — each user is their own onion service, no
  servers. One-to-one.
- **[TorX](https://torx-chat.github.io/)** — no servers, entirely peer-to-peer, v3 onions, group
  chats. Closest thing to this architecture, and more mature.
- **[Cwtch](https://cwtch.im)** — group chat over Tor, via untrusted relay servers.
- **[Quiet](https://tryquiet.org)** — Slack-shaped, syncs between devices over Tor.
- **[Briar](https://briarproject.org)** and **[OnionShare](https://onionshare.org)** — both worth
  your time.

What none of them do is derive the address from the secret. They all hand you an identifier to share.
That's the one idea here that appears to be new.

## Verifying your copy

One file, no build step:

```
sha256sum talkshit.py
dcc5ec474a60dca5ec5d2457a8cc6d5745ede8373661ee75d70d39a5116debbe
```

## Forks

`PROTOCOL` is sent during key agreement. A fork that changes the padding, key schedule or message
format would otherwise agree keys fine and then silently drop everything, looking like an empty room
to both sides. Bump `PROTOCOL` when you change the wire format and peers will say so out loud.

## Running the tests

```
pip install -r requirements-dev.txt
python3 -m pytest tests/ -q --timeout=400        # 349 tests
python3 tests/harnesses/attack.py                # adversarial protocol checks
STEPS=2 SETTLE=30 python3 tests/harnesses/soak.py 30
```

None of that touches the real Tor network. For that:

```
python3 talkshit.py doctor      # checks your tor and reports what works
python3 talkshit.py selftest    # two tor instances, a real room, a real message
```

## Help wanted

1. **Run it between two machines on different networks** and say what happened. The most useful thing
   anyone can do right now.
2. **Try to break the protocol.** Assume the attacker has this file, because they do.
3. **A real scale test** — peers in separate processes, or a simulation with modelled Tor latency.

## What it leaves behind

Nothing of what was said.

Tor needs a state directory, so one is made in the system temp area at startup and deleted on the way
out. With Tor installed by a package manager, nothing persists at all. `--keep-state` trades the other
way and keeps Tor's entry guards between runs, which Tor's own design considers better for anonymity
over time.

`wipe` removes anything that's left.

<img width="254" height="313" alt="image" src="https://github.com/user-attachments/assets/47c874a1-78f6-4118-8c50-42822fb2256c" />
