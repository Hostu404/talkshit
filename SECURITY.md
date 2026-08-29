# Reporting a problem

**This protocol has not been audited by anyone.** If you find something, you are
probably the first, and I would rather hear about it than not.

For anything that would let someone read messages they shouldn't, get into a room
without the passphrase, learn who is in one, or work out someone's IP, please
report it privately first — open a [private security advisory][advisory] rather
than a public issue, and give me a reasonable window to fix it before you publish.

[advisory]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

For everything else — crashes, hangs, rooms that don't connect, someone being
able to annoy a room rather than break it — a normal issue is fine and welcome.

## Already known

The README's **Known limits** section is the honest list. Things like "a member
can take a door", "the public room list is unauthenticated" and "timing leaks to
a global observer" are documented consequences of the design, not oversights. If
you find a way to make one of them worse than described, that is worth reporting.

## What is most useful

1. Running it between two machines on different networks and saying what happened.
2. Attacking the protocol. Assume the attacker has this file, because they do.
3. Anything that makes a check quietly stop checking — most bugs found so far
   were of that shape.
