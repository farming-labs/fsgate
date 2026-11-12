# RFC 0011: audit what the broker refuses before the gate

- Status: accepted
- Date: 2026-11-10
- Roadmap: [M9](../../ROADMAP.md#m9--review-readiness-and-020)
- Builds on: [RFC 0002](0002-audit-events.md) (audit events), [RFC 0003](0003-broker-protocol.md) (the broker protocol), [RFC 0007](0007-broker-peers.md) (peer checks and the connection limit)
- Revisits: RFC 0007's decision 3

## Problem

A `Broker` audits every request it passes to its gate, through the gate's
sink. It refuses some things before the gate sees them, and those leave
no event:

- **A refused peer.** `serve_with` closes a connection from a uid it does
  not admit, or one whose identity it cannot read.
- **The connection limit.** A connection past `max_connections` is closed
  with no answer.
- **A protocol error.** On an admitted connection, a frame over 1 MiB,
  bytes past the declared length, an attached descriptor, or a request
  that does not parse closes the connection.

These are what RFC 0002 names as a reason to audit: intrusion detection.
Another user probing the socket, or a compromised worker sending a
descriptor or a malformed request, is invisible to the embedder. RFC 0007
decided that a refused peer produces no event, because RFC 0002 events
describe operations on paths. This RFC proposes events that are not about
a path.

## Goals

- Each refusal above produces exactly one event, through the sink already
  installed on the broker's gate.
- An event about a connection names the peer's uid when it can be read.
- No new public API to receive them, and nothing changes for a gate with
  no sink.
- Existing events and their keys are unchanged, so this stays format
  version 1.

## Non-goals

- **Tying operations to a peer.** Events for `open` and the rest still
  come from the gate, which does not know the connection. See open
  question 3.
- **Client-side errors.** A `BrokerGate` that refuses a response is not a
  broker decision.
- **Rate limiting or sampling.** RFC 0002 leaves those to the sink.
- **A connection that ends normally.** A peer that hangs up between
  requests, or in the middle of one, is not refused.

## Design

### Two operations

| `op` | When | `decision` | `reason` |
|---|---|---|---|
| `connect` | `serve_with` accepts a connection | `allow` | `ok` |
| | the peer's uid is not admitted, or cannot be read | `deny` | `peer_refused` |
| | `max_connections` connections are already served | `deny` | `connection_limit` |
| | no thread can be started for it | `deny` | `no_thread` |
| `request` | a frame's length prefix is over 1 MiB | `deny` | `frame_too_large` |
| | the peer sent bytes past the declared length, or attached a descriptor | `deny` | `malformed_frame` |
| | the frame is not a valid request | `deny` | `malformed_request` |

A `request` event is the one event for a request that never reached the
gate. Each closes the connection, as today, so there is at most one per
connection. A request that parses goes to the gate and is audited there,
as today, with its own `op`.

`path`, `grant`, `rights`, `restrictions`, `syscall`, and `notification`
are `null` for both operations. `errno` is `null`.

The `allow` event for `connect` follows RFC 0002's rule of one event per
decision: admitting a peer is a decision, and its uid is what a sink
needs to tell sessions apart. It is open question 1.

### One new key

`peer_uid`, the peer's effective uid as a number, read the way the peer
check reads it: `SO_PEERCRED` on Linux and `getpeereid` on macOS. It is
set for `connect`, and for a `request` event on a connection `serve_with`
accepted, including with `any_peer`, where nothing checks it. It is
`null` when the uid cannot be read, on other platforms, for every other
`op`, and on a connection given to `serve_conn` directly, which the
broker did not accept. Like
`restrictions`, it is added within version 1, and in Rust it is
`AuditEvent::peer_uid: Option<u32>`.

```json
{"v":1,"ts":"2026-11-10T12:00:00.000Z","op":"connect","path":null,"grant":null,"rights":null,"restrictions":null,"decision":"deny","reason":"peer_refused","errno":null,"syscall":null,"notification":null,"peer_uid":1001}
{"v":1,"ts":"2026-11-10T12:00:01.000Z","op":"request","path":null,"grant":null,"rights":null,"restrictions":null,"decision":"deny","reason":"malformed_frame","errno":null,"syscall":null,"notification":null,"peer_uid":1000}
```

### In Rust

`AuditOp` gains `Connect` and `Request`, and `AuditReason` gains
`PeerRefused`, `ConnectionLimit`, `NoThread`, `FrameTooLarge`,
`MalformedFrame`, and `MalformedRequest`. All three types are
`#[non_exhaustive]`, so none of this is a breaking change. The broker
emits through its gate's sink with a crate-private method, so only fsgate
creates events, as RFC 0002 requires.

`serve_with` emits a refused connection's `connect` event on its
accepting thread, before it closes the connection. An admitted one's
`allow` is emitted on the connection's thread before it reads a request,
so it comes before every other event for that connection. `request`
events come from the connection's thread. All are synchronous, as every
event is.

### Compatibility

Sinks see new `op` and `reason` values and a new key. RFC 0002 already
requires JSON tooling to accept unknown values and keys within version 1,
and Rust code to match with a wildcard. The changelog lists the additions
under Added, and RFC 0002 and RFC 0007 are updated to point here.

## What this does not stop

- A peer that connects and hangs up. It is admitted and audited as
  `allow`, and then it ends normally.
- A peer that cannot reach the socket. The owner-only socket refuses it
  in the kernel, which the broker never sees.
- A refusal by Landlock or the kernel to a confined worker. Those never
  reach the broker.

## Testing

Tests drive a real `Broker` over real Unix sockets with a recording sink,
and assert the event and the refusal:

- With `allow_peer_uids` set to a uid other than the test's own, the
  test's connection is refused with `connect`, `deny`, `peer_refused`, and
  its uid, and closed with no answer.
- With `max_connections(1)` and one connection held open, a second is
  refused with `connection_limit`, and the first is still served.
- An admitted connection is `connect`, `allow`, `ok`, with the test's uid.
- A length prefix over 1 MiB, bytes past the declared length, an attached
  descriptor, and invalid JSON each produce one `request` event with their
  reason, and the connection is closed. No gate event follows any of them.
- A connection given to `serve_conn` directly produces `request` events
  with `peer_uid` `null`, and no `connect` event.
- A gate with no sink behaves as today.
- On Linux, `no_thread` is tested in a process of its own, which lowers
  its own `RLIMIT_NPROC` while its broker accepts a connection.

## Alternatives considered

- **Keep RFC 0007's decision.** Refusals stay invisible, including a
  worker that sends a descriptor, which only a compromised worker does.
- **A separate sink for connections.** It would split what the embedder
  already routes through one sink, and add an API.
- **Log to standard error.** A library must not write where its embedder
  did not ask, and a sink is where fsgate's observations go.
- **Put the peer in `path`.** `path` has one meaning, and tooling reads it
  as a path.

## Open questions

1. Should an admitted connection produce an `allow` event? This RFC says
   yes, for one event per decision and the uid of each session. Without
   it, only refusals are recorded.
2. A refused peer can cause events as fast as it can connect, and a slow
   sink slows the accepting thread. This RFC proposes accepting that:
   RFC 0002 makes the sink own backpressure, and only new connections
   wait. Is that enough, or should the broker stop auditing refused peers
   past some rate?
3. Should events for `open` and the rest carry the peer's uid too? That
   needs the gate to know which connection a request came from. It could
   follow as its own RFC.

## Decisions

Accepted in [#73](https://github.com/farming-labs/fsgate/pull/73), with its
open questions answered:

1. An admitted connection produces an `allow` event.
2. The broker does not limit the rate of events. The sink owns
   backpressure, as RFC 0002 says.
3. The peer's uid on `open` and the other operations is left to a later
   RFC.
