//! Descriptors a worker attaches to a request. A test binary of its own:
//! these tests watch which descriptors stay open, and the Linux one lowers
//! the process's descriptor limit, so nothing else may start programs or
//! open files meanwhile. macOS marks received descriptors close-on-exec
//! only after `recvmsg` returns, so a program started then would inherit
//! one. The tests take `SERIAL` so they do not overlap each other either.

#![cfg(unix)]

use std::fs::{self, File};
use std::io::{ErrorKind, IoSlice, Read};
use std::mem::MaybeUninit;
use std::net::Shutdown;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use fsgate::{Broker, Gate, Rights};
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};

/// The most descriptors Linux lets one message carry (`SCM_MAX_FD`).
/// macOS allows 254.
const MOST_PER_MESSAGE: usize = 253;

fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn frame(body: &serde_json::Value) -> Vec<u8> {
    let body = body.to_string();
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(body.as_bytes());
    frame
}

fn send_with_descriptors(client: &UnixStream, bytes: &[u8], fds: &[BorrowedFd<'_>]) {
    let mut space = vec![MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(fds.len()))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(fds)));
    let sent = rustix::net::sendmsg(
        client,
        &[IoSlice::new(bytes)],
        &mut ancillary,
        SendFlags::empty(),
    )
    .expect("send the request");
    assert_eq!(sent, bytes.len());
}

/// Sends one request with `fds` attached, and no more, so the broker can
/// serve the connection on this thread.
fn send_last_request(client: &UnixStream, bytes: &[u8], fds: &[BorrowedFd<'_>]) {
    send_with_descriptors(client, bytes, fds);
    client.shutdown(Shutdown::Write).unwrap();
}

/// Panics unless every copy of `probe`'s peer has been closed.
fn assert_peer_closed(probe: &UnixStream) {
    probe.set_nonblocking(true).unwrap();
    let mut probe = probe;
    match probe.read(&mut [0u8; 1]) {
        Ok(0) => {}
        Ok(_) => panic!("nothing writes to the probe"),
        Err(err) if err.kind() == ErrorKind::WouldBlock => {
            panic!("a descriptor the worker attached is still open")
        }
        Err(err) => panic!("reading the probe failed: {err}"),
    }
}

/// Requests carry no descriptors (RFC 0003). The broker fails a connection
/// that attaches any, acts on nothing, and closes what it received, even
/// as many as one message can carry.
#[test]
fn a_request_that_carries_descriptors_fails_the_connection_closed() {
    let _serial = serial();
    let root = tempfile::tempdir().expect("create temp root");
    let granted = root.path().join("granted");
    let secret_path = root.path().join("outside/secret.txt");
    fs::create_dir(&granted).unwrap();
    fs::create_dir(root.path().join("outside")).unwrap();
    fs::write(&secret_path, b"secret").unwrap();
    let mut gate = Gate::new();
    gate.grant(&granted, Rights::READ | Rights::WRITE | Rights::CREATE)
        .unwrap();

    // One attached descriptor is a file outside the grant. The rest are
    // copies of `held`, so `probe` reads end-of-file only once every one
    // of them is closed.
    let secret = File::open(&secret_path).unwrap();
    let (held, probe) = UnixStream::pair().unwrap();
    let mut attached = vec![secret.as_fd()];
    attached.extend(std::iter::repeat_n(held.as_fd(), MOST_PER_MESSAGE - 1));

    // A request the broker would otherwise serve, with a visible effect.
    let planted = granted.join("planted.txt");
    let (mut client, server) = UnixStream::pair().unwrap();
    let request = serde_json::json!({ "op": "create", "path": planted });
    send_last_request(&client, &frame(&request), &attached);
    drop(attached);
    drop(held);

    let err = Broker::new(gate).serve_conn(server).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData, "{err}");
    assert!(err.to_string().contains("requests carry none"), "{err}");

    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert!(response.is_empty(), "the broker answered the request");
    assert!(!planted.exists(), "the broker acted on the request");
    assert_peer_closed(&probe);
}

/// The first descriptor ends the connection, before the rest of the frame
/// arrives, so a worker cannot pile them up in the broker by splitting one
/// request across many messages.
#[test]
fn the_first_descriptor_ends_a_request_split_across_messages() {
    let _serial = serial();
    let (client, server) = UnixStream::pair().unwrap();
    // Only for a regression, where the broker would wait for the rest of
    // the frame. The refusal does not wait for it.
    server
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let (held, probe) = UnixStream::pair().unwrap();

    // Half of a length prefix, with the connection left open.
    send_with_descriptors(&client, &[1, 0], &[held.as_fd()]);
    drop(held);

    let err = Broker::new(Gate::new()).serve_conn(server).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData, "{err}");
    assert_peer_closed(&probe);
    drop(client);
}

/// With its descriptor table full, or too full for every descriptor a
/// request carries, the broker cannot receive them. Linux reports the
/// message truncated. macOS fails `recvmsg` with `EMFILE` or `EMSGSIZE`,
/// or delivers only the descriptors that fit, which the broker refuses
/// like any other. Either way it fails the connection closed instead of
/// serving the request, audits that once (RFC 0011), and leaves none of
/// the descriptors open.
#[test]
fn a_request_whose_descriptors_cannot_be_received_fails_the_connection_closed() {
    use fsgate::{AuditDecision, AuditEvent, AuditOp, AuditReason, AuditSink};
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    use std::sync::Arc;

    #[derive(Default)]
    struct Capture(Mutex<Vec<AuditEvent>>);
    impl AuditSink for Capture {
        fn event(&self, event: &AuditEvent) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    let _serial = serial();
    let open = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    // How many descriptor numbers stay free above the highest open one.
    for room in [0, MOST_PER_MESSAGE as u64 / 2] {
        let (held, probe) = UnixStream::pair().unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let request = serde_json::json!({ "op": "metadata", "path": "/" });
        send_last_request(&client, &frame(&request), &[held.as_fd(); MOST_PER_MESSAGE]);
        drop(held);
        let sink = Arc::new(Capture::default());
        let mut gate = Gate::new();
        gate.set_audit_sink(sink.clone());

        let highest = fs::read_dir(open)
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
            })
            .max()
            .unwrap();
        let saved = getrlimit(Resource::Nofile);
        let limited = Rlimit {
            current: Some(highest + 1 + room),
            maximum: saved.maximum,
        };
        setrlimit(Resource::Nofile, limited).unwrap();
        let result = Broker::new(gate).serve_conn(server);
        setrlimit(Resource::Nofile, saved).unwrap();

        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData, "room {room}: {err}");
        let message = err.to_string();
        assert!(
            message.contains("could be received") || message.contains("requests carry none"),
            "room {room}: {err}"
        );
        let events = sink.0.lock().unwrap().clone();
        let audited: Vec<_> = events
            .iter()
            .map(|event| (event.op, event.decision, event.reason))
            .collect();
        assert_eq!(
            audited,
            [(
                AuditOp::Request,
                AuditDecision::Deny,
                AuditReason::MalformedFrame
            )],
            "room {room}: {events:?}"
        );
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert!(
            response.is_empty(),
            "room {room}: the broker served a request it could not fully receive"
        );
        // The kernel closed what it could not install; the broker closed
        // the rest.
        assert_peer_closed(&probe);
    }
}
