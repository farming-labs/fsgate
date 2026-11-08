//! Feeds arbitrary bytes to one broker connection, as a hostile worker
//! would. This covers RFC 0003 frame reassembly, the 1 MiB limit, JSON
//! request parsing, and the gate's path handling behind them.
//!
//! Besides panics, hangs, and sanitizer reports, the target fails if any
//! descriptor the broker sends back reads the file outside the grant.
//!
//! The whole input is queued on the socket before the broker reads it, so
//! how `read_frame` sees the bytes depends on the input alone, not on
//! thread timing, and a saved crash reproduces.

#![no_main]

use std::fs;
use std::io::{self, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::net::Shutdown;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::OnceLock;

use fsgate::{Broker, Gate, Rights};
use libfuzzer_sys::fuzz_target;
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, sockopt};

/// A fixed path, so seeds can name files beneath the grant.
const FIXTURE: &str = "/tmp/fsgate-fuzz";
const SECRET: &[u8] = b"fsgate-fuzz: outside the grant";
/// Larger than one `read_frame` read (64 KiB), so frames can span reads,
/// and small enough to queue under Linux's default socket buffer cap.
const MAX_INPUT: usize = 128 * 1024;
const SOCKET_BUFFER: usize = 1 << 20;

fn broker() -> &'static Broker {
    static BROKER: OnceLock<Broker> = OnceLock::new();
    BROKER.get_or_init(|| {
        let root = Path::new(FIXTURE);
        match fs::DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => panic!("creating {FIXTURE} failed: {err}"),
        }
        // /tmp is shared: use the directory only if it is a real directory
        // that this user owns and nobody else can write.
        let meta = fs::symlink_metadata(root).expect("stat the fixture");
        assert!(
            meta.is_dir()
                && meta.uid() == rustix::process::getuid().as_raw()
                && meta.permissions().mode() & 0o022 == 0,
            "{FIXTURE} is not a private directory owned by this user; remove it"
        );

        let granted = root.join("granted");
        let outside = root.join("outside");
        for dir in [&granted, &granted.join("sub"), &outside] {
            fs::create_dir_all(dir).expect("create fixture directory");
        }
        fs::write(granted.join("a.txt"), b"inside").unwrap();
        fs::write(granted.join("sub/b.txt"), b"inside").unwrap();
        fs::write(outside.join("secret.txt"), SECRET).unwrap();
        for (target, link) in [("../outside/secret.txt", "escape"), ("a.txt", "inner")] {
            let link = granted.join(link);
            let _ = fs::remove_file(&link);
            symlink(target, link).unwrap();
        }

        // READ and LIST only, so no input changes the fixture.
        let mut gate = Gate::new();
        gate.grant(&granted, Rights::READ | Rights::LIST)
            .expect("grant the fixture");
        Broker::new(gate)
    })
}

/// Reads responses until the broker's end is closed, checking every
/// descriptor it sent.
fn check_responses(client: &UnixStream) {
    let mut buf = [0u8; 65536];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(8))];
    loop {
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let received = rustix::net::recvmsg(
            client,
            &mut [IoSliceMut::new(&mut buf)],
            &mut ancillary,
            RecvFlags::empty(),
        )
        .expect("read responses");
        for message in ancillary.drain() {
            if let RecvAncillaryMessage::ScmRights(fds) = message {
                for fd in fds {
                    let mut contents = Vec::new();
                    let _ = fs::File::from(fd).read_to_end(&mut contents);
                    assert_ne!(
                        contents, SECRET,
                        "the broker delivered a file outside the grant"
                    );
                }
            }
        }
        if received.bytes == 0 {
            return;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let broker = broker();
    let (mut client, server) = UnixStream::pair().expect("socketpair");
    for end in [&client, &server] {
        sockopt::set_socket_send_buffer_size(end, SOCKET_BUFFER).expect("raise send buffer");
        sockopt::set_socket_recv_buffer_size(end, SOCKET_BUFFER).expect("raise receive buffer");
    }

    // Queue everything first. Nonblocking, so a buffer too small for the
    // input fails loudly instead of hanging the run.
    client.set_nonblocking(true).unwrap();
    client
        .write_all(data)
        .expect("the socket buffer holds the whole input; lower -max_len");
    client.set_nonblocking(false).unwrap();
    client.shutdown(Shutdown::Write).unwrap();

    // Single-threaded: the broker reads to the end of the input or the
    // first violation, then its end closes and the responses are checked.
    let _ = broker.serve_conn(server);
    check_responses(&client);
});
