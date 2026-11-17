//! D-148 proof in TWO separate GitHub-hosted network namespaces/processes.
//! This test-only module is compiled ONLY by `cargo test --features
//! hosted-guest-fixture` in debug mode; the production binary refuses a
//! release build with this feature, and never accepts CI veths as Wi-Fi.
//!
//! Receiver runs the *actual* nearby LAN UDP/TCP selector and the production
//! guest RPK TLS / SAS / Offer / publisher / journal / Complete dispatcher.
//! Sender runs the production Rust Android-sender *engine* behind a synthetic
//! file reader and hosted-only simulated owner gesture; it is NOT Android
//! ART/Keystore and makes no claim about phone hardware.
//!
//! The shell runner sets ONLY each process's own local interface/IP/prefix.
//! Neither process accepts an injected remote candidate or hardcoded peer IP.
//! A peer is discovered exclusively from a received OS UDP packet, or from
//! a freshly accepted TCP socket after same-link validation.
use super::guest_runtime::{route_connection, GuestConfig};
use super::nearby_lan::{self, LocalLink};
use super::UiEvent;
use opendrop_android_sender::sender::{
    connect_guest as connect_sender, prehash_source, prepare_offer,
};
use opendrop_core::guest::GuestAdmission;
use opendrop_core::journal::Journal;
use opendrop_core::nearby::{
    AdvertisedRole, NearbyBeacon, NearbyCandidate, TcpDirection, NEARBY_TCP_PORT, NEARBY_UDP_PORT,
};
use opendrop_linux_receiver::storage::LinuxReceiverStorage;
use opendrop_linux_receiver::ForegroundLinuxReceiver;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Cursor};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, RecvTimeoutError},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

const SIZE: usize = 131_123;
const TEST_TIMEOUT: Duration = Duration::from_secs(27);

fn synthetic_bytes() -> Vec<u8> {
    (0..SIZE).map(|index| (index % 251) as u8).collect()
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn case() -> String {
    std::env::var("D148_SCENARIO").expect("CI must explicitly select the network scenario")
}

fn link() -> LocalLink {
    let interface = std::env::var("D148_INTERFACE").unwrap();
    let source = std::env::var("D148_LOCAL_IPV4").unwrap().parse().unwrap();
    let prefix = std::env::var("D148_LOCAL_PREFIX").unwrap().parse().unwrap();
    let link = LocalLink {
        interface,
        source,
        prefix,
    };
    nearby_lan::validate_hosted_netns_link(&link).expect("not the declared live isolated veth");
    link
}

fn is_expected_failure(scenario: &str) -> bool {
    matches!(
        scenario,
        "decline"
            | "sas_decline"
            | "collision"
            | "no_listener"
            | "blocked"
            | "interface_loss"
            | "cancel"
    )
}

fn receiver_run() {
    let scenario = case();
    let local = link();
    let base = PathBuf::from(std::env::var("D148_RECEIVER_ROOT").unwrap());
    let private = base.join("private");
    let destination = base.join("destination");
    fs::create_dir_all(&private).unwrap();
    fs::create_dir_all(&destination).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
    let store = LinuxReceiverStorage::open_private(&private, &destination).unwrap();
    let journal_path = private.join("journal.sqlite");
    if scenario == "collision" {
        fs::write(
            destination.join("d148-synthetic.bin"),
            b"preexisting owner file",
        )
        .unwrap();
    }
    let mut admission = GuestAdmission::new_closed();
    admission.open_for_hosted_guest_fixture(); // TEST-ONLY, owner gesture simulation.
    let guest = Arc::new(GuestConfig {
        identity: Arc::new(crate::ephemeral_guest::create_once().unwrap()),
        admission: Arc::new(Mutex::new(admission)),
        live: Arc::new(Mutex::new(None)),
    });
    let running = Arc::new(AtomicBool::new(true));
    if scenario == "cancel" {
        running.store(false, Ordering::Release);
    }
    let (ui_tx, ui_rx) = mpsc::sync_channel::<UiEvent>(4);
    let ui_running = running.clone();
    let ui_journal = journal_path.clone();
    let ui_scenario = scenario.clone();
    let ui = thread::spawn(move || loop {
        match ui_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(UiEvent::GuestSas(request)) => {
                println!("D148_RECEIVER_SAS={}", request.provisional.displayed_code());
                let answer = if ui_scenario == "sas_decline" {
                    None
                } else {
                    Some(
                        request
                            .provisional
                            .approve_sas_for_hosted_guest_fixture()
                            .unwrap(),
                    )
                };
                request.result.send(answer).unwrap();
            }
            Ok(UiEvent::GuestOffer(request)) => {
                let actual = request.offer.file_offer();
                let payload = synthetic_bytes();
                let matches_exact_offer = actual.name == "d148-synthetic.bin"
                    && actual.bytes == payload.len() as u64
                    && actual.sha256.as_str() == sha256(&payload);
                assert!(matches_exact_offer, "unapproved offered metadata rejected");
                if ui_scenario == "decline" {
                    request.result.send(None).unwrap();
                    println!("D148_OWNER_EXACT_OFFER=DECLINE_SIMULATED");
                } else {
                    println!("D148_OWNER_EXACT_OFFER=ACCEPT_SIMULATED");
                    let mut journal = Journal::open(&ui_journal).unwrap();
                    let approved = ForegroundLinuxReceiver::after_hosted_guest_fixture_approval(
                        request.verified,
                        request.offer,
                        &mut journal,
                        store.clone(),
                        request.active,
                    )
                    .unwrap();
                    request.result.send(Some(approved)).unwrap();
                }
            }
            Ok(UiEvent::Status(_)) | Ok(UiEvent::NearbyDiagnostic(_)) | Ok(UiEvent::Offer(_)) => {
                panic!("guest fixture entered forbidden paired-mode owner UI");
            }
            Err(RecvTimeoutError::Timeout) => {
                if !ui_running.load(Ordering::Acquire) {
                    return;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    });
    println!("D148_RECEIVER_WAITING_UDP scenario={scenario}");
    let budget = if matches!(scenario.as_str(), "blocked" | "interface_loss" | "cancel") {
        Duration::from_secs(4)
    } else {
        TEST_TIMEOUT
    };
    let result = nearby_lan::wait_for_hosted_netns(&running, local, budget).and_then(|socket| {
        println!(
            "D148_TCP_SELECTED_FROM_REAL_DISCOVERY local={:?} peer={:?}",
            socket.local_addr().unwrap(),
            socket.peer_addr().unwrap()
        );
        route_connection(socket, None, Some(&guest), &journal_path, &ui_tx, &running)
            .map_err(io::Error::other)
    });
    running.store(false, Ordering::Release);
    drop(ui_tx);
    ui.join().unwrap();
    let publication = destination.join("d148-synthetic.bin");
    if is_expected_failure(&scenario) {
        assert!(result.is_err(), "a rejected guest must not complete");
        if scenario == "collision" {
            assert_eq!(fs::read(&publication).unwrap(), b"preexisting owner file");
        } else {
            assert!(!publication.exists(), "no publication on failed sharing");
        }
        println!("D148_NEGATIVE_RECEIVER_FAIL_CLOSED={scenario}");
        return;
    }
    result.unwrap();
    let actual = fs::read(&publication).unwrap();
    let expected = synthetic_bytes();
    assert_eq!(actual, expected);
    let journal = rusqlite::Connection::open(&journal_path).unwrap();
    let committed: i64 = journal
        .query_row(
            "SELECT COUNT(*) FROM transfers WHERE phase='committed'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(committed, 1, "one and only one durable published receipt");
    println!(
        "D148_RECEIVER_COMMITTED sha256={} bytes={} committed={committed}",
        sha256(&actual),
        actual.len()
    );
}

fn accept_sender_hotspot(local: &LocalLink) -> io::Result<TcpStream> {
    // The Rust sender-process emulates the Android hotspot listener role
    // only. Android's real NetworkInterface/Keystore/UI are not running here.
    let listener = TcpListener::bind(SocketAddrV4::new(local.source, NEARBY_TCP_PORT))?;
    listener.set_nonblocking(true)?;
    let udp = UdpSocket::bind(SocketAddrV4::new(local.source, 0))?;
    nearby_lan::bind_one_interface(&udp, local)?;
    udp.set_broadcast(true)?;
    let beacon = NearbyBeacon::fresh(AdvertisedRole::SenderTcpListener)
        .unwrap()
        .encode();
    let broadcast = SocketAddrV4::new(nearby_lan::directed_broadcast(local), NEARBY_UDP_PORT);
    let started = Instant::now();
    let mut announced = 0usize;
    while started.elapsed() < TEST_TIMEOUT {
        udp.send_to(&beacon, broadcast)?;
        announced += 1;
        if announced == 2 {
            println!("D148_DUPLICATE_BEACON_SAME_NONCE_EXPOSURE_ONLY");
        }
        for _ in 0..8 {
            match listener.accept() {
                Ok((socket, address)) => {
                    if let SocketAddr::V4(peer) = address {
                        let candidate = NearbyCandidate::from_packet(
                            &beacon,
                            *peer.ip(),
                            local.source,
                            local.prefix,
                        );
                        if candidate.is_ok()
                            && socket.local_addr()?.ip() == std::net::IpAddr::V4(local.source)
                        {
                            println!("D148_HOTSPOT_ACCEPTED_PEER={peer} beacon_count={announced}");
                            return Ok(socket);
                        }
                    }
                    drop(socket);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            thread::sleep(Duration::from_millis(80));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "CI hotspot listener expired",
    ))
}

fn discover_receiver_lan(local: &LocalLink) -> io::Result<TcpStream> {
    let udp = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, NEARBY_UDP_PORT))?;
    nearby_lan::bind_one_interface(&udp, local)?;
    udp.set_read_timeout(Some(Duration::from_millis(250)))?;
    let started = Instant::now();
    while started.elapsed() < TEST_TIMEOUT {
        let mut buffer = [0u8; 128];
        match udp.recv_from(&mut buffer) {
            Ok((len, SocketAddr::V4(peer))) => {
                let Ok(candidate) = NearbyCandidate::from_packet(
                    &buffer[..len],
                    *peer.ip(),
                    local.source,
                    local.prefix,
                ) else {
                    continue;
                };
                if candidate.sender_tcp_direction() != Ok(TcpDirection::LocalConnects) {
                    continue;
                }
                println!("D148_REAL_UDP_DISCOVERY_RX role=receiver peer={peer} bytes={len}");
                let route = super::reverse_tcp::DirectWifiRoute {
                    interface: local.interface.clone(),
                    source: local.source,
                    peer: candidate.peer,
                };
                return super::reverse_tcp::connect_exact(&route, &AtomicBool::new(true), true);
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "no actual UDP candidate received",
    ))
}

fn sender_run() {
    let scenario = case();
    let local = link();
    let socket = if scenario == "hotspot" {
        accept_sender_hotspot(&local)
    } else if scenario == "no_listener" {
        // Valid same-link UDP ad on an exact private source but NO real TCP
        // listener; the Linux connector must fail, never publish.
        let udp = UdpSocket::bind(SocketAddrV4::new(local.source, 0)).unwrap();
        nearby_lan::bind_one_interface(&udp, &local).unwrap();
        udp.set_broadcast(true).unwrap();
        let beacon = NearbyBeacon::fresh(AdvertisedRole::SenderTcpListener)
            .unwrap()
            .encode();
        for _ in 0..2 {
            udp.send_to(
                &beacon,
                (nearby_lan::directed_broadcast(&local), NEARBY_UDP_PORT),
            )
            .unwrap();
            thread::sleep(Duration::from_millis(200));
        }
        println!("D148_NO_LISTENER_BEACON_SENT");
        return;
    } else {
        discover_receiver_lan(&local)
    }
    .expect("actual network candidate never selected a permitted socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let sender = crate::ephemeral_guest::create_once().unwrap();
    let live = Arc::new(AtomicBool::new(true));
    // This is the real production sender engine and TLS Client, but a hosted
    // synthetic source and hosted-only owner click, not a physical phone.
    let pairing = connect_sender(socket, &sender, live).unwrap();
    println!("D148_SENDER_SAS={}", pairing.displayed_code());
    if scenario == "sas_decline" {
        // The Linux owner fixture denies their SAS gesture.
        assert!(pairing.confirm_for_hosted_fixture().is_err());
        println!("D148_SENDER_REJECTED=sas_decline");
        return;
    }
    let authorized = pairing.confirm_for_hosted_fixture().unwrap();
    let data = synthetic_bytes();
    let (size, digest) = prehash_source(&mut Cursor::new(&data), None).unwrap();
    let offer = prepare_offer(&sender, "d148-synthetic.bin", size, digest).unwrap();
    let mut received_scoped_ready = false;
    let outcome = authorized.send_one(&offer, &mut Cursor::new(&data), |_pending| {
        received_scoped_ready = true; // ephemeral in-process fixture only
        Ok(())
    });
    if matches!(scenario.as_str(), "decline" | "collision") {
        assert!(
            outcome.is_err(),
            "owner rejection/collision must fail sender"
        );
        println!("D148_SENDER_REJECTED={scenario}");
        return;
    }
    let receipt = outcome.unwrap();
    assert_eq!(receipt.transfer_id, *offer.id());
    assert_eq!(receipt.sha256, offer.file_offer().sha256);
    assert_eq!(receipt.bytes, data.len() as u64);
    assert!(received_scoped_ready, "exact Ready credential required");
    println!(
        "D148_SENDER_AUTHENTICATED_COMPLETE sha256={} bytes={} receipt_id={} same_tls_client=true",
        receipt.sha256.as_str(),
        receipt.bytes,
        receipt.transfer_id.as_str()
    );
}

#[test]
#[ignore = "D148 CI only; run inside disposable named Linux network namespace"]
fn hosted_receiver_process_real_udp_tcp_tls_file() {
    assert_eq!(std::env::var("D148_FIXTURE_CI").unwrap(), "isolate-only");
    receiver_run();
}

#[test]
#[ignore = "D148 CI only; Rust-hosted sender process, not Android OS"]
fn hosted_sender_process_real_udp_tcp_tls_file() {
    assert_eq!(std::env::var("D148_FIXTURE_CI").unwrap(), "isolate-only");
    sender_run();
}
