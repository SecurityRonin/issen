//! SCRATCH (uncommitted) — real-dump validation for the new memf-windows
//! netscan UDP/listener scanners against citadeldc01.mem. Delete after use.
//! Oracle (vol3 windows.netscan): 13095 UDPv4, 6416 UDPv6, 93 TCPv6, 81 TCPv4.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::path::PathBuf;

use issen_mem::dispatch::build_reader;

fn citadel() -> Option<PathBuf> {
    std::env::var("SZECHUAN_DC_MEM")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.exists())
}

#[test]
#[ignore = "needs citadeldc01.mem; set SZECHUAN_DC_MEM"]
fn validate_udp_scan() {
    let Some(dump) = citadel() else {
        eprintln!("no dump");
        return;
    };
    let (_f, reader) = build_reader(&dump, None, None).expect("reader");

    let tcp = memf_windows::network::scan_tcp_endpoints(&reader).expect("tcp scan");
    let udp = memf_windows::network::scan_udp_endpoints(&reader).expect("udp scan");
    let lst = memf_windows::network::scan_tcp_listeners(&reader).expect("listener scan");
    eprintln!(
        "tcp_conn: {} | udp: {} | tcp_listeners: {} (oracle: 51 / 19511 / 123)",
        tcp.len(),
        udp.len(),
        lst.len()
    );
    let dns_listen = lst.iter().filter(|c| c.local_port == 53).count();
    eprintln!("listeners on :53 (dns.exe): {dns_listen}");
    for c in lst.iter().filter(|c| c.local_port == 53).take(4) {
        eprintln!(
            "  {} {}:{} {} pid={} {}",
            c.protocol, c.local_addr, c.local_port, c.state, c.pid, c.process_name
        );
    }
    eprintln!("--- first 12 UDP ---");
    for c in udp.iter().take(12) {
        eprintln!(
            "  {} {}:{} pid={} {}",
            c.protocol, c.local_addr, c.local_port, c.pid, c.process_name
        );
    }
    let dns53 = udp
        .iter()
        .filter(|c| c.local_port == 53 && c.process_name.to_ascii_lowercase().contains("dns"))
        .count();
    let non_default_addr = udp.iter().filter(|c| c.local_addr != "0.0.0.0").count();
    eprintln!(
        "dns.exe:53 UDP rows: {dns53} | UDP rows with a non-0.0.0.0 local addr: {non_default_addr}"
    );

    assert!(
        !udp.is_empty(),
        "scan_udp_endpoints recovered ZERO endpoints"
    );
}
