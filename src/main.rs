mod net;
mod tcp;

use net::{EthProtocol, IPv4Protocol};
use std::collections::HashMap;
use std::io;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut connections: HashMap<tcp::Connection, tcp::State> = HashMap::default();
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        // TUN/TAP 3.2 Frame format
        let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        if eth_proto != EthProtocol::IPv4.into() {
            continue;
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dst = ip_header.destination_addr();
                if ip_header.protocol() != IPv4Protocol::TCP.into() {
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(
                    &buf[4 + ip_header.slice().len()..nbytes],
                ) {
                    Ok(tcp_header) => {
                        let payload = 4 + ip_header.slice().len() + tcp_header.slice().len();
                        connections
                            .entry(tcp::Connection {
                                src: (src, tcp_header.source_port()),
                                dst: (dst, tcp_header.destination_port()),
                            })
                            .or_default()
                            .on_packet(ip_header, tcp_header, &buf[payload..nbytes]);
                    }
                    Err(e) => {
                        eprintln!("Failed to parse TCP packet {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to parse IPv4 packet {:?}", e);
            }
        }
    }
}
