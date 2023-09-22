mod net;
mod tcp;

use std::collections::HashMap;

fn main() -> Result<(), anyhow::Error> {
    let mut connections: HashMap<tcp::Hosts, tcp::Connection> = HashMap::default();

    let mut nic;
    let mut buf;
    #[cfg(feature = "tt_package_info")]
    {
        nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
        // Additional 4 bytes (TUN/TAP 3.2)
        buf = [0u8; 1504];
    }
    #[cfg(not(feature = "tt_package_info"))]
    {
        nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
        buf = [0u8; 1500];
    }

    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        #[cfg(feature = "tt_package_info")]
        {
            let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
            let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
            if eth_proto != EthProtocol::IPv4.into() {
                continue;
            }
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dst = ip_header.destination_addr();
                if ip_header.protocol() != etherparse::IpTrafficClass::Tcp as u8 {
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[ip_header.slice().len()..nbytes])
                {
                    Ok(tcp_header) => {
                        use std::collections::hash_map::Entry;
                        let payload = ip_header.slice().len() + tcp_header.slice().len();
                        match connections.entry(tcp::Hosts {
                            src: (src, tcp_header.source_port()),
                            dst: (dst, tcp_header.destination_port()),
                        }) {
                            Entry::Occupied(mut c) => {
                                c.get_mut().on_packet(
                                    &mut nic,
                                    ip_header,
                                    tcp_header,
                                    &buf[payload..nbytes],
                                )?;
                            }
                            Entry::Vacant(e) => {
                                if let Some(conn) = tcp::Connection::accept(
                                    &mut nic,
                                    ip_header,
                                    tcp_header,
                                    &buf[payload..nbytes],
                                )? {
                                    e.insert(conn);
                                }
                            }
                        }
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