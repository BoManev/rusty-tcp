use std::io;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
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
            Ok(p) => {
                let src = p.source_addr();
                let dst = p.destination_addr();
                let proto = p.protocol();
                if proto != IPv4Protocol::TCP.into() {
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + p.slice().len()..]) {
                    Ok(p) => {
                        eprintln!(
                            "{} -> {}:{} {}b TCP",
                            src,
                            dst,
                            p.destination_port(),
                            p.slice().len(),
                        );
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

enum EthProtocol {
    IPv4,
    #[allow(unused)]
    IPv6,
}

impl From<EthProtocol> for u16 {
    fn from(value: EthProtocol) -> Self {
        match value {
            EthProtocol::IPv4 => 0x0800,
            EthProtocol::IPv6 => 0x86dd,
        }
    }
}

enum IPv4Protocol {
    TCP,
    #[allow(unused)]
    ICMP,
}

impl From<IPv4Protocol> for u8 {
    fn from(value: IPv4Protocol) -> Self {
        match value {
            IPv4Protocol::ICMP => 1,
            IPv4Protocol::TCP => 6,
        }
    }
}
