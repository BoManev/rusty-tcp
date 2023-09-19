use std::io;

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

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        // TUN/TAP 3.2 Frame format
        let eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        if eth_proto != EthProtocol::IPv4.into() {
            continue;
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(p) => {
                let src = p.source_addr();
                let dst = p.destination_addr();
                let proto = p.protocol();
                eprintln!(
                    "{} -> {} {}b of protocol {}",
                    src,
                    dst,
                    p.payload_len(),
                    proto,
                );
            }
            Err(e) => {
                eprintln!("Failed to parse packet {:?}", e);
            }
        }
    }
    Ok(())
}
