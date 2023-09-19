use std::io;

enum Protocol {
    IPv4,
    IPv6,
}

impl From<Protocol> for u16 {
    fn from(value: Protocol) -> Self {
        match value {
            Protocol::IPv4 => 0x0800,
            Protocol::IPv6 => 0x86dd,
        }
    }
}

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        // TUN/TAP 3.2 Frame format
        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);
        if proto != Protocol::IPv4.into() {
            continue;
        }
        eprintln!(
            "read {} bytes (flags: {:x}, proto: {:x}, payload {:x?})",
            nbytes - 4,
            flags,
            proto,
            &buf[4..nbytes]
        );
    }
    Ok(())
}
