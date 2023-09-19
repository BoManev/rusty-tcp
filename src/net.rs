pub enum EthProtocol {
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

pub enum IPv4Protocol {
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
