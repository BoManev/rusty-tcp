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
