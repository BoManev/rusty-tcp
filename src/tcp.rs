use std::net::Ipv4Addr;

pub struct State {}

impl Default for State {
    fn default() -> Self {
        Self {}
    }
}

impl State {
    pub fn on_packet<'a>(
        &mut self,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) {
        eprintln!(
            "{}:{} -> {}:{} {}b TCP",
            iph.source_addr(),
            tcph.source_port(),
            iph.destination_addr(),
            tcph.destination_port(),
            data.len()
        );
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct Connection {
    pub(crate) src: (Ipv4Addr, u16),
    pub(crate) dst: (Ipv4Addr, u16),
}
