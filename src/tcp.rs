use anyhow::Error;
use std::io::Write;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct Hosts {
    pub(crate) src: (Ipv4Addr, u16),
    pub(crate) dst: (Ipv4Addr, u16),
}

pub enum State {
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    fn is_sync(&self) -> bool {
        match *self {
            Self::SynRcvd => false,
            Self::Estab | Self::FinWait1 | Self::FinWait2 | Self::TimeWait => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    iph: etherparse::Ipv4Header,
    tcph: etherparse::TcpHeader,
}

/// Send Sequence Space (RFC793 S3.2 F4)
///
///     1         2          3          4
///     ----------|----------|----------|----------
///     SND.UNA    SND.NXT    SND.UNA
///                         +SND.WND
///
///     1 - old sequence numbers which have been acknowledged
///     2 - sequence numbers of unacknowledged data
///     3 - sequence numbers allowed for new data transmission
///     4 - future sequence numbers which are not yet allowed
struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: u32,
}

/// Receive Sequence Space
///
///     1          2          3      
///     ----------|----------|----------
///     RCV.NXT    RCV.NXT        
///                 +RCV.WND        m3
///
///     1 - old sequence numbers which have been acknowledged  
///     2 - sequence numbers allowed for new reception         
///     3 - future sequence numbers which are not yet allowed  
struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initilize receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> Result<Option<Self>, anyhow::Error> {
        if !tcph.syn() {
            return Ok(None);
        }

        eprintln!(
            "{}:{} -> {}:{} {}b TCP",
            iph.source_addr(),
            tcph.source_port(),
            iph.destination_addr(),
            tcph.destination_port(),
            data.len()
        );

        let iss = 0;
        let wnd = 1024;

        let mut conn = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd,
                up: false,

                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },
            iph: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                iph.destination_addr().octets(),
                iph.source_addr().octets(),
            ),
            tcph: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),
        };

        conn.tcph.syn = true;
        conn.tcph.ack = true;
        conn.write(nic, &[])?;
        Ok(Some(conn))
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> Result<(), anyhow::Error> {
        eprintln!(
            "{}:{} -> {}:{} {}b TCP",
            iph.source_addr(),
            tcph.source_port(),
            iph.destination_addr(),
            tcph.destination_port(),
            data.len()
        );

        if let Err(_) = self.check_recv_seq(&tcph, data.len() as u32) {
            self.write(nic, &[])?;
            eprintln!("\tInvalid recv sequence numbar");
            return Ok(());
        } else {
            self.recv.nxt = tcph.sequence_number().wrapping_add(data.len() as u32)
        }

        if !tcph.ack() {
            return Ok(());
        }

        if let Ok(_) = self.check_send_seq(&tcph) {
            match self.state {
                State::SynRcvd => self.state = State::Estab,
                State::Estab => {
                    self.tcph.fin = true;
                    self.send.una = tcph.acknowledgment_number();
                    self.write(nic, &[])?;
                    self.state = State::FinWait1;
                }
                State::FinWait1 => {
                    self.send.una = tcph.acknowledgment_number();
                    if self.send.una == self.send.iss + 2 {
                        self.state = State::FinWait2;
                    } else {
                        eprintln!("\tExpected FIN, ACK");
                    }
                }
                State::FinWait2 => {
                    if tcph.fin() {
                        self.send.una = tcph.acknowledgment_number();
                        self.write(nic, &[])?;
                        self.state = State::TimeWait;
                    } else {
                        eprintln!("\tExpected FIN, ACK");
                    }
                }
                _ => unimplemented!(),
            }
        } else {
            match self.state {
                State::SynRcvd => {
                    // TODO: <SEQ=SEG.ACK><CTL=RST>
                    todo!()
                }
                _ => unimplemented!(),
            }
        };
        Ok(())
    }

    pub fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> Result<usize, Error> {
        let mut buf = [0u8; 1500];
        self.tcph.sequence_number = self.send.nxt;
        self.tcph.acknowledgment_number = self.recv.nxt;

        let size = self.tcph.header_len() as usize + self.iph.header_len() as usize + payload.len();
        if size > buf.len() {
            return Err(Error::msg("Packet exceeds buf len"));
        };

        self.iph
            .set_payload_len(size - self.iph.header_len() as usize)
            .map_err(|_| return Error::msg("Failed to set payload"))?;

        self.tcph.checksum = self
            .tcph
            .calc_checksum_ipv4(&self.iph, &[])
            .expect("failed to compute checksum");

        let mut unwritten = &mut buf[..];
        self.iph
            .write(&mut unwritten)
            .map_err(|_| Error::msg("Failed to write iph"))?;

        self.tcph
            .write(&mut unwritten)
            .map_err(|_| Error::msg("Failed to write tpch"))?;

        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();
        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcph.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcph.syn = false;
        }
        if self.tcph.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcph.fin = false;
        }
        nic.send(&buf[..buf.len() - unwritten])?;
        Ok(payload_bytes)
    }

    pub fn send_rst<'a>(&mut self, nic: &mut tun_tap::Iface) -> Result<(), anyhow::Error> {
        self.tcph.rst = true;
        self.tcph.acknowledgment_number = 0;
        self.tcph.sequence_number = 0;
        self.write(nic, &[])?;
        Ok(())
    }

    /// una < ack =< nxt with wrapping arithmetic
    /// special edge cases
    pub fn check_send_seq<'a>(
        &self,
        tcph: &etherparse::TcpHeaderSlice<'a>,
    ) -> Result<(), anyhow::Error> {
        let ackn = tcph.acknowledgment_number();
        let err = Error::msg("Invalid send sequence number");

        if let State::SynRcvd = self.state {
            // edge case: inclusive middle
            match is_middle_wrapping(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                true => Ok(()),
                false => Err(err),
            }
        } else {
            match is_middle_wrapping(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                true => Ok(()),
                false => Err(err),
            }
        }
    }

    /// nxt =< seq < nxt+wnd with wrapping arithmetic
    /// nxt =< seq + seq.len-1 < nxt+wnd
    pub fn check_recv_seq<'a>(
        &self,
        tcph: &etherparse::TcpHeaderSlice<'a>,
        data_len: u32,
    ) -> Result<(), anyhow::Error> {
        let err = Error::msg("Invalid recv sequence number");
        let seqn = tcph.sequence_number();

        let mut slen = data_len;
        if tcph.fin() {
            slen += 1;
        }
        if tcph.syn() {
            slen += 1;
        }

        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        if slen == 0 {
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    Err(err)
                } else {
                    Ok(())
                }
            } else if !is_middle_wrapping(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                Err(err)
            } else {
                Ok(())
            }
        } else {
            if self.recv.wnd == 0 {
                Err(err)
            } else if !is_middle_wrapping(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_middle_wrapping(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                Err(err)
            } else {
                Ok(())
            }
        }
    }
}

fn is_middle_wrapping(start: u32, mid: u32, end: u32) -> bool {
    // RFC1323
    start.wrapping_sub(mid) > (1 << 31) && mid.wrapping_sub(end) > (1 << 31)
}
