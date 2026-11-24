use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use crate::wire::{DnsName, Message};

pub const DEFAULT_EDNS_UDP_SIZE: u16 = 1232;

static NEXT_QUERY_ID: AtomicU16 = AtomicU16::new(0x4120);

#[derive(Debug, Clone)]
pub struct DnsTransport {
    pub timeout: Duration,
    pub edns_udp_size: u16,
    pub force_tcp: bool,
}

impl Default for DnsTransport {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(4),
            edns_udp_size: DEFAULT_EDNS_UDP_SIZE,
            force_tcp: false,
        }
    }
}

impl DnsTransport {
    pub fn query(
        &self,
        server: SocketAddr,
        name: &DnsName,
        qtype: u16,
        recursion_desired: bool,
    ) -> Result<(Message, bool), String> {
        let id = NEXT_QUERY_ID.fetch_add(1, Ordering::Relaxed);
        let query = Message::build_query(id, name.clone(), qtype, recursion_desired, self.edns_udp_size);
        let wire = query.encode();

        if self.force_tcp {
            let resp = self.exchange_tcp(server, &wire, id)?;
            return Ok((resp, true));
        }

        let resp = self.exchange_udp(server, &wire, id)?;
        if resp.header.tc() {
            let tcp_resp = self.exchange_tcp(server, &wire, id)?;
            return Ok((tcp_resp, true));
        }
        Ok((resp, false))
    }

    fn exchange_udp(&self, server: SocketAddr, wire: &[u8], expected_id: u16) -> Result<Message, String> {
        let bind_addr = if server.is_ipv4() {
            if server.ip().is_loopback() {
                "127.0.0.1:0"
            } else {
                "0.0.0.0:0"
            }
        } else if server.ip().is_loopback() {
            "[::1]:0"
        } else {
            "[::]:0"
        };

        let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("UDP bind failed: {e}"))?;
        sock.set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("set_read_timeout failed: {e}"))?;
        sock.set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("set_write_timeout failed: {e}"))?;
        sock.connect(server)
            .map_err(|e| format!("UDP connect to {server} failed: {e}"))?;

        sock.send(wire)
            .map_err(|e| format!("UDP send to {server} failed: {e}"))?;

        let mut buf = vec![0u8; 4096];
        let n = sock
            .recv(&mut buf)
            .map_err(|e| format!("UDP recv from {server} failed: {e}"))?;
        let msg = Message::parse(&buf[..n])?;
        if msg.header.id != expected_id || !msg.header.is_response() {
            return Err(format!(
                "unexpected DNS response from {server}: id={} (expected {}), qr={}",
                msg.header.id,
                expected_id,
                msg.header.is_response()
            ));
        }
        Ok(msg)
    }

    fn exchange_tcp(&self, server: SocketAddr, wire: &[u8], expected_id: u16) -> Result<Message, String> {
        let mut stream = TcpStream::connect_timeout(&server, self.timeout)
            .map_err(|e| format!("TCP connect to {server} failed: {e}"))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("TCP read timeout failed: {e}"))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("TCP write timeout failed: {e}"))?;

        let len = u16::try_from(wire.len()).map_err(|_| "query exceeds TCP u16 length")?;
        stream
            .write_all(&len.to_be_bytes())
            .and_then(|_| stream.write_all(wire))
            .map_err(|e| format!("TCP write to {server} failed: {e}"))?;

        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| format!("TCP length read from {server} failed: {e}"))?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; resp_len];
        stream
            .read_exact(&mut buf)
            .map_err(|e| format!("TCP body read from {server} failed: {e}"))?;

        let msg = Message::parse(&buf)?;
        if msg.header.id != expected_id || !msg.header.is_response() {
            return Err(format!(
                "unexpected TCP DNS response from {server}: id={} (expected {})",
                msg.header.id, expected_id
            ));
        }
        Ok(msg)
    }
}
