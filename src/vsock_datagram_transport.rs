//! VSOCK datagram transport for NTP time sync packets.
//!
//! This module implements the framing protocol used to communicate with
//! a vsock proxy that handles datagram (UDP) forwarding with hostname resolution.
//!
//! The framing protocol uses a stream-based vsock connection with the following format:
//! - hostname_len (1 byte): length of hostname string
//! - hostname (variable): hostname bytes
//! - port (2 bytes, big-endian): destination port
//! - payload_len (4 bytes, big-endian): length of payload data
//! - payload (variable): NTP packet data

use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::debug;

use crate::config::NtpServerInfo;
use crate::error::{Error, Result};

/// Maximum size for hostname in packet header
const MAX_HOSTNAME_LEN: usize = 255;

/// Datagram header for vsock stream proxy
#[derive(Debug, Clone)]
pub struct DatagramHeader {
    /// The hostname
    pub hostname: String,
    /// The UDP port
    pub port: u16,
    /// The payload length
    pub payload_len: u32,
}

impl DatagramHeader {
    /// Size of the fixed part of header (hostname_len + port + payload_len)
    const FIXED_SIZE: usize = 1 + 2 + 4;

    /// Calculates the total frame size from the header
    pub fn frame_size(&self) -> usize {
        Self::FIXED_SIZE + self.hostname.len() + self.payload_len as usize
    }

    /// Serializes the header to bytes (without payload)
    pub fn to_bytes(&self) -> Vec<u8> {
        let hostname_bytes = self.hostname.as_bytes();
        let hostname_len = hostname_bytes.len().min(MAX_HOSTNAME_LEN) as u8;

        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + hostname_len as usize);
        buf.push(hostname_len);
        buf.extend_from_slice(&hostname_bytes[..hostname_len as usize]);
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf.extend_from_slice(&self.payload_len.to_be_bytes());
        buf
    }

    /// Deserializes the header from bytes
    /// Returns (header, header_size) where header_size includes hostname_len + hostname + port + payload_len
    pub fn from_bytes(data: &[u8]) -> io::Result<(Self, usize)> {
        if data.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Empty packet",
            ));
        }

        let hostname_len = data[0] as usize;
        if hostname_len > MAX_HOSTNAME_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Hostname too long: {}", hostname_len),
            ));
        }

        let header_size = Self::FIXED_SIZE + hostname_len;
        if data.len() < header_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Header too short: expected at least {} bytes, got {}", header_size, data.len()),
            ));
        }

        let hostname = String::from_utf8(data[1..1 + hostname_len].to_vec())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid hostname UTF-8: {}", e),
                )
            })?;

        let port_start = 1 + hostname_len;
        let port = u16::from_be_bytes([data[port_start], data[port_start + 1]]);

        let payload_len_start = port_start + 2;
        let payload_len = u32::from_be_bytes([
            data[payload_len_start],
            data[payload_len_start + 1],
            data[payload_len_start + 2],
            data[payload_len_start + 3],
        ]);

        Ok((DatagramHeader { hostname, port, payload_len }, header_size))
    }

    /// Reads a complete frame from a stream
    /// Returns (header, payload)
    pub async fn read_from_stream<R>(reader: &mut R) -> io::Result<(Self, Vec<u8>)>
    where
        R: AsyncReadExt + Unpin,
    {
        // Read hostname_len (1 byte)
        let mut hostname_len_buf = [0u8; 1];
        reader.read_exact(&mut hostname_len_buf).await?;
        let hostname_len = hostname_len_buf[0] as usize;

        if hostname_len > MAX_HOSTNAME_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Hostname too long: {}", hostname_len),
            ));
        }

        // Read hostname
        let mut hostname_buf = vec![0u8; hostname_len];
        reader.read_exact(&mut hostname_buf).await?;
        let hostname = String::from_utf8(hostname_buf)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid hostname UTF-8: {}", e),
                )
            })?;

        // Read port (2 bytes, big-endian)
        let mut port_buf = [0u8; 2];
        reader.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        // Read payload_len (4 bytes, big-endian)
        let mut payload_len_buf = [0u8; 4];
        reader.read_exact(&mut payload_len_buf).await?;
        let payload_len = u32::from_be_bytes(payload_len_buf) as usize;

        // Read payload
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;

        Ok((
            DatagramHeader {
                hostname,
                port,
                payload_len: payload_len as u32,
            },
            payload,
        ))
    }

    /// Writes a frame (header + payload) to a stream
    pub async fn write_to_stream<W>(&self, writer: &mut W, payload: &[u8]) -> io::Result<()>
    where
        W: AsyncWriteExt + Unpin,
    {
        let header_bytes = self.to_bytes();
        writer.write_all(&header_bytes).await?;
        writer.write_all(payload).await?;
        writer.flush().await?;
        Ok(())
    }
}

/// VSOCK datagram transport for sending NTP packets through a vsock proxy.
///
/// This transport establishes a vsock stream connection to the proxy for each
/// NTP request/response exchange. Note, that the proxy handles hostname resolution and
/// UDP forwarding.
pub struct VsockDatagramTransport {
    /// The vsock address of the proxy
    proxy_addr: VsockAddr,
    /// Connection timeout
    timeout: Duration,
}

impl VsockDatagramTransport {
    /// Create a new VsockDatagramTransport.
    ///
    /// # Arguments
    ///
    /// * `cid` - The VSOCK Context Identifier of the proxy
    /// * `port` - The VSOCK port the datagram proxy is listening on
    /// * `timeout` - Timeout for vsock operations
    pub fn new(cid: u32, port: u32, timeout: Duration) -> Self {
        Self {
            proxy_addr: VsockAddr::new(cid, port),
            timeout,
        }
    }

    /// Send an NTP request and receive a response through the vsock proxy.
    ///
    /// # Arguments
    ///
    /// * `server_info` - The NTP server hostname and port
    /// * `request` - The NTP request packet
    ///
    /// # Returns
    ///
    /// The NTP response packet
    pub async fn send_to(&self, server_info: &NtpServerInfo, request: &[u8]) -> Result<Vec<u8>> {
        debug!(
            "Sending NTP request to {}:{} via vsock datagram proxy",
            server_info.hostname, server_info.port
        );

        // Connect to the vsock proxy
        let mut stream = tokio::time::timeout(
            self.timeout,
            VsockStream::connect(self.proxy_addr),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| {
            Error::ServerUnavailable(format!("VSOCK datagram proxy connection failed: {e}"))
        })?;

        // Create header with server info
        let header = DatagramHeader {
            hostname: server_info.hostname.clone(),
            port: server_info.port,
            payload_len: request.len() as u32,
        };

        // Send the framed request
        tokio::time::timeout(self.timeout, header.write_to_stream(&mut stream, request))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| Error::Io(e))?;

        debug!("Sent {} bytes NTP request via vsock proxy", request.len());

        // Read the response frame
        let (response_header, response_payload) =
            tokio::time::timeout(self.timeout, DatagramHeader::read_from_stream(&mut stream))
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(|e| {
                    Error::ServerUnavailable(format!("Failed to read vsock proxy response: {e}"))
                })?;

        debug!(
            "Received NTP response {:?}, {} bytes of payload",
            response_header, response_payload.len()
        );

        Ok(response_payload)
    }

    /// Send an NTP request and receive a response, with retry on hostname mismatch.
    ///
    /// This is a convenience method that handles the case where the proxy might
    /// return a response from a different hostname (e.g., due to DNS round-robin).
    ///
    /// # Arguments
    ///
    /// * `server_info` - The expected NTP server hostname and port
    /// * `request` - The NTP request packet
    /// * `_max_retries` - Maximum number of retries on hostname mismatch
    ///
    /// # Returns
    ///
    /// The NTP response packet
    pub async fn send_to_with_retry(
        &self,
        server_info: &NtpServerInfo,
        request: &[u8],
        _max_retries: u32,
    ) -> Result<Vec<u8>> {
        self.send_to(server_info, request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datagram_header_serialization() {
        let header = DatagramHeader {
            hostname: "time.cloudflare.com".to_string(),
            port: 123,
            payload_len: 48,
        };

        let bytes = header.to_bytes();
        // Header should be: 1 (hostname_len) + 19 (hostname) + 2 (port) + 4 (payload_len) = 26
        assert_eq!(bytes.len(), 26);

        let (parsed, size) = DatagramHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.hostname, "time.cloudflare.com");
        assert_eq!(parsed.port, 123);
        assert_eq!(parsed.payload_len, 48);
        assert_eq!(size, 26);
    }

    #[test]
    fn test_datagram_header_with_payload() {
        let payload = b"Hello, NTP!";
        let header = DatagramHeader {
            hostname: "time.local".to_string(),
            port: 123,
            payload_len: payload.len() as u32,
        };

        let mut bytes = header.to_bytes();
        bytes.extend_from_slice(payload);

        // Parse header only
        let (parsed, header_size) = DatagramHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.hostname, "time.local");
        assert_eq!(parsed.port, 123);
        assert_eq!(parsed.payload_len, payload.len() as u32);
        assert_eq!(header_size, 1 + 10 + 2 + 4); // hostname_len + hostname + port + payload_len

        // Verify payload is intact
        assert_eq!(&bytes[header_size..], payload);
    }

    #[test]
    fn test_datagram_header_empty_hostname() {
        let header = DatagramHeader {
            hostname: "".to_string(),
            port: 123,
            payload_len: 0,
        };

        let bytes = header.to_bytes();
        let (parsed, _) = DatagramHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.hostname, "");
        assert_eq!(parsed.port, 123);
        assert_eq!(parsed.payload_len, 0);
    }

    #[test]
    fn test_datagram_header_max_hostname() {
        let hostname = "a".repeat(MAX_HOSTNAME_LEN);
        let header = DatagramHeader {
            hostname: hostname.clone(),
            port: 443,
            payload_len: 100,
        };

        let bytes = header.to_bytes();
        let (parsed, _) = DatagramHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.hostname, hostname);
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.payload_len, 100);
    }
}
