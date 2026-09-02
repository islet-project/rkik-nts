//! VSOCK stream transport handling for NTS-KE connections.
//!
//! This module provides VSOCK transport support for VM-to-host communication
//! where TCP/IP networking is disabled. It includes a transport abstraction
//! that can handle either TCP or VSOCK streams.

#[cfg(feature = "vsock")]
use tokio_vsock::{VsockAddr, VsockStream};

use crate::config::NtsClientConfig;
use crate::error::{Error, Result};
use std::net::SocketAddr;
use tracing::{debug, info};

#[cfg(feature = "vsock")]
use crate::conproto;

/// A transport stream that can be either TCP or VSOCK.
#[allow(clippy::large_enum_variant)]
pub enum TransportStream {
    Tcp(tokio::net::TcpStream),
    #[cfg(feature = "vsock")]
    Vsock(VsockStream),
}

impl tokio::io::AsyncRead for TransportStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(feature = "vsock")]
            TransportStream::Vsock(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            TransportStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for TransportStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            #[cfg(feature = "vsock")]
            TransportStream::Vsock(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            TransportStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(feature = "vsock")]
            TransportStream::Vsock(s) => std::pin::Pin::new(s).poll_flush(cx),
            TransportStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(feature = "vsock")]
            TransportStream::Vsock(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            TransportStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Unpin for TransportStream {}

/// Establish a VSOCK transport connection.
#[cfg(feature = "vsock")]
pub async fn establish_vsock_transport(config: &NtsClientConfig) -> Result<TransportStream> {
    let vsock_config = config
        .vsock_config
        .as_ref()
        .ok_or_else(|| Error::ServerUnavailable("VSOCK config not provided".to_string()))?;

    info!(
        "Connecting via VSOCK to CID {}:{}",
        vsock_config.cid, vsock_config.port
    );
    let vsock_addr = VsockAddr::new(vsock_config.cid, vsock_config.port);
    let mut vsock_stream = tokio::time::timeout(config.timeout, VsockStream::connect(vsock_addr))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::ServerUnavailable(format!("VSOCK connection failed: {e}")))?;

    // If conproto is enabled, send the target server address to the proxy
    if vsock_config.conproto {
        debug!(
            "Using conproto to connect to {}:{} via VSOCK proxy",
            config.nts_ke_server, config.nts_ke_port
        );
        conproto::connect(
            &mut vsock_stream,
            &config.nts_ke_server,
            config.nts_ke_port,
            config.timeout,
        )
        .await
        .map_err(|e| Error::ServerUnavailable(format!("Conproto failed: {e}")))?;
        debug!("Conproto connection established");
    }

    debug!("VSOCK connection established");
    Ok(TransportStream::Vsock(vsock_stream))
}

/// Establish a transport connection (TCP or VSOCK) based on configuration.
pub async fn establish_transport(config: &NtsClientConfig) -> Result<TransportStream> {
    #[cfg(feature = "vsock")]
    {
        if config.vsock_config.is_some() {
            return establish_vsock_transport(config).await;
        }
    }

    // Fall back to TCP
    establish_tcp_transport(config).await
}

/// Establish a TCP transport connection.
async fn establish_tcp_transport(config: &NtsClientConfig) -> Result<TransportStream> {
    info!(
        "Connecting via TCP to {}:{}",
        config.nts_ke_server, config.nts_ke_port
    );

    let server_addrs =
        resolve_server(&config.nts_ke_server, config.nts_ke_port, config.timeout).await?;
    debug!("Resolved NTS-KE server addresses: {server_addrs:?}");

    let mut last_connect_error = None;
    let mut tcp_stream = None;

    for server_addr in &server_addrs {
        match tokio::time::timeout(config.timeout, tokio::net::TcpStream::connect(server_addr))
            .await
        {
            Ok(Ok(stream)) => {
                tcp_stream = Some(stream);
                break;
            }
            Ok(Err(err)) => last_connect_error = Some(err.to_string()),
            Err(_) => last_connect_error = Some(format!("timed out connecting to {server_addr}")),
        }
    }

    let tcp_stream = tcp_stream.ok_or_else(|| {
        Error::ServerUnavailable(
            last_connect_error
                .unwrap_or_else(|| "unable to connect to any resolved address".to_string()),
        )
    })?;

    debug!("TCP connection established");
    Ok(TransportStream::Tcp(tcp_stream))
}

/// Resolve server address
pub async fn resolve_server(
    server: &str,
    port: u16,
    timeout: std::time::Duration,
) -> Result<Vec<SocketAddr>> {
    if let Ok(addr) = format!("{server}:{port}").parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }

    let addrs = tokio::time::timeout(timeout, tokio::net::lookup_host((server, port)))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::ServerUnavailable(format!("DNS resolution failed: {e}")))?;

    let mut resolved: Vec<_> = addrs.collect();
    resolved.sort_unstable();
    resolved.dedup();
    if resolved.is_empty() {
        return Err(Error::ServerUnavailable(
            "No addresses resolved".to_string(),
        ));
    }
    Ok(resolved)
}
