//! Connection protocol (conproto) for stream VSOCK proxy connection negotiation.
//!
//! This module handles the protocol for negotiating connections through a VSOCK proxy.
//! The proxy receives a JSON request with the target IP server address, establishes
//! a connection with a TCP server and responds with success or failure
//! reply depending on the status of the connection.

#![cfg(feature = "vsock")]

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::VsockStream;

/// Proxy request sent to the VSOCK proxy.
#[derive(Debug, Serialize)]
pub struct ProxyRequest {
    pub command: String,
    pub server_addr: String,
}

/// Proxy response received from the VSOCK proxy.
#[derive(Debug, Deserialize)]
pub struct ProxyResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Send a proxy request to the VSOCK stream.
async fn send_request(
    stream: &mut VsockStream,
    request: &ProxyRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut req_str = serde_json::to_string(request)?;
    req_str.push('\n');
    stream.write_all(req_str.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Receive a proxy response from the VSOCK stream.
async fn receive_response(
    stream: &mut VsockStream,
) -> Result<ProxyResponse, Box<dyn std::error::Error + Send + Sync>> {
    let mut response_str = String::new();
    let mut buf = [0u8; 1024];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err("Connection closed before proxy response".into());
        }

        if let Some(pos) = buf[..n].iter().position(|&b| b == b'\n') {
            response_str.push_str(std::str::from_utf8(&buf[..pos])?);
            break;
        }

        response_str.push_str(std::str::from_utf8(&buf[..n])?);
    }

    let response: ProxyResponse = serde_json::from_str(&response_str)
        .map_err(|e| format!("Failed to parse proxy response: {}", e))?;

    Ok(response)
}

/// Connect to a target server through a VSOCK proxy.
///
/// Sends a CONNECT request to the proxy with the target hostname and port,
/// then waits for a SUCCESS response before proceeding.
///
/// # Arguments
/// * `stream` - The VSOCK stream connected to the proxy
/// * `hostname` - The target server hostname
/// * `dest_port` - The target server port
/// * `timeout_dur` - Timeout duration for the proxy response
///
/// # Returns
/// * `Ok(())` if the proxy successfully connected to the target
/// * `Err` if the proxy connection failed or timed out
pub async fn connect(
    stream: &mut VsockStream,
    hostname: &str,
    dest_port: u16,
    timeout_dur: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server_addr = format!("{}:{}", hostname, dest_port);

    let request = ProxyRequest {
        command: "CONNECT".to_string(),
        server_addr,
    };

    send_request(stream, &request).await?;

    let response = tokio::time::timeout(timeout_dur, receive_response(stream))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Proxy response timeout"))??;

    if response.status != "SUCCESS" {
        return Err(format!("Proxy connection failed: {:?}", response.reason).into());
    }

    Ok(())
}
