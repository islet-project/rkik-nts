//! High-level NTS client implementation with real RFC 8915 authentication.

use std::net::SocketAddr;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::NtsClientConfig;
use crate::error::{Error, Result};
use crate::nts_ke::perform_nts_ke;
use crate::nts_ntp::NtsState;
use crate::types::{CertificateInfo, NtpServerDestination, TimeSnapshot};

#[cfg(feature = "vsock")]
use crate::vsock_datagram_transport::VsockDatagramTransport;

/// A high-level NTS (Network Time Security) client.
///
/// This client handles NTS key exchange and authenticated NTP time queries
/// according to RFC 8915. All time queries are cryptographically authenticated
/// using AEAD encryption with keys negotiated during the NTS-KE handshake.
///
/// # Security
///
/// - NTP packets contain NTS extension fields (Unique ID, Cookie, Authenticator)
/// - AEAD verification is performed on every response
/// - Spoofed or modified responses are rejected
/// - Cookies are consumed and replenished automatically
///
/// # Examples
///
/// ```no_run
/// use rkik_nts::{NtsClient, NtsClientConfig};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = NtsClientConfig::new("time.cloudflare.com");
///     let mut client = NtsClient::new(config);
///
///     // Connect and perform NTS key exchange
///     client.connect().await?;
///
///     // Get the current time (authenticated)
///     let time = client.get_time().await?;
///     println!("Network time: {:?}", time.network_time);
///     println!("Offset: {} ms", time.offset_signed());
///     println!("Authenticated: {}", time.authenticated);
///
///     Ok(())
/// }
/// ```
pub struct NtsClient {
    config: NtsClientConfig,
    /// NTS cryptographic state (ciphers and cookies).
    nts_state: Option<NtsState>,
    /// UDP socket for NTP queries (used in standard mode).
    socket: Option<UdpSocket>,
    /// VSOCK datagram transport (used when vsock_datagram_config is set).
    #[cfg(feature = "vsock")]
    vsock_datagram_transport: Option<VsockDatagramTransport>,
    /// Primary NTP server destination from NTS-KE.
    ntp_server_destination: Option<NtpServerDestination>,
    /// NTS-KE diagnostic information.
    ke_info: Option<NtsKeInfo>,
}

/// Diagnostic information from the NTS-KE handshake.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NtsKeInfo {
    /// The NTP server destination negotiated during NTS-KE.
    pub ntp_server: NtpServerDestination,
    /// The negotiated AEAD algorithm.
    pub aead_algorithm: String,
    /// Duration of the NTS-KE handshake.
    pub ke_duration: std::time::Duration,
    /// TLS certificate information.
    pub certificate: Option<CertificateInfo>,
    /// Initial cookie count from NTS-KE.
    pub initial_cookie_count: usize,
}

impl NtsClient {
    /// Create a new NTS client with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the NTS client.
    pub fn new(config: NtsClientConfig) -> Self {
        Self {
            config,
            nts_state: None,
            socket: None,
            #[cfg(feature = "vsock")]
            vsock_datagram_transport: None,
            ntp_server_destination: None,
            ke_info: None,
        }
    }

    /// Connect to the NTS server and perform key exchange.
    ///
    /// This performs the NTS-KE handshake over TLS to negotiate:
    /// - AEAD algorithm
    /// - Client-to-server and server-to-client encryption keys
    /// - Initial pool of cookies
    ///
    /// Note, that the address resolution is deferred until `get_time()` is called.
    /// This allows to delegate DNS resolution to vsock proxy.
    ///
    /// This must be called before querying time.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or the key exchange fails.
    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to NTS server: {}", self.config.nts_ke_server);

        // Validate configuration
        self.config.validate()?;

        // Perform NTS key exchange
        let nts_result = perform_nts_ke(&self.config).await?;

        let ntp_server_destination = nts_result.ntp_server.clone();
        let aead_algorithm = nts_result.aead_algorithm.clone();
        let ke_duration = nts_result.ke_duration();
        let certificate = nts_result.certificate.clone();
        let initial_cookie_count = nts_result.cookie_count();

        info!(
            "NTS key exchange successful. NTP server: {:?}, cookies: {}",
            ntp_server_destination, initial_cookie_count
        );

        // Check if we're using vsock datagram mode
        #[cfg(feature = "vsock")]
        let using_vsock_datagram = self.config.vsock_datagram_config.is_some();
        #[cfg(not(feature = "vsock"))]
        let using_vsock_datagram = false;

        if using_vsock_datagram {
            // VSOCK datagram mode: create vsock datagram transport
            #[cfg(feature = "vsock")]
            {
                if let Some(vsock_datagram_config) = &self.config.vsock_datagram_config {
                    self.vsock_datagram_transport = Some(VsockDatagramTransport::new(
                        vsock_datagram_config.cid,
                        vsock_datagram_config.port,
                        self.config.timeout,
                    ));
                    info!("Using VSOCK datagram transport for NTP packets");
                }
            }
            // No UDP socket needed in vsock datagram mode
            self.socket = None;

            // Extract NTS state for authenticated queries
            let nts_state = nts_result.into_nts_state();

            self.nts_state = Some(nts_state);
            self.ntp_server_destination = Some(ntp_server_destination.clone());
            self.ke_info = Some(NtsKeInfo {
                ntp_server: ntp_server_destination,
                aead_algorithm,
                ke_duration,
                certificate,
                initial_cookie_count,
            });

            return Ok(());
        }

        // Standard UDP mode: create UDP socket for NTP queries.
        // Socket will be bound in get_time() when we know the address family.
        self.socket = None;
        #[cfg(feature = "vsock")]
        {
            self.vsock_datagram_transport = None;
        }

        // Extract NTS state for authenticated queries
        let nts_state = nts_result.into_nts_state();

        self.nts_state = Some(nts_state);
        self.ntp_server_destination = Some(ntp_server_destination.clone());
        self.ke_info = Some(NtsKeInfo {
            ntp_server: ntp_server_destination,
            aead_algorithm,
            ke_duration,
            certificate,
            initial_cookie_count,
        });

        Ok(())
    }

    /// Query the current time from the NTS-secured NTP server.
    ///
    /// This creates an NTS-authenticated NTP request with:
    /// - Unique Identifier extension field (anti-replay)
    /// - NTS Cookie extension field
    /// - Cookie Placeholder extension fields (to replenish cookies)
    /// - AEAD authenticator
    ///
    /// The response is verified using:
    /// - AEAD decryption and verification
    /// - Unique Identifier matching
    /// - Origin timestamp matching
    ///
    /// Only after successful verification is `authenticated` set to `true`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Not connected (call `connect()` first)
    /// - No cookies available (need to reconnect)
    /// - AEAD verification fails (response tampered or spoofed)
    /// - Response doesn't match request (replay attack detected)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rkik_nts::{NtsClient, NtsClientConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = NtsClient::new(NtsClientConfig::new("time.cloudflare.com"));
    /// client.connect().await?;
    /// let time = client.get_time().await?;
    /// assert!(time.authenticated);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_time(&mut self) -> Result<TimeSnapshot> {
        let nts_state = self.nts_state.as_mut().ok_or_else(|| {
            Error::Other("No NTS state available. Call connect() first.".to_string())
        })?;

        let ntp_server_destination = self.ntp_server_destination.as_ref().ok_or_else(|| {
            Error::Other("No NTP server configured. Call connect() first.".to_string())
        })?;

        // Check if we have cookies available
        if !nts_state.has_cookies() {
            return Err(Error::MissingNtsCookie);
        }

        debug!(
            "Creating NTS-authenticated NTP request ({} cookies available)",
            nts_state.cookie_count()
        );

        #[cfg(feature = "vsock")]
        let using_vsock_datagram = self.vsock_datagram_transport.is_some();
        #[cfg(not(feature = "vsock"))]
        let using_vsock_datagram = false;

        // Use the vsock datagram mode
        if using_vsock_datagram {
            #[cfg(feature = "vsock")]
            {
                let server_info = match ntp_server_destination {
                    NtpServerDestination::Hostname(info) => info,
                    NtpServerDestination::SocketAddr(_) => {
                        return Err(Error::Other(
                            "VSOCK datagram mode requires hostname-based server config".to_string(),
                        ));
                    }
                };

                if let Some(transport) = &self.vsock_datagram_transport {
                    return Self::send_ntp_requests_vsock_datagram_mode(
                        transport,
                        nts_state,
                        server_info,
                        self.config.max_retries,
                        self.config.timeout,
                        ntp_server_destination,
                    )
                    .await;
                } else {
                    return Err(Error::Other(
                        "VSOCK datagram transport not initialized".to_string(),
                    ));
                }
            }
        }

        // Standard UDP mode: resolve server addresses and create socket if needed
        let ntp_addrs = match ntp_server_destination {
            NtpServerDestination::SocketAddr(addr) => vec![*addr],
            #[cfg(feature = "vsock")]
            NtpServerDestination::Hostname(info) => {
                crate::transport::resolve_server(&info.hostname, info.port, self.config.timeout)
                    .await?
            }
            #[cfg(not(feature = "vsock"))]
            NtpServerDestination::Hostname(info) => {
                crate::transport::resolve_server(&info.hostname, info.port, self.config.timeout)
                    .await?
            }
        };

        if ntp_addrs.is_empty() {
            return Err(Error::ServerUnavailable(
                "No NTP server addresses resolved".to_string(),
            ));
        }

        // Create or reuse UDP socket
        // Prefer IPv6 if any resolved address is IPv6; fall back to IPv4.
        if self.socket.is_none() {
            let socket = if ntp_addrs.iter().any(SocketAddr::is_ipv6) {
                match UdpSocket::bind("[::]:0").await {
                    Ok(socket) => socket,
                    Err(_) => UdpSocket::bind("0.0.0.0:0").await?,
                }
            } else {
                UdpSocket::bind("0.0.0.0:0").await?
            };

            // Discard addresses that don't match the bound socket's address family.
            let socket_is_v6 = socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
            let filtered_addrs: Vec<SocketAddr> = ntp_addrs
                .into_iter()
                .filter(|a| a.is_ipv6() == socket_is_v6)
                .collect();

            if filtered_addrs.is_empty() {
                return Err(Error::ServerUnavailable(
                    "no NTP server addresses are compatible with the bound socket family"
                        .to_string(),
                ));
            }

            self.socket = Some(socket);
            // Store filtered addresses for use in the retry loop
            // We use a local variable since we don't store addresses in the struct anymore
            return Self::send_ntp_requests_standard_mode(
                self.socket.as_ref().unwrap(),
                nts_state,
                &filtered_addrs,
                self.config.max_retries,
                self.config.timeout,
                ntp_server_destination,
            )
            .await;
        }

        let socket = self.socket.as_ref().unwrap();

        // Filter addresses to match socket family
        let socket_is_v6 = socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
        let filtered_addrs: Vec<SocketAddr> = ntp_addrs
            .into_iter()
            .filter(|a| a.is_ipv6() == socket_is_v6)
            .collect();

        if filtered_addrs.is_empty() {
            return Err(Error::ServerUnavailable(
                "no NTP server addresses are compatible with the bound socket family".to_string(),
            ));
        }

        Self::send_ntp_requests_standard_mode(
            socket,
            nts_state,
            &filtered_addrs,
            self.config.max_retries,
            self.config.timeout,
            ntp_server_destination,
        )
        .await
    }

    /// Send NTP requests in VSOCK datagram mode with retry logic.
    #[cfg(feature = "vsock")]
    async fn send_ntp_requests_vsock_datagram_mode(
        transport: &VsockDatagramTransport,
        nts_state: &mut NtsState,
        server_info: &crate::config::NtpServerInfo,
        max_retries: u32,
        op_timeout: std::time::Duration,
        _ntp_server_destination: &NtpServerDestination,
    ) -> Result<TimeSnapshot> {
        let mut last_error = None;
        let max_attempts = max_retries.saturating_add(1);
        let mut nts_response = None;

        for attempt in 0..max_attempts {
            let request = nts_state.create_request()?;

            debug!(
                "Sending NTS request attempt {} ({} bytes) via VSOCK datagram to {}:{}",
                attempt + 1,
                request.len(),
                server_info.hostname,
                server_info.port
            );

            let response =
                match tokio::time::timeout(op_timeout, transport.send_to(server_info, &request))
                    .await
                {
                    Ok(Ok(response)) => response,
                    Ok(Err(err)) => {
                        nts_state.abandon_request();
                        last_error = Some(err);
                        continue;
                    }
                    Err(_) => {
                        nts_state.abandon_request();
                        last_error = Some(Error::Timeout);
                        continue;
                    }
                };

            debug!(
                "Received {} bytes response via VSOCK datagram",
                response.len()
            );

            match nts_state.parse_response(&response) {
                Ok(response) => {
                    nts_response = Some(response);
                    break;
                }
                Err(
                    err @ Error::InvalidResponse(_)
                    | err @ Error::MissingAuthenticator
                    | err @ Error::AeadVerificationFailed(_)
                    | err @ Error::MalformedNtsExtension(_)
                    | err @ Error::KissOfDeath(_),
                ) => {
                    debug!("Discarding invalid NTS response: {}", err);
                    nts_state.abandon_request();
                    last_error = Some(err);
                    continue;
                }
                Err(err) => {
                    nts_state.abandon_request();
                    last_error = Some(err);
                    break;
                }
            }
        }

        let nts_response = match nts_response {
            Some(response) => response,
            None => return Err(last_error.unwrap_or(Error::Timeout)),
        };

        debug!(
            "NTS response verified. Stratum: {}, authenticated: {}, cookies remaining: {}",
            nts_response.stratum,
            nts_response.authenticated,
            nts_state.cookie_count()
        );

        // Warn if cookie count is getting low
        if nts_state.needs_more_cookies() {
            warn!(
                "Cookie count is low ({}). Consider reconnecting if queries fail.",
                nts_state.cookie_count()
            );
        }

        // Convert NtsResponse to TimeSnapshot
        let offset = nts_response.offset();
        let server_str = format!("{}:{}", server_info.hostname, server_info.port);

        Ok(TimeSnapshot {
            system_time: nts_response.system_time,
            network_time: nts_response.network_time,
            offset,
            round_trip_delay: nts_response.round_trip_delay,
            server: server_str,
            authenticated: nts_response.authenticated,
        })
    }

    /// Send NTP requests in standard UDP mode with retry logic.
    async fn send_ntp_requests_standard_mode(
        socket: &UdpSocket,
        nts_state: &mut NtsState,
        ntp_addrs: &[SocketAddr],
        max_retries: u32,
        op_timeout: std::time::Duration,
        ntp_server_destination: &NtpServerDestination,
    ) -> Result<TimeSnapshot> {
        let mut last_error = None;
        let max_attempts = max_retries.saturating_add(1).max(ntp_addrs.len() as u32);
        let mut nts_response = None;

        for attempt in 0..max_attempts {
            let request = nts_state.create_request()?;
            let target = ntp_addrs[attempt as usize % ntp_addrs.len()];

            debug!(
                "Sending NTS request attempt {} ({} bytes) to {}",
                attempt + 1,
                request.len(),
                target
            );

            if let Err(err) = socket.send_to(&request, target).await {
                nts_state.abandon_request();
                last_error = Some(Error::Io(err));
                continue;
            }

            let deadline = tokio::time::Instant::now() + op_timeout;
            let mut buf = vec![0u8; 2048];
            let mut attempt_error = Error::Timeout;

            loop {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    break;
                }
                let remaining = deadline.saturating_duration_since(now);
                let (len, src) = match timeout(remaining, socket.recv_from(&mut buf)).await {
                    Ok(Ok(v)) => v,
                    Ok(Err(err)) => {
                        attempt_error = Error::Io(err);
                        break;
                    }
                    Err(_) => break,
                };

                if src.ip() != target.ip() || src.port() != target.port() {
                    debug!("Discarding UDP packet from unexpected source {}", src);
                    continue;
                }

                debug!("Received {} bytes from {}", len, src);
                let packet = &buf[..len];
                match nts_state.parse_response(packet) {
                    Ok(response) => {
                        nts_response = Some(response);
                        break;
                    }
                    Err(
                        err @ Error::InvalidResponse(_)
                        | err @ Error::MissingAuthenticator
                        | err @ Error::AeadVerificationFailed(_)
                        | err @ Error::MalformedNtsExtension(_)
                        | err @ Error::KissOfDeath(_),
                    ) => {
                        debug!("Discarding invalid NTS response from {}: {}", src, err);
                        attempt_error = err;
                        continue;
                    }
                    Err(err) => {
                        attempt_error = err;
                        break;
                    }
                }
            }

            if nts_response.is_some() {
                break;
            }

            nts_state.abandon_request();
            last_error = Some(attempt_error);
        }

        let nts_response = match nts_response {
            Some(response) => response,
            None => return Err(last_error.unwrap_or(Error::Timeout)),
        };

        debug!(
            "NTS response verified. Stratum: {}, authenticated: {}, cookies remaining: {}",
            nts_response.stratum,
            nts_response.authenticated,
            nts_state.cookie_count()
        );

        // Warn if cookie count is getting low
        if nts_state.needs_more_cookies() {
            warn!(
                "Cookie count is low ({}). Consider reconnecting if queries fail.",
                nts_state.cookie_count()
            );
        }

        // Convert NtsResponse to TimeSnapshot
        let offset = nts_response.offset();

        // Get server string for the snapshot
        let server_str = match ntp_server_destination {
            NtpServerDestination::SocketAddr(addr) => addr.to_string(),
            NtpServerDestination::Hostname(info) => format!("{}:{}", info.hostname, info.port),
        };

        Ok(TimeSnapshot {
            system_time: nts_response.system_time,
            network_time: nts_response.network_time,
            offset,
            round_trip_delay: nts_response.round_trip_delay,
            server: server_str,
            authenticated: nts_response.authenticated,
        })
    }

    /// Check if the client is connected and ready to query time.
    pub fn is_connected(&self) -> bool {
        self.nts_state.is_some() && self.has_transport()
    }

    /// Check if we have a transport available.
    #[cfg(feature = "vsock")]
    fn has_transport(&self) -> bool {
        self.socket.is_some() || self.vsock_datagram_transport.is_some()
    }

    #[cfg(not(feature = "vsock"))]
    fn has_transport(&self) -> bool {
        self.socket.is_some()
    }

    /// Get the NTP server destination being used.
    pub fn ntp_server_destination(&self) -> Option<&NtpServerDestination> {
        self.ntp_server_destination.as_ref()
    }

    /// Get the NTP server address being used (if in standard UDP mode).
    pub fn ntp_server(&self) -> Option<SocketAddr> {
        self.ntp_server_destination
            .as_ref()
            .and_then(|d| d.as_socket_addr())
    }

    /// Get the current cookie count.
    ///
    /// Each NTP query consumes one cookie, and responses may provide new ones.
    /// If this reaches zero, you need to reconnect to get fresh cookies.
    pub fn cookie_count(&self) -> usize {
        self.nts_state
            .as_ref()
            .map(|s| s.cookie_count())
            .unwrap_or(0)
    }

    /// Check if the client needs more cookies.
    ///
    /// Returns `true` if the cookie count is below the minimum threshold.
    pub fn needs_more_cookies(&self) -> bool {
        self.nts_state
            .as_ref()
            .map(|s| s.needs_more_cookies())
            .unwrap_or(true)
    }

    /// Get diagnostic information from the NTS-KE handshake.
    ///
    /// This provides access to NTS-KE negotiation details including:
    /// - AEAD algorithm
    /// - Initial cookie count
    /// - Key exchange duration
    /// - TLS certificate information
    ///
    /// Returns `None` if not connected.
    pub fn nts_ke_info(&self) -> Option<&NtsKeInfo> {
        self.ke_info.as_ref()
    }

    /// Reconnect and perform a fresh NTS key exchange.
    ///
    /// This is useful when:
    /// - The connection has been idle for a long time
    /// - The server has rotated keys
    /// - Cookies have been exhausted
    /// - AEAD verification failures indicate stale keys
    pub async fn reconnect(&mut self) -> Result<()> {
        debug!("Reconnecting to NTS server");
        self.socket = None;
        #[cfg(feature = "vsock")]
        {
            self.vsock_datagram_transport = None;
        }
        self.nts_state = None;
        self.ntp_server_destination = None;
        self.ke_info = None;
        self.connect().await
    }
}

impl Drop for NtsClient {
    fn drop(&mut self) {
        debug!("NtsClient dropped");
    }
}
