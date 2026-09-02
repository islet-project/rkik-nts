//! Configuration for NTS client.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
#[cfg(feature = "vsock")]
use vsock::{VMADDR_CID_HOST, VMADDR_CID_LOCAL};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Configuration for VSOCK stream transport (for NTS-KE handshake).
///
/// VSOCK (Virtual Sockets) provides communication between VMs and their hosts
/// without requiring TCP/IP networking. This is useful for secure, isolated
/// VM environments.
///
/// When `conproto` is enabled, the client will send a CONNECT request to the
/// vsock proxy with the target server address, allowing the proxy to establish
/// the actual TCP connection on behalf of the client.
#[cfg(feature = "vsock")]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VsockConfig {
    /// The VSOCK CID (Context Identifier) of the target.
    /// Use [`VsockConfig::HOST_CID`] for the host.
    pub cid: u32,
    /// The VSOCK port number.
    pub port: u32,
    /// Enable conproto protocol for server address negotiation.
    ///
    /// When enabled, the client sends a CONNECT request to the vsock proxy
    /// with the target server hostname and port, allowing the proxy to
    /// establish the TCP connection on behalf of the client.
    pub conproto: bool,
}

#[cfg(feature = "vsock")]
impl VsockConfig {
    /// The CID for the localhost
    pub const LOCAL_CID: u32 = VMADDR_CID_LOCAL;

    /// The CID for the host
    pub const HOST_CID: u32 = VMADDR_CID_HOST;

    /// Create a new VsockConfig without conproto
    pub fn new(cid: u32, port: u32) -> Self {
        Self {
            cid,
            port,
            conproto: false,
        }
    }

    /// Create a new VsockConfig with conproto enabled
    pub fn with_conproto(cid: u32, port: u32) -> Self {
        Self {
            cid,
            port,
            conproto: true,
        }
    }

    /// Set whether conproto is enabled
    pub fn with_conproto_flag(mut self, conproto: bool) -> Self {
        self.conproto = conproto;
        self
    }
}

/// Configuration for VSOCK datagram transport (for NTP time sync packets).
///
/// This configuration enables sending NTP time synchronization packets over
/// a vsock proxy that supports datagram mode. The proxy handles hostname
/// resolution and UDP forwarding.
///
/// The vsock proxy uses a framing protocol over stream connections:
/// - hostname_len (1 byte): length of hostname string
/// - hostname (variable): hostname bytes
/// - port (2 bytes, big-endian): destination port
/// - payload_len (4 bytes, big-endian): length of payload data
/// - payload (variable): NTP packet data
///
/// This is useful for VM environments where only vsock is available and
/// the VM has no direct TCP/IP network access.
#[cfg(feature = "vsock")]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VsockDatagramConfig {
    /// The VSOCK CID (Context Identifier) of the vsock proxy.
    /// e.g use [`VsockDatagramConfig::HOST_CID`] for the host
    pub cid: u32,
    /// The VSOCK port number the datagram proxy is listening on
    pub port: u32,
}

#[cfg(feature = "vsock")]
impl VsockDatagramConfig {
    /// The CID for the localhost
    pub const LOCAL_CID: u32 = VMADDR_CID_LOCAL;

    /// The CID for the host
    pub const HOST_CID: u32 = VMADDR_CID_HOST;

    /// The default datagram proxy port
    pub const DEFAULT_PORT: u32 = 1338;

    /// Create a new VsockDatagramConfig
    pub fn new(cid: u32, port: u32) -> Self {
        Self { cid, port }
    }

    /// Create a new VsockDatagramConfig with default port
    pub fn with_host_cid() -> Self {
        Self {
            cid: Self::HOST_CID,
            port: Self::DEFAULT_PORT,
        }
    }
}

/// Information about an NTP server (hostname and port).
///
/// This is used to defer DNS resolution until the actual packet is sent,
/// which is necessary when using vsock datagram proxy mode.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NtpServerInfo {
    /// The hostname of the NTP server.
    pub hostname: String,
    /// The port of the NTP server.
    pub port: u16,
}

impl NtpServerInfo {
    /// Create a new NtpServerInfo.
    pub fn new(hostname: impl Into<String>, port: u16) -> Self {
        Self {
            hostname: hostname.into(),
            port,
        }
    }
}

/// Configuration for an NTS client.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NtsClientConfig {
    /// The NTS key exchange server hostname.
    pub nts_ke_server: String,

    /// The NTS key exchange server port (default: 4460).
    pub nts_ke_port: u16,

    /// Timeout for network operations.
    pub timeout: Duration,

    /// Maximum number of retry attempts for time queries after transport or
    /// validation failures.
    pub max_retries: u32,

    /// Whether to verify the server's TLS certificate.
    ///
    /// Disabling certificate verification is rejected unless the crate is
    /// compiled with the `dangerous-configuration` feature.
    pub verify_tls_cert: bool,

    /// Optional override for the NTP server address to use after key exchange.
    ///
    /// When set, this overrides the server/port negotiated by NTS-KE.
    /// Can be either a SocketAddr (for direct UDP) or NtpServerInfo (for vsock datagram).
    #[cfg(feature = "vsock")]
    pub ntp_server: Option<NtpServerConfig>,
    /// For backwards compatibility without vsock feature.
    #[cfg(not(feature = "vsock"))]
    pub ntp_server: Option<SocketAddr>,

    /// NTP version to use.
    ///
    /// Only NTPv4 is supported by this crate.
    pub ntp_version: u8,

    /// Additional CA certificate paths to trust.
    ///
    /// These certificates will be added to the root certificate store.
    pub additional_ca_certs: Vec<PathBuf>,

    /// Optional pinned certificate paths for certificate pinning.
    ///
    /// When set, the TLS connection will only accept the server certificate
    /// if it matches one of the pinned certificates. This provides an
    /// additional layer of security by preventing MITM attacks even if
    /// the CA infrastructure is compromised.
    ///
    /// If both `verify_tls_cert` and `pinned_certs` are set, the pinned
    /// certificate check takes precedence.
    pub pinned_certs: Option<Vec<PathBuf>>,

    /// VSOCK configuration for key exchange.
    ///
    /// When set, the client will use VSOCK instead of TCP for the NTS-KE handshake.
    /// This is useful for VM-to-host communication where TCP/IP networking is disabled.
    /// The `nts_ke_server` field is used as the hostname for TLS verification.
    #[cfg(feature = "vsock")]
    pub vsock_config: Option<VsockConfig>,

    /// VSOCK datagram configuration for NTP time sync packets.
    ///
    /// When set, NTP time synchronization packets will be sent over VSOCK
    /// to a proxy that handles hostname resolution and UDP forwarding.
    #[cfg(feature = "vsock")]
    pub vsock_datagram_config: Option<VsockDatagramConfig>,
}

#[cfg(feature = "vsock")]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// Configuration for the NTP server destination.
///
/// This enum allows specifying either a direct socket address for standard UDP mode
/// or a hostname and port for vsock datagram proxy mode.
pub enum NtpServerConfig {
    /// Direct socket address (for standard UDP mode)
    SocketAddr(SocketAddr),
    /// Hostname and port (for vsock datagram proxy mode)
    Hostname(NtpServerInfo),
}

impl Default for NtsClientConfig {
    fn default() -> Self {
        Self {
            nts_ke_server: String::new(),
            nts_ke_port: 4460, // Standard NTS-KE port
            timeout: Duration::from_secs(10),
            max_retries: 3,
            verify_tls_cert: true,
            ntp_server: None,
            ntp_version: 4,
            additional_ca_certs: Vec::new(),
            pinned_certs: None,
            #[cfg(feature = "vsock")]
            vsock_config: None,
            #[cfg(feature = "vsock")]
            vsock_datagram_config: None,
        }
    }
}

impl NtsClientConfig {
    /// Create a new configuration with the given NTS-KE server.
    ///
    /// # Arguments
    ///
    /// * `server` - The hostname or IP address of the NTS-KE server.
    ///
    /// # Examples
    ///
    /// ```
    /// use rkik_nts::config::NtsClientConfig;
    ///
    /// let config = NtsClientConfig::new("time.cloudflare.com");
    /// ```
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            nts_ke_server: server.into(),
            ..Default::default()
        }
    }

    /// Set the NTS-KE server port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.nts_ke_port = port;
        self
    }

    /// Set the timeout duration.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum number of retries for time queries.
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Set whether to verify TLS certificates.
    pub fn with_tls_verification(mut self, verify: bool) -> Self {
        self.verify_tls_cert = verify;
        self
    }

    /// Set a specific NTP server to use (SocketAddr).
    #[cfg(not(feature = "vsock"))]
    pub fn with_ntp_server(mut self, server: SocketAddr) -> Self {
        self.ntp_server = Some(server);
        self
    }

    /// Set a specific NTP server to use using SocketAddr.
    #[cfg(feature = "vsock")]
    pub fn with_ntp_server_addr(mut self, server: SocketAddr) -> Self {
        self.ntp_server = Some(NtpServerConfig::SocketAddr(server));
        self
    }

    /// Set a specific NTP server to use using hostname and port.
    #[cfg(feature = "vsock")]
    pub fn with_ntp_server_hostname(mut self, hostname: impl Into<String>, port: u16) -> Self {
        self.ntp_server = Some(NtpServerConfig::Hostname(NtpServerInfo::new(
            hostname, port,
        )));
        self
    }

    /// Set the NTP version.
    ///
    /// Only version 4 is supported.
    pub fn with_ntp_version(mut self, version: u8) -> Self {
        self.ntp_version = version;
        self
    }

    /// Add a custom CA certificate to trust.
    ///
    /// This is useful for testing with self-signed certificates or internal CAs.
    /// The certificate at the given path will be loaded and added to the root
    /// certificate store during TLS configuration.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to a PEM-encoded CA certificate file.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rkik_nts::config::NtsClientConfig;
    ///
    /// let config = NtsClientConfig::new("127.0.0.1")
    ///     .with_additional_ca_cert("/etc/pki/tls/certs/localCA.crt");
    /// ```
    pub fn with_additional_ca_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.additional_ca_certs.push(path.into());
        self
    }

    /// Add multiple custom CA certificates to trust.
    ///
    /// # Arguments
    ///
    /// * `paths` - Iterator of paths to PEM-encoded CA certificate files.
    pub fn with_additional_ca_certs<I, P>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.additional_ca_certs
            .extend(paths.into_iter().map(Into::into));
        self
    }

    /// Set pinned certificates for certificate pinning.
    ///
    /// When set, the TLS connection will only accept the server certificate
    /// if it matches one of the pinned certificates. This provides an
    /// additional layer of security by preventing MITM attacks even if
    /// the CA infrastructure is compromised.
    ///
    /// # Arguments
    ///
    /// * `paths` - Iterator of paths to PEM-encoded certificate files to pin.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rkik_nts::config::NtsClientConfig;
    ///
    /// let config = NtsClientConfig::new("time.example.com")
    ///     .with_pinned_certs(vec!["/path/to/server_cert.pem"]);
    /// ```
    pub fn with_pinned_certs<I, P>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.pinned_certs = Some(paths.into_iter().map(Into::into).collect());
        self
    }

    /// Add a single pinned certificate for certificate pinning.
    ///
    /// This is useful when you want to add a certificate to the pinned list
    /// without replacing existing pinned certificates.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to a PEM-encoded certificate file to pin.
    pub fn with_pinned_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.pinned_certs
            .get_or_insert_with(Vec::new)
            .push(path.into());
        self
    }

    /// Configure VSOCK stream transport for NTS-KE handshake.
    ///
    /// When configured, the client will use VSOCK instead of TCP for the key exchange.
    /// This is useful for VM-to-host communication where TCP/IP networking is disabled.
    ///
    /// # Arguments
    ///
    /// * `cid` - The VSOCK Context Identifier of the target (use `VsockConfig::HOST_CID` for host)
    /// * `port` - The VSOCK port number
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "vsock")]
    /// use rkik_nts::config::{NtsClientConfig, VsockConfig};
    ///
    /// # #[cfg(feature = "vsock")]
    /// let config = NtsClientConfig::new("time.example.com")
    ///     .with_vsock_stream(VsockConfig::new(VsockConfig::HOST_CID, 8443));
    /// ```
    #[cfg(feature = "vsock")]
    pub fn with_vsock_stream(mut self, vsock_config: VsockConfig) -> Self {
        self.vsock_config = Some(vsock_config);
        self
    }

    /// Configure VSOCK datagram transport for NTP time sync packets.
    ///
    /// When configured, NTP time synchronization packets will be sent over VSOCK
    /// to a proxy that handles hostname resolution and UDP forwarding.
    /// This is useful for VMs without direct TCP/IP network access.
    ///
    /// # Arguments
    ///
    /// * `cid` - The VSOCK Context Identifier of the proxy (use `VsockDatagramConfig::HOST_CID` for host)
    /// * `port` - The VSOCK port number the datagram proxy is listening on
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "vsock")]
    /// use rkik_nts::config::{NtsClientConfig, VsockDatagramConfig};
    ///
    /// # #[cfg(feature = "vsock")]
    /// let config = NtsClientConfig::new("time.cloudflare.com")
    ///     .with_vsock_datagram(VsockDatagramConfig::with_host_cid());
    /// ```
    #[cfg(feature = "vsock")]
    pub fn with_vsock_datagram(mut self, vsock_datagram_config: VsockDatagramConfig) -> Self {
        self.vsock_datagram_config = Some(vsock_datagram_config);
        self
    }

    /// Validate the configuration.
    pub(crate) fn validate(&self) -> crate::error::Result<()> {
        if self.nts_ke_server.is_empty() {
            return Err(crate::error::Error::InvalidConfig(
                "NTS-KE server hostname is required".to_string(),
            ));
        }

        if self.timeout.is_zero() {
            return Err(crate::error::Error::InvalidConfig(
                "timeout must be greater than zero".to_string(),
            ));
        }

        if self.ntp_version != 4 {
            return Err(crate::error::Error::InvalidConfig(
                "only NTPv4 is supported".to_string(),
            ));
        }

        if !self.verify_tls_cert && !cfg!(feature = "dangerous-configuration") {
            return Err(crate::error::Error::InvalidConfig(
                "TLS verification can only be disabled with the dangerous-configuration feature"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NtsClientConfig::default();
        assert_eq!(config.nts_ke_server, ""); // Default is empty
        assert_eq!(config.nts_ke_port, 4460);
        assert_eq!(config.ntp_version, 4);
        assert!(config.verify_tls_cert);
        // Default config with empty server should fail validation
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_builder_pattern() {
        let config = NtsClientConfig::new("custom.server.com")
            .with_port(1234)
            .with_timeout(std::time::Duration::from_secs(10))
            .with_max_retries(5);

        assert_eq!(config.nts_ke_server, "custom.server.com");
        assert_eq!(config.nts_ke_port, 1234);
        assert_eq!(config.timeout, std::time::Duration::from_secs(10));
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_empty_server_validation() {
        let config = NtsClientConfig {
            nts_ke_server: String::new(),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("hostname is required"));
    }

    #[test]
    fn test_invalid_ntp_version() {
        let config = NtsClientConfig {
            ntp_version: 3,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = NtsClientConfig {
            ntp_version: 5,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_valid_ntp_versions() {
        let config4 = NtsClientConfig::new("test.server.com").with_ntp_version(4);
        assert!(config4.validate().is_ok());
    }

    #[test]
    fn test_tls_verification_disable() {
        let config = NtsClientConfig::new("test.server.com").with_tls_verification(false);
        assert!(!config.verify_tls_cert);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_zero_timeout_is_invalid() {
        let config = NtsClientConfig::new("test.server.com").with_timeout(Duration::ZERO);
        assert!(config.validate().is_err());
    }
}
