//! NTS client with VSOCK transport support.
//!
//! This example demonstrates how to use the rkik-nts library with VSOCK transport
//! for both NTS-KE handshake (stream) and NTP time sync (datagram).
//!
//! Run with: cargo run --example nts_vsock_client --features vsock -- --nts-server 127.0.0.1 --vsock-stream-cid local --vsock-stream-port 8443 --vsock-datagram-cid local --vsock-datagram-port 1338

use clap::{Parser, ValueEnum};
use rkik_nts::{NtsClient, NtsClientConfig, VsockConfig, VsockDatagramConfig};
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

/// Sets the system time to the specified duration since UNIX_EPOCH.
///
/// This function requires elevated privileges (root/admin).
#[cfg(unix)]
fn set_system_time(network_time: Duration) -> Result<(), Box<dyn Error>> {
    // Calculate the target time as seconds and nanoseconds since epoch
    let secs = network_time.as_secs() as libc::time_t;
    let nsecs = network_time.subsec_nanos() as libc::c_long;

    let ts = libc::timespec {
        tv_sec: secs,
        tv_nsec: nsecs,
    };

    println!("  Setting system time to: {:?}", network_time);

    // SAFETY: The pointer `&ts` is valid for the duration of the call since it points to a
    // stack-allocated local variable. This call requires root privileges to set the system time.
    let res = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };

    if res == 0 {
        println!("✓ System time updated successfully");
        Ok(())
    } else {
        Err(format!("Failed to set system time: {}", std::io::Error::last_os_error()).into())
    }
}

#[cfg(not(unix))]
fn set_system_time(_network_time: Duration) -> Result<(), Box<dyn Error>> {
    Err("Setting system time is only supported on Unix systems".into())
}

/// VSOCK CID options for binding
#[derive(Debug, Clone, Copy, ValueEnum)]
enum VsockCid {
    /// Wildcard - binds to all local contexts (CID=0)
    Any,
    /// Local loopback within the same context (CID=1)
    Local,
    /// The host's fixed identity in vsock namespace (CID=2)
    Host,
}

impl From<VsockCid> for u32 {
    fn from(cid: VsockCid) -> u32 {
        match cid {
            VsockCid::Any => 0,
            VsockCid::Local => VMADDR_CID_LOCAL,
            VsockCid::Host => VMADDR_CID_HOST,
        }
    }
}

impl fmt::Display for VsockCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VsockCid::Any => write!(f, "any"),
            VsockCid::Local => write!(f, "local"),
            VsockCid::Host => write!(f, "host"),
        }
    }
}

use vsock::{VMADDR_CID_HOST, VMADDR_CID_LOCAL};

#[derive(Parser, Debug)]
#[command(author, version, about = "NTS client with VSOCK transport support", long_about = None)]
struct Args {
    /// The NTS-KE server hostname
    #[arg(long, default_value = "127.0.0.1")]
    nts_server: String,

    /// The NTS-KE server port
    #[arg(long, default_value_t = 4460)]
    nts_port: u16,

    /// VSOCK CID for datagram transport (NTP time sync)
    #[arg(long, default_value_t = VsockCid::Host)]
    vsock_datagram_cid: VsockCid,

    /// VSOCK port for datagram transport (NTP time sync)
    #[arg(long, default_value_t = 1338)]
    vsock_datagram_port: u32,

    /// VSOCK CID for stream transport (NTS-KE handshake)
    #[arg(long, default_value_t = VsockCid::Host)]
    vsock_stream_cid: VsockCid,

    /// VSOCK port for stream transport (NTS-KE handshake)
    #[arg(long, default_value_t = 8443)]
    vsock_stream_port: u32,

    /// Enable conproto for stream transport (server address negotiation)
    #[arg(long, default_value_t = false)]
    conproto: bool,

    /// Paths to additional CA certificate files to trust (can be specified multiple times)
    #[arg(long, value_name = "PATH")]
    ca_cert_path: Vec<PathBuf>,

    /// Paths to pinned certificate files for certificate pinning (can be specified multiple times)
    #[arg(long, value_name = "PATH")]
    pinned_cert_path: Vec<PathBuf>,

    /// Timeout for network operations in seconds
    #[arg(long, default_value_t = 10)]
    timeout_secs: u64,

    /// Maximum number of retry attempts
    #[arg(long, default_value_t = 3)]
    max_retries: u32,

    /// Enable verbose logging
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Set the local system time based on the network time (requires root/admin privileges)
    #[arg(long, default_value_t = false)]
    set_time: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    println!("rkik-nts VSOCK Client\n");
    println!("================================\n");

    // Print configuration
    println!("Configuration:");
    println!("  NTS-KE Server: {}:{}" , args.nts_server, args.nts_port);
    println!("  VSOCK Datagram: CID={}, Port={}", u32::from(args.vsock_datagram_cid), args.vsock_datagram_port);
    println!("  VSOCK Stream: CID={}, Port={}", u32::from(args.vsock_stream_cid), args.vsock_stream_port);
    println!("  Conproto: {}", args.conproto);
    if !args.ca_cert_path.is_empty() {
        println!("  Additional CA Certificates:");
        for path in &args.ca_cert_path {
            println!("    - {:?}", path);
        }
    }
    if !args.pinned_cert_path.is_empty() {
        println!("  Pinned Certificates:");
        for path in &args.pinned_cert_path {
            println!("    - {:?}", path);
        }
    }
    println!();

    // Create configuration for the NTS server
    let mut config = NtsClientConfig::new(&args.nts_server)
        .with_port(args.nts_port)
        .with_timeout(std::time::Duration::from_secs(args.timeout_secs))
        .with_max_retries(args.max_retries);

    // Add additional CA certificates
    if !args.ca_cert_path.is_empty() {
        config = config.with_additional_ca_certs(args.ca_cert_path);
    }

    // Add pinned certificates
    if !args.pinned_cert_path.is_empty() {
        config = config.with_pinned_certs(args.pinned_cert_path);
    }

    // Configure VSOCK datagram transport for NTP time sync
    let datagram_config = VsockDatagramConfig::new(u32::from(args.vsock_datagram_cid), args.vsock_datagram_port);
    config = config.with_vsock_datagram(datagram_config);

    // Configure VSOCK stream transport for NTS-KE handshake
    let stream_config = if args.conproto {
        VsockConfig::with_conproto(u32::from(args.vsock_stream_cid), args.vsock_stream_port)
    } else {
        VsockConfig::new(u32::from(args.vsock_stream_cid), args.vsock_stream_port)
    };
    config = config.with_vsock_stream(stream_config);

    // Create NTS client
    let mut client = NtsClient::new(config);

    // Connect and perform NTS key exchange
    println!("Connecting to NTS-KE server...");
    match client.connect().await {
        Ok(_) => {
            println!("Successfully connected to {}", args.nts_server);
            if let Some(ref server) = client.ntp_server() {
                println!("  NTP server: {}", server);
            }
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
            return Err(e.into());
        }
    }

    println!();

    // Query time
    println!("Querying time...");
    match client.get_time().await {
        Ok(time) => {
            println!("Time query successful!\n");
            println!("  Network time:  {:?}", time.network_time);
            println!("  System time:   {:?}", time.system_time);
            println!("  Offset:        {:?}", time.offset);
            println!("  Offset (ms):   {} ms", time.offset_signed());
            println!("  Round-trip:    {:?}", time.round_trip_delay);
            println!("  Authenticated: {}", time.authenticated);
            println!("  Server:        {}", time.server);

            if time.is_ahead() {
                println!("\n  System clock is ahead of network time");
            } else if time.is_behind() {
                println!("\n  System clock is behind network time");
            } else {
                println!("\n  System clock is synchronized");
            }

            // Set system time if requested
            if args.set_time {
                println!("\nAttempting to set system time...");

                // Calculate the target system time using the network time from the response
                // network_time is the corrected time from the NTP server
                let network_time_duration = time.network_time
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| format!("Invalid network time: {}", e))?;

                if let Err(e) = set_system_time(network_time_duration) {
                    eprintln!("  Error setting system time: {}", e);
                    eprintln!("  Note: Setting system time requires root/administrator privileges.");
                    return Err(e);
                }
            }
        }
        Err(e) => {
            println!("Failed to query time: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}
