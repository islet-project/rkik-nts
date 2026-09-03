# Islet Project: NTS Client with VSOCK Support

## Overview

This document describes the modifications made to the original **rkik-nts** NTS (Network Time Security) client to enable operation in virtualized environments where traditional TCP/IP networking is unavailable. The changes introduce **VSOCK (Virtual Sockets)** support, allowing the NTS client to run inside isolated VMs while communicating with host-based time services.

### Background: What Changed from Original rkik-nts

The original rkik-nts library was designed for standard TCP/IP networks where:
- The NTS-KE (Key Exchange) handshake occurs over TCP/TLS
- NTP time synchronization packets are sent via UDP directly

For the Islet project, the following architectural changes were implemented:

#### 1. VSOCK Stream Transport for NTS-KE

A new `TransportStream` enum was added that supports both TCP and VSOCK connections:

```rust
pub enum TransportStream {
    Tcp(tokio::net::TcpStream),
    Vsock(VsockStream),  // New VSOCK support
}
```

When VSOCK is configured, the client connects to a **stream proxy** on the host that forwards the TLS-encrypted NTS-KE traffic to the actual NTS-KE server.

#### 2. VSOCK Datagram Transport for NTP Packets

A new `VsockDatagramTransport` was implemented that:
- Establishes a VSOCK stream connection to a **datagram proxy** on the host
- Uses a custom framing protocol to send NTP packets with hostname/port information
- Receives NTP responses through the same VSOCK connection

The framing protocol uses the following format:

| Field | Size | Description |
|-------|------|-------------|
| hostname_len | 1 byte | Length of the hostname string |
| hostname | variable | Hostname bytes |
| port | 2 bytes | Destination port (big-endian) |
| payload_len | 4 bytes | Length of payload data (big-endian) |
| payload | variable | NTP packet data |

#### 3. Conproto Protocol

A **conproto** (connection protocol) mechanism was added for server address negotiation. When enabled:
- The VSOCK client sends a CONNECT request to the proxy with the target hostname and port
- The proxy establishes the actual TCP/UDP connection on behalf of the VM
- This allows the proxy to handle DNS resolution and connection management

#### 4. Configuration Extensions

New configuration structs were added:

- **`VsockConfig`**: Configures VSOCK stream transport (CID, port, conproto flag)
- **`VsockDatagramConfig`**: Configures VSOCK datagram transport (CID, port)
- **`NtpServerConfig`**: Enum for either direct socket address or hostname-based config

---

## Running locally on Ubuntu

This section describes how to set up and run the complete NTS time synchronization stack locally for development and testing purposes.

### Prerequisites

Install chrony daemon on your Ubuntu system:

```bash
sudo apt install chrony
```

### Step 1: Configure Chrony

Copy the chrony configuration file (with NTS support enabled) and development certificates:

```bash
cd rkik-nts
sudo cp chrony/chrony.conf /etc/chrony/
sudo cp chrony/certs/nts-devel.key /etc/chrony/
sudo cp chrony/certs/nts-devel.crt /etc/chrony/
sudo chown _chrony:_chrony /etc/chrony/nts-devel.key
sudo chown _chrony:_chrony /etc/chrony/nts-devel.crt
sudo chmod 440 /etc/chrony/nts-devel.key
sudo chmod 644 /etc/chrony/nts-devel.crt
```

Restart the chrony daemon to apply the configuration:

```bash
sudo systemctl restart chrony
```

### Step 2: Enable VSOCK Loopback

Ensure your Linux kernel provides VSOCK loopback support (allows communication with local CID=1):

```bash
sudo modprobe vsock_loopback
```

### Step 3: Launch VSOCK Proxies

Two proxy instances are required - one for stream (TLS/NTS-KE) and one for datagram (NTP) traffic.

Navigate to the vsock proxy directory:
```bash
cd <AOSP>/packages/modules/Virtualization/libs/libvsock_proxy
```

**Launch the stream proxy** (for TLS-encrypted NTS-KE handshake):

```bash
cargo run -- \
  --mode stream \
  --vsock-cid local \
  --vsock-port 8443 \
  --vm-cid 1 \
  -c \
  --verbose
```

**Launch the datagram proxy** (for NTP time synchronization packets):

```bash
cargo run -- \
  --mode datagram \
  --vsock-cid local \
  --vsock-port 8888 \
  --vm-cid 1 \
  -c \
  --verbose
```

### Step 4: Run the NTS VSOCK Client

From the `rkik-nts` source directory, run the example client:

```bash
cargo run --example nts_vsock_client --features="tracing-subscriber vsock" -- \
  --nts-server 127.0.0.1 \
  --vsock-stream-cid local \
  --vsock-stream-port 8443  \
  --vsock-datagram-cid local \
  --vsock-datagram-port 8888 \
  --conproto \
  --pinned-cert-path /etc/chrony/nts-devel.crt \
  --verbose
```

#### Command Line Options Explained

| Option | Description |
|--------|-------------|
| `--nts-server` | Hostname of the NTS-KE server (used for TLS verification) |
| `--vsock-stream-cid` | VSOCK Context ID for the stream proxy (NTS-KE) |
| `--vsock-stream-port` | VSOCK port for the stream proxy (default: 8443) |
| `--vsock-datagram-cid` | VSOCK Context ID for the datagram proxy (NTP) |
| `--vsock-datagram-port` | VSOCK port for the datagram proxy (default: 8888) |
| `--conproto` | Enable conproto protocol for server address negotiation |
| `--pinned-cert-path` | Path to pinned certificate for certificate pinning |
| `--verbose` | Enable debug logging |

### Example Output

```
Configuration:
  NTS-KE Server: 127.0.0.1:4460
  VSOCK Datagram: CID=1, Port=8888
  VSOCK Stream: CID=1, Port=8443
  Conproto: true
  Pinned Certificates:
    - "/etc/chrony/nts-devel.crt"

Connecting to NTS-KE server...
2026-09-03T05:02:15.044549Z  INFO rkik_nts::client: Connecting to NTS server: 127.0.0.1
2026-09-03T05:02:15.044567Z  INFO rkik_nts::nts_ke: Starting NTS-KE with 127.0.0.1:4460 (transport: VSOCK)
...
2026-09-03T05:02:15.098546Z  INFO rkik_nts::client: NTS key exchange successful. NTP server: Hostname(NtpServerInfo { hostname: "127.0.0.1", port: 123 }), cookies: 8
Successfully connected to 127.0.0.1

Querying time...
Time query successful!

  Network time:  SystemTime { tv_sec: 1788411735, tv_nsec: 101928739 }
  System time:   SystemTime { tv_sec: 1788411735, tv_nsec: 101475355 }
  Offset:        453.384µs
  Offset (ms):   0 ms
  Round-trip:    1.935275ms
  Authenticated: true
  Server:        127.0.0.1:123

  System clock is behind network time
```

---

## Cross-compiling a prebuilt client binary

To build the client executable for ARM64 target (e.g., for deployment in [Microdroid/AVF/Arm CCA Realms](https://github.com/islet-project/odcc-aosp-modules-virtualization)):

```bash
cargo install cross
cross build --example nts_vsock_client --features="tracing-subscriber vsock dangerous-configuration" --release --target aarch64-unknown-linux-musl
```

The resulting `nts_vsock_client` binary should be placed in:
```
<AOSP>/packages/modules/Virtualization/build/tools/prebuilt/
```

---

## Integration with AOSP/AVF

In Islet's AOSP/AVF [environment](https://github.com/islet-project/odcc-aosp-modules-virtualization), the vsock proxy is used as a library (libvsock_proxy) rather than a standalone binary. The virtualization manager (`virtmgr`) configures and launches the proxy instances automatically when starting VMs that require NTS time synchronization.

For development and experimentation purposes, the command-line usage described above can be used.
