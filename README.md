# Captivating - Complete Go Captive Portal with Wireless AP

Captivating is a complete captive portal solution written in (nearly)pure Go, featuring:

1. A built-in wireless access point (hotspot)
2. A custom DNS server that intercepts all queries
3. HTTP/HTTPS servers to serve the captive portal pages
4. Support for captive portal detection on various operating systems
5. Authentication system with login page
6. Automatic detection and resolution of port conflicts
7. Pure Go implementations of most components

This project minimizes external dependencies by implementing core functionality in pure Go:
- Custom DNS server implementation
- DHCP server implementation
- Port checking utilities
- Iptables wrapper for network rules


## How Captive Portals Work: Technical Deep Dive

Captive portals are web pages that are displayed to newly connected users of public-access networks before they are granted broader network access. Here's how they function at a technical level:

### Network Interception Mechanisms

1. **DNS Hijacking**: When a client makes a DNS request, the captive portal system intercepts it and responds with its own IP address instead of the actual IP for all or specific domains.
   
2. **HTTP Redirection**: All HTTP requests are intercepted and redirected to the portal page using HTTP 302 redirects.
   
3. **Firewall Rules**: Iptables or other firewall technologies block all non-portal traffic until authentication occurs.
   
4. **Layer 2 Isolation**: Clients are typically isolated at layer 2, preventing peer-to-peer communication for security.

### Captive Portal Detection

Modern operating systems employ various methods to detect captive portals:

1. **Probe Requests**: The OS sends HTTP requests to specific URLs when connecting to a network:
   - Apple: http://captive.apple.com/hotspot-detect.html
   - Android: http://connectivitycheck.gstatic.com/generate_204
   - Windows: http://www.msftconnecttest.com/connecttest.txt
   - Linux/NetworkManager: http://networkcheck.gnome.org

2. **Response Analysis**: The OS analyzes responses for expected content or status codes:
   - Expected 200 OK with specific content for regular connections
   - Any deviation (redirect, unexpected content) indicates a captive portal

3. **HTTPS Certificate Validation**: Some systems check if HTTPS connections receive valid certificates.

### Authentication Flow

1. **Initial Connection**: Client connects to the wireless network and receives IP via DHCP.
   
2. **Network Access Restriction**: All traffic except to the portal is blocked by firewall rules.
   
3. **Portal Detection**: Client attempts to access the internet; requests are redirected to the portal.
   
4. **Authentication Process**: User authenticates via login, payment, or viewing terms.
   
5. **Rule Modification**: Upon successful authentication, the system:
   - Adds the client's MAC/IP to an allowlist
   - Modifies firewall rules to permit this client's traffic
   - May set a session timeout for reauthentication

### Implementation Challenges

1. **HTTPS Handling**: Modern browsers use HTTPS, making DNS/HTTP interception ineffective. Solutions include:
   - Relying on OS captive portal detection
   - Using a local CA certificate (security implications)
   - Focusing on DNS interception for captive portal discovery

2. **Device Compatibility**: Different devices handle captive portals differently, requiring flexible detection mechanisms.

3. **Walled Garden**: Implementing selective access to certain sites (like payment processors) while blocking general internet.

4. **Session Management**: Tracking authenticated users and handling session expiration.

5. **Regulatory Compliance**: Handling data retention and privacy laws that may apply to captive portal operators.

### Security Considerations

1. **Man-in-the-Middle Concerns**: Captive portals inherently perform a form of MITM attack, raising security considerations.

2. **HTTPS Limitations**: Cannot decrypt HTTPS traffic without security warnings to users.

3. **Authentication Security**: Credentials submitted through captive portals need protection.

4. **Rogue Portals**: Malicious actors can create fake captive portals to harvest credentials or perform phishing attacks.

This technical implementation in Captivating demonstrates these concepts through pure Go components that handle the complex interactions between DNS, DHCP, HTTP/HTTPS, and firewall management required for effective captive portal operation.


## Prerequisites

- Linux-based operating system
- Root privileges
- The following tools are required for the wireless AP only:
  - `hostapd` (for wireless AP - the only component we couldn't fully reimplement in Go)

## Usage

Since the program requires control over network interfaces, DNS, and other system services, it must be run as root:

```bash
sudo ./captivating
```

If any required ports (53, 80, 443) are already in use, the program will identify which process is using them and ask if you want to stop that process:

```
Checking if required ports are available...
Port 53 is already in use by dnsmasq (PID 1234). Do you want to stop it? [y/N]: y
Stopping process dnsmasq (PID 1234)...
Waiting for port 53 to be released...
```

### Command-line Options

```
  -ssid string
        SSID of the wireless network (default "CaptivePortal")
  -interface string
        Name of the wireless interface to use (auto-detect if empty)
  -channel int
        WiFi channel (1-11) (default 6)
  -ip string
        IP address for the captive portal (default "192.168.1.1")
  -dns-port int
        Port for the DNS server (default 53)
  -http-port int
        Port for the HTTP server (default 80)
  -https-port int
        Port for the HTTPS server (default 443)
  -redirect string
        URL to redirect users to (default "/portal")
```

Example with custom settings:

```bash
sudo ./captive-portal -ssid "MyFreeWiFi" -channel 11 -ip "10.0.0.1"
```

## Architecture

Captivating uses a modular architecture with the following key components:

### 1. Wireless Module (`wireless/`)

- **AP Management** (`ap.go`): Creates and manages a wireless access point using wpa_supplicant
- **DHCP Server** (`dhcp.go`): Pure Go DHCP server implementation for assigning IP addresses to clients
- **Interface Configuration** (`interface.go`): Setup and management of network interfaces
- **Network Management** (`network.go`): Handles routing and network connectivity
- **WPA Configuration** (`wpa.go`): Configures wireless settings via wpa_supplicant

### 2. DNS Module (`dns/`)

- **DNS Server** (`server.go`): Implements a custom DNS server that responds to all queries
- **Request Handler** (`handler.go`): Processes incoming DNS queries and redirects domains to the portal
- **Domain Management** (`domains.go`): Manages special domains for captive portal detection
- **Utilities** (`utils.go`): Helper functions for DNS packet manipulation

### 3. Portal Module (`portal/`)

- **Web Server** (`server.go`): Manages HTTP and HTTPS servers for the captive portal
- **Authentication** (`auth.go`): Handles user authentication and session management
- **Certificate Generation** (`certificate.go`): Creates self-signed TLS certificates on the fly
- **Request Handlers** (`handlers.go`): Processes web requests and serves portal pages
- **HTML Templates** (`template.go`): Manages HTML templates for the portal interface

### 4. Netfilter Module (`netfilter/`)

- **IPTables Management** (`iptables.go`): Pure Go wrapper for iptables to manage firewall rules

### 5. Utils Package (`utils/`)

- **Port Checking** (`portcheck.go`): Utilities to detect port usage and identify conflicting processes

## How It Works

1. **Startup and Port Checks**: Main program checks if required ports are available
2. **Wireless AP**: Creates a wireless access point and configures the interface
3. **DHCP Service**: The DHCP server assigns IP addresses to connecting clients
4. **DNS Interception**: All DNS queries are redirected to the captive portal's IP address
5. **Web Portal**: HTTP/HTTPS servers provide login pages and detect captive portal checks
6. **Authentication**: After successful login, users are granted access to the internet
7. **Graceful Shutdown**: Signal handlers ensure proper cleanup on exit

## Customization

- Modify the HTML templates in `portal/templates/` to customize the look and feel
- Extend the authentication logic in `portal/auth.go` to implement more sophisticated authentication
- Add custom handlers in `portal/handlers.go` for additional functionality

## Security Considerations

This software is primarily for educational purposes. For production use, consider:

1. Implementing proper user authentication with secure password storage
2. Using real SSL certificates from a trusted CA
3. Adding proper logging and monitoring
4. Implementing rate limiting for login attempts
5. Securing the wireless network with WPA2/WPA3 if desired

## Troubleshooting

### Wireless Issues

1. Make sure your wireless card supports AP mode
2. Check that hostapd is installed: `sudo apt install hostapd`
3. Try specifying the interface explicitly with `-interface wlan0`
4. Run with `-ip` set to a subnet that doesn't conflict with your network

### Port Conflicts

1. Let the program handle stopping conflicting services, or
2. Manually stop services that use ports 53, 80, or 443:
   ```
   sudo systemctl stop systemd-resolved  # for DNS port 53
   sudo systemctl stop apache2           # for HTTP port 80
   ```
3. Use custom ports with the `-dns-port`, `-http-port`, and `-https-port` flags

### DNS Resolution

If clients can connect but can't access the portal:
1. Check firewall settings on your host machine
2. Verify that the DNS server is running on the specified port
3. Ensure IP forwarding is enabled: `cat /proc/sys/net/ipv4/ip_forward`
4. If it isn't, run: `echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward`
