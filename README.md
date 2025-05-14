# Captivating - Complete Go Captive Portal with Wireless AP

Captivating is a comprehensive captive portal solution written almost entirely in Go. It is designed to create a controlled wireless network environment where users must interact with a portal page (e.g., accept terms, log in) before gaining broader internet access.

## Features

*   **Wireless Access Point**: Creates a configurable Wi-Fi hotspot.
*   **Custom DHCP Server**: Assigns IP addresses and network configuration to clients.
    *   Implements **DHCP Option 114 (RFC 8910)** for reliable captive portal detection.
*   **Custom DNS Server**: Intercepts DNS queries to redirect clients to the portal.
*   **HTTP/HTTPS Web Server**: Serves the captive portal pages.
    *   Handles specific OS detection URLs.
    *   Uses self-signed certificates for HTTPS on the portal itself.
*   **Authentication System**: Basic login mechanism for user authentication.
*   **Port Conflict Resolution**: Detects and offers to resolve conflicts on required ports.
*   **Minimal Dependencies**: Core functionalities are custom-built in Go.
*   **Firewall Integration**: (Assumed, typically uses iptables for restricting/allowing traffic - details depend on `netfilter/iptables.go` and its usage in `main.go`)

## Dependencies

*   Go (for building and running)
*   Standard Linux utilities for network configuration (e.g., `iw`, `ip`, `hostapd`, `dnsmasq` might be used by underlying OS commands if not fully pure Go for AP setup).
*   `iptables` (if used for firewall rules).

## Installation

1.  **Clone the repository**:
    ```bash
    git clone <repository-url>
    cd captivating
    ```
2.  **Build the application**:
    ```bash
    go build -o captivating
    ```

## Usage

The application typically requires root privileges to manage network interfaces, start an access point, bind to privileged ports (53, 67, 80, 443), and potentially manage firewall rules.

```bash
sudo ./captivating [options]
```

### Command-Line Options

The following command-line options are available (defaults may vary):

*   `-interface <name>`: WiFi interface for the access point (default: "wlan0").
*   `-ssid <name>`: SSID for the WiFi network (default: "CaptivatingPortal").
*   `-channel <number>`: WiFi channel (1-14) (default: 6).
*   `-portal-ip <ip_address>`: IP address for the captive portal server itself. This will be the gateway and DNS server for clients (default: "192.168.10.1").
*   `-dns-port <port>`: Port for the internal DNS server (default: 53).
*   `-http-port <port>`: Port for the HTTP portal web server (default: 80).
*   `-https-port <port>`: Port for the HTTPS portal web server (default: 443).
*   `-redirect-url <path>`: URL path to redirect clients to for login (e.g., "/login", "/portal") (default: "/portal").
*   `-debug`: Enable debug logging (default: false).

Example:
```bash
sudo ./captivating -interface wlan1 -ssid "MyPortal" -portal-ip "10.0.0.1"
```

## How Captive Portals Work: Technical Deep Dive

Captive portals are web pages displayed to newly connected users of public-access networks before they are granted broader network access. Here's how they function at a technical level:

### Network Interception Mechanisms

1.  **DHCP Configuration**: The client receives its IP address, gateway, and DNS server address from the captive portal's DHCP server. The DNS server address is typically the captive portal device itself. Captivating's DHCP server also implements **DHCP Option 114 (RFC 8910)** to directly inform clients of the portal's URI, enhancing detection reliability.
2.  **DNS Hijacking**: When a client makes a DNS request, the captive portal system (acting as the DNS server) intercepts it and responds with its own IP address instead of the actual IP for all or specific domains.
3.  **HTTP Redirection**: All HTTP requests are intercepted and redirected to the portal page using HTTP 302 redirects or by directly serving the portal content.
4.  **Firewall Rules**: Iptables or other firewall technologies block all non-portal traffic until authentication occurs.
5.  **Layer 2 Isolation**: Clients are typically isolated at layer 2, preventing peer-to-peer communication for security.

### Captive Portal Detection

Modern operating systems employ various methods to detect captive portals:

1.  **DHCP Option 114 (RFC 8910)**: The OS receives a URI via DHCP (from Captivating's DHCP server) that points to a captive portal API (or the portal page itself, e.g., `http://<portalIP>/`). This is a more direct and reliable detection method.
2.  **Probe Requests**: The OS sends HTTP requests to specific URLs when connecting to a network:
    *   Apple: `http://captive.apple.com/hotspot-detect.html`
    *   Android/Google: `http://connectivitycheck.gstatic.com/generate_204` or `http://connectivitycheck.android.com/generate_204`
    *   Windows: `http://www.msftncsi.com/ncsi.txt`
    *   Linux/NetworkManager: `http://networkcheck.gnome.org` (varies by distribution)
3.  **Response Analysis**: The OS analyzes responses for expected content or status codes:
    *   Expected 200 OK with specific content (e.g., "Success" for Apple) or a 204 No Content for regular connections.
    *   Any deviation (redirect, unexpected content) indicates a captive portal.
4.  **HTTPS Certificate Validation**: Some systems check if HTTPS connections receive valid certificates. Self-signed certificates used by local captive portals can trigger warnings if not handled carefully by the portal detection logic (i.e., by primarily relying on HTTP probes or DHCP Option 114).

### Authentication Flow

1.  **Initial Connection**: Client connects to the wireless network and receives IP and other network settings (including DNS server IP and potentially Captive Portal API URI) via DHCP from the Captivating system.
2.  **Network Access Restriction**: All traffic except to the portal (and DNS to itself) is initially blocked by firewall rules.
3.  **Portal Detection**: Client's OS attempts to detect the captive portal using DHCP Option 114 or by making HTTP probe requests.
4.  **Redirection to Portal**: DNS queries for probe domains (or any domain, depending on configuration) are resolved to the portal's IP. HTTP requests are then directed to the portal's web server.
5.  **Authentication Process**: User is presented with the portal page and authenticates (e.g., via login, accepting terms).
6.  **Rule Modification**: Upon successful authentication, the system:
    *   Adds the client's MAC/IP to an allowlist in the firewall.
    *   May set a session timeout for reauthentication.

### Implementation Challenges

1.  **HTTPS Handling**: Modern browsers use HTTPS extensively. DNS hijacking and HTTP redirection are less effective for initial HTTPS requests due to certificate warnings. Solutions include:
    *   Relying on OS captive portal detection via HTTP probes or DHCP Option 114.
    *   Ensuring the portal responds correctly to these HTTP probes.
    *   DNS interception primarily facilitates the discovery of the portal for HTTP traffic.

## Redirection Logic - End to End

This section details the step-by-step process of how a client is redirected to the captive portal within the Captivating system.

### Phase 1: Network Connection & Initial Configuration (DHCP)

1.  **Client Connects**: A user connects their device to the wireless network broadcast by Captivating.
2.  **DHCP Request (Client -> Broadcast)**:
    *   The client, not yet having an IP address, broadcasts a **DHCPDISCOVER** message on its local network segment. This message is a general call asking "Are there any DHCP servers out there that can give me an IP address?"
    *   Key fields in DHCPDISCOVER:
        *   `op`: 1 (BOOTREQUEST)
        *   `chaddr`: Client's MAC address.
        *   Option 53 (DHCP Message Type): DHCPDISCOVER (value 1).
        *   Option 55 (Parameter Request List): Client lists options it wants from the server (e.g., Subnet Mask, Router, DNS Server, and potentially Option 114 if the client supports it).

3.  **DHCP Offer/Acknowledge (`wireless/dhcp.go`) (Captivating -> Client)**:
    *   Captivating's built-in DHCP server (`SimpleDHCPServer` in `wireless/dhcp.go`) listens on UDP port 67 for these broadcast messages.
    *   Upon receiving a DHCPDISCOVER, it responds with a **DHCPOFFER** message (unicast or broadcast depending on client flags). This message says, "I'm a DHCP server, and I can offer you this IP address and these settings."
        *   Key fields in DHCPOFFER:
            *   `op`: 2 (BOOTREPLY)
            *   `xid`: Transaction ID (copied from client's DISCOVER).
            *   `yiaddr`: 'Your' (client) IP address being offered (e.g., "192.168.10.100").
            *   `siaddr`: Server IP address (Captivating's `portalIP`).
            *   `chaddr`: Client's MAC address.
            *   Option 53: DHCPOFFER (value 2).
            *   Other options providing network details.
    *   The client then typically sends a **DHCPREQUEST** message, formally requesting the offered IP and parameters. "I'd like to accept the offer from server X for IP Y."
    *   Captivating's DHCP server finalizes the lease with a **DHCPACK** (Acknowledge) message. "Okay, IP Y is yours for Z seconds, and here are your final configuration details."
    *   This DHCPACK provides the client with:
        *   An IP address from the configured pool (e.g., `192.168.10.100`).
        *   Subnet mask (e.g., `255.255.255.0`).
        *   Router (gateway) IP: This is the IP address of the Captivating device itself (`portalIP`, e.g., "192.168.10.1"). All off-subnet traffic from the client will be sent here.
        *   DNS Server IP: Also the IP address of the Captivating device (`portalIP`). This is crucial for DNS interception.
    *   **Captive Portal Option (RFC 8910)**: The DHCP server includes **Option 114** in its DHCPOFFER and DHCPACK messages.
        *   This option provides clients with the URI of the captive portal.
        *   The URI is typically `http://<portalIP>/` (e.g., `http://192.168.10.1/`).
        *   Code snippet from `wireless/dhcp.go` in `buildDHCPMessage` function:
            ```go
            // ... (Standard BOOTP header fields: op, xid, yiaddr, siaddr, chaddr) ...
            // ... (DHCP magic cookie: 99, 130, 83, 99) ...
            pos := 240 // Start of DHCP options

            // Option 53: DHCP Message Type (e.g., DHCPOFFER (2) or DHCPACK (5))
            packet[pos] = 53; packet[pos+1] = 1; packet[pos+2] = msgType; pos += 3

            // Option 54: DHCP Server Identifier (portalIP)
            packet[pos] = 54; packet[pos+1] = 4; copy(packet[pos+2:pos+6], siaddr); pos += 6

            // Option 51: IP Address Lease Time
            packet[pos] = 51; packet[pos+1] = 4;
            packet[pos+2] = byte(leaseTime >> 24); packet[pos+3] = byte(leaseTime >> 16);
            packet[pos+4] = byte(leaseTime >> 8); packet[pos+5] = byte(leaseTime); pos += 6

            // Option 1: Subnet Mask
            packet[pos] = 1; packet[pos+1] = 4; copy(packet[pos+2:pos+6], subnetMask); pos += 6

            // Option 3: Router (Gateway IP - portalIP)
            packet[pos] = 3; packet[pos+1] = 4; copy(packet[pos+2:pos+6], router); pos += 6

            // Option 6: DNS Server (portalIP)
            packet[pos] = 6; packet[pos+1] = 4; copy(packet[pos+2:pos+6], router); pos += 6 // Using router as DNS

            // Option 114: Captive Portal URI (RFC 8910)
            captivePortalURI := fmt.Sprintf("http://%s/", siaddr.String()) // siaddr is the portalIP
            packet[pos] = 114                         // Option code for Captive-Portal
            packet[pos+1] = byte(len(captivePortalURI)) // Length of the URI
            copy(packet[pos+2:], captivePortalURI)      // The URI string, e.g., "http://192.168.10.1/"
            pos += 2 + len(captivePortalURI)

            // Option 255: End of options
            packet[pos] = 255
            pos++
            return packet[:pos]
            ```

### Phase 2: Captive Portal Detection & DNS Interception

Once the client has network configuration, its operating system will try to determine if it's behind a captive portal.

1.  **OS Detection (using DHCP Option 114)**:
    *   If the client OS supports RFC 8910, it will parse the URI from DHCP Option 114 (e.g., `http://192.168.10.1/`).
    *   The OS may then make an HTTP GET request to this URI directly.
    *   The expected response depends on the API specification (RFC8908) or, for simpler portals, might just be the portal login page itself.

2.  **OS Detection (using HTTP Probes - Fallback/Legacy)**:
    *   If Option 114 is not used/supported, or as an additional check, the OS sends HTTP GET requests to predefined URLs. These URLs are hardcoded into operating systems by their vendors.
    *   Examples (from `dns/domains.go` `GetCaptivePortalDomains()`):
        ```go
        // From dns/domains.go
        func GetCaptivePortalDomains() []string {
            return []string{
                "captive.apple.com", // iOS, macOS
                "www.apple.com", "apple.com", // Also probed by Apple
                "connectivitycheck.gstatic.com", // Android, ChromeOS
                "connectivitycheck.android.com", // Older Android
                "clients3.google.com", // Google services
                "www.msftconnecttest.com", // Windows
                "www.msftncsi.com", // Windows
                "detectportal.firefox.com", // Firefox browser
                // ... and others
            }
        }
        ```
    *   The OS expects a specific, predictable response from these URLs if internet access is unrestricted (e.g., HTTP 200 OK with "Success" content, or HTTP 204 No Content). Any deviation suggests a captive portal.

3.  **DNS Query (Client -> Captivating's DNS Server)** (`dns/server.go`):
    *   To send these HTTP probes (e.g., to `http://connectivitycheck.gstatic.com/generate_204`), the client first needs to resolve the domain name (`connectivitycheck.gstatic.com`) to an IP address.
    *   It sends a DNS query (a UDP packet, typically to port 53) to the DNS server IP it received via DHCP. In Captivating, this DNS server IP is the `portalIP` itself.
    *   Captivating's `dns.Server` has a `serve()` method that continuously listens for such UDP packets on the configured DNS port (e.g., 53).
        ```go
        // Simplified from dns/server.go
        func (s *Server) serve() {
            buffer := make([]byte, 512) // Standard DNS UDP packet size
            for {
                // ... (select for stopChan) ...
                n, clientAddr, err := s.conn.ReadFromUDP(buffer)
                // ... (error handling) ...
                go func(data []byte, addr *net.UDPAddr) {
                    response := s.handleDNSRequest(data) // Process the DNS query
                    if response != nil {
                        s.conn.WriteToUDP(response, addr) // Send DNS response
                    }
                }(buffer[:n], clientAddr)
            }
        }
        ```

4.  **DNS Interception & Response (`dns/handler.go`)**:
    *   Captivating's DNS server (`dns.Server`) receives the query. The `handleDNSRequest` function in `dns/handler.go` is responsible for parsing the request and crafting a response.
    *   **DNS Packet Structure & Constants (from `dns/constants.go`)**:
        *   A DNS packet has a 12-byte header followed by question and answer sections.
        *   Header Fields: Transaction ID (2 bytes), Flags (2 bytes), Question Count (2 bytes), Answer Count (2 bytes), etc.
            *   `headerIDOffset = 0`, `headerFlagsOffset = 2`, `headerQDCountOffset = 4`, `headerANCountOffset = 6`
        *   Key Flags for Response:
            *   `flagQR = 0x8000` (1 << 15): Indicates a response (0 for query, 1 for response).
            *   `flagAA = 0x0400` (1 << 10): Authoritative Answer (server is authoritative for the domain).
            *   `flagRD = 0x0100` (1 << 8): Recursion Desired (copied from client's request).
        *   Record Types: `typeA = 1` (IPv4 address), `typeAAAA = 28` (IPv6 address).
        *   Classes: `classIN = 1` (Internet).
    *   **Processing Logic in `handleDNSRequest`**:
        1.  **Parse Request**: The incoming DNS query (byte slice) is parsed. The domain name is extracted from the question section (e.g., using `decodeDomain`). The query type (`qType`) and class (`qClass`) are read.
        2.  **Check `httpsOnlyDomains`**:
            *   It checks if the queried domain is in the `httpsOnlyDomains` list (from `GetHttpsOnlyDomains()` in `dns/domains.go`).
            *   If `isHttpsDomain` is true AND `isCaptivePortalDetection` is false, the server returns a DNS response with zero answers. This is to avoid "hijacking" domains that are known to strictly use HTTPS and might have HSTS preloaded, which could lead to certificate errors if redirected.
            ```go
            // Simplified logic from dns/handler.go
            isHttpsDomain := isDomainInList(domain, GetHttpsOnlyDomains())
            isCaptivePortalDetection := isDomainInList(domain, GetCaptivePortalDomains())

            if qType == typeA && qClass == classIN {
                if isHttpsDomain && !isCaptivePortalDetection {
                    // Return 0 answers for HTTPS-only domains not used for detection
                    binary.BigEndian.PutUint16(response[headerANCountOffset:headerANCountOffset+2], 0) // ANCount = 0
                    binary.BigEndian.PutUint16(response[headerNSCountOffset:headerNSCountOffset+2], 0) // NSCount = 0
                    binary.BigEndian.PutUint16(response[headerARCountOffset:headerARCountOffset+2], 0) // ARCount = 0
                    log.Printf("DNS: Not redirecting HTTPS-only domain %s", domain)
                    // Response flags (QR=1, AA=1, RD=preserved) are still set.
                } else {
                    // Redirect other domains, including captive portal detection domains
                    log.Printf("DNS: Redirecting domain %s to portal %s", domain, s.portalIP.String())
                    // ... (construct A record response pointing to s.portalIP) ...
                }
            }
            ```
        3.  **Crafting a Redirected A Record Response**: For most other domains (especially known captive portal detection domains like `captive.apple.com`), the DNS server crafts a response that maps the queried domain to the `portalIP`.
            *   **Set Response Flags**: `respFlags := flagQR | flagAA | (flags & flagRD)`
               `binary.BigEndian.PutUint16(response[headerFlagsOffset:headerFlagsOffset+2], respFlags)`
            *   **Set Answer Count**: `binary.BigEndian.PutUint16(response[headerANCountOffset:headerANCountOffset+2], 1)` (ANCount = 1, meaning one answer record).
            *   **Construct the Answer Record (A Record)**:
                ```go
                // In dns/handler.go, when redirecting a domain:
                // Current offset 'offset' is just after the DNS header and question section.

                // Answer Section - Name (Domain Name Pointer for compression)
                // Points to the domain name in the Question section (usually at offset 12 from DNS packet start).
                response[offset] = 0xC0   // Pointer identifier (binary 11xxxxxx xxxxxxxx)
                response[offset+1] = 0x0C // Offset value (12 in this case, headerSize)
                offset += 2

                // Record Type: A (IPv4 address)
                binary.BigEndian.PutUint16(response[offset:offset+2], typeA) // typeA = 1
                offset += 2

                // Class: IN (Internet)
                binary.BigEndian.PutUint16(response[offset:offset+2], classIN) // classIN = 1
                offset += 2

                // Time-To-Live (TTL)
                ttl := uint32(60) // Default TTL (e.g., 60 seconds)
                if isCaptivePortalDetection {
                    ttl = 1 // Very short TTL (1 second) for captive portal domains to prevent caching
                }
                binary.BigEndian.PutUint32(response[offset:offset+4], ttl)
                offset += 4

                // RDLENGTH (Resource Data Length): 4 bytes for an IPv4 address
                binary.BigEndian.PutUint16(response[offset:offset+2], 4)
                offset += 2

                // RDATA (Resource Data): The portal's IP address (s.portalIP)
                copy(response[offset:offset+4], s.portalIP.To4()) // s.portalIP is net.IP
                offset += 4
                ```
    *   **Handling IPv6 (AAAA) Queries**:
        *   If `qType == typeAAAA`, Captivating's DNS server returns a response with zero answers (ANCount = 0).
        *   This is a common strategy to encourage clients to fall back to IPv4 for DNS resolution. This simplifies the captive portal logic, as it primarily has to deal with redirecting IPv4 traffic.
            ```go
            // else if qType == typeAAAA && qClass == classIN
            binary.BigEndian.PutUint16(response[headerANCountOffset:headerANCountOffset+2], 0) // ANCount = 0
            // ... (zero out other counts)
            log.Printf("DNS: Returning empty response for AAAA query for %s", domain)
            ```
    *   The final DNS response byte slice `response[:offset]` is then sent back to the client.

### Phase 3: HTTP/HTTPS Interaction & Portal Display (`portal/handlers.go`)

1.  **Client HTTP Request to Portal IP**:
    *   As a result of the DNS interception, the client's OS now believes that the IP address for `connectivitycheck.gstatic.com` (or whatever domain it probed) is the `portalIP` of the Captivating device.
    *   The client (OS or browser) sends an HTTP GET request.
        *   **Destination IP**: `portalIP`.
        *   **Destination Port**: 80 (for HTTP).
        *   **HTTP Host Header**: Still contains the original domain (e.g., `Host: connectivitycheck.gstatic.com`).
        *   **Request Path**: The original path (e.g., `/generate_204` or `/hotspot-detect.html`).

2.  **Portal Web Server Response (`portal.Server`, `portal.Handler`)**:
    *   Captivating's web server (`portal.Server` defined in `portal/server.go`) listens on HTTP (e.g., port 80, `s.httpPort`) and HTTPS (e.g., port 443, `s.httpsPort`) on the `portalIP`.
    *   The main request router is `Handler.ServeHTTP` in `portal/handlers.go`. This function determines if the request is HTTP or HTTPS and passes it to the appropriate handler.
        ```go
        // From portal/handlers.go
        func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
            clientIP := getClientIP(r) // Utility to get actual client IP
            log.Printf("Portal access from %s: %s %s (TLS: %v)", clientIP, r.Method, r.URL.Path, r.TLS != nil)

            // Set common security and cache-control headers
            w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
            w.Header().Set("Pragma", "no-cache")
            w.Header().Set("Expires", "0")

            if r.TLS != nil {
                h.handleHTTPSRequest(w, r, clientIP) // Handles requests to the HTTPS port
                return
            }
            h.handleHTTPRequest(w, r, clientIP) // Handles requests to the HTTP port
        }
        ```
    *   **Handling HTTP Requests (`handleHTTPRequest` in `portal/handlers.go`)**:
        *   **Specific Captive Portal Detection URLs**: The handler checks if `r.URL.Path` matches known OS detection URLs (defined in `portal/constants.go` `AppleSuccessURLs`, `NoContentURLs`, and also checks against `CaptivePortalDetectionPatterns` which might include hostnames if `r.Host` is checked).
            *   For `AppleSuccessURLs` (e.g., `/hotspot-detect.html`):
                The server responds with HTTP 200 OK and a simple HTML body containing "Success". This is what iOS/macOS expects to see to confirm unrestricted internet. In a captive scenario, this response (or the login page) indicates a portal.
                ```go
                // Simplified from portal/handlers.go, actual might use templates
                // if isAppleSuccessURL(r.URL.Path)
                w.Header().Set("Content-Type", "text/html")
                w.WriteHeader(http.StatusOK)
                // templateManager.ExecuteTemplate(w, "apple_success.html", nil)
                // or directly:
                w.Write([]byte("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"))
                return
                ```
            *   For `NoContentURLs` (e.g., `/generate_204` for Android/Google):
                The server responds with HTTP 204 No Content. This is what Android/Google services expect.
                ```go
                // Simplified from portal/handlers.go
                // if isNoContentURL(r.URL.Path)
                w.WriteHeader(http.StatusNoContent)
                return
                ```
            *   Satisfying these OS probes correctly is crucial. If the OS detects the portal, it will typically:
                *   Display a notification ("Sign in to Wi-Fi network").
                *   Automatically open a browser (or a sandboxed web view) to the page that was originally requested or to a page indicated by the portal (e.g., via the DHCP Option 114 URI or by redirecting the probe itself).
        *   **General HTTP Redirection (if client is not authorized)**:
            *   If the request is for any other HTTP URL (and not a special path like `/login`, `/favicon.ico`, or the portal page itself, and the client is not yet authenticated via `h.auth.IsClientAuthorized(clientIP)`):
            *   The server issues an HTTP 302 Found redirect to the main portal login page (e.g., `h.server.redirectURL` which might be `/portal`).
            ```go
            // Simplified redirection logic in portal/handlers.go handleHTTPRequest:
            // This check happens after specific detection URLs and other special paths.
            if !h.auth.IsClientAuthorized(clientIP) && r.URL.Path != h.server.redirectURL && r.URL.Path != "/login" {
                log.Printf("Redirecting unauthorized client %s from %s to portal %s", clientIP, r.URL.Path, h.server.redirectURL)
                http.Redirect(w, r, h.server.redirectURL, http.StatusFound)
                return
            }
            ```
        *   **Serving the Portal Page**: When the client is redirected to or directly accesses `h.server.redirectURL` (e.g., `/portal`), the `portalHandler` (if matched by a route) serves the HTML login page (e.g., `login.html` from embedded templates using `h.templateManager`).
        *   **Login Submission**: When the user submits the login form (typically a POST to `/login`):
            *   The request is handled, credentials are checked by `h.auth.Authenticate()`.
            *   If successful, `h.auth.AuthorizeClient(clientIP)` adds the client's IP (or MAC address, depending on implementation) to an allowlist. This allowlist is then used by the firewall component to grant broader network access.
            *   The user is then typically redirected to a success page or their original intended destination.
    *   **Handling HTTPS Requests (`handleHTTPSRequest` in `portal/handlers.go`)**:
        *   Directly intercepting and redirecting *arbitrary* HTTPS traffic (e.g., a user trying to visit `https://google.com`) is generally avoided because the captive portal uses a self-signed certificate (generated by `GenerateSelfSignedCertPEM()` in `portal/certificate.go`). This would cause major browser certificate warnings, alarming the user.
        *   The portal's HTTPS server (`https://<portalIP>`) primarily serves:
        *   It does not attempt to transparently MITM other HTTPS sites. The reliance is on the OS detecting the portal via HTTP probes or DHCP Option 114 and then opening the portal page in a browser, which might then use HTTPS for the login interaction.

## Glossary

*   **BOOTREQUEST (op=1)**: A message sent by a DHCP client to a DHCP server to request network configuration parameters, such as an IP address. This is the initial type of message in the DHCP discovery process (e.g., DHCPDISCOVER). The `op` field in the BOOTP/DHCP header is set to 1.
*   **BOOTREPLY (op=2)**: A message sent by a DHCP server to a DHCP client in response to a BOOTREQUEST. This includes messages like DHCPOFFER and DHCPACK. The `op` field in the BOOTP/DHCP header is set to 2.
*   **DHCP Magic Cookie**: A fixed 4-byte value (99, 130, 83, 99 or `0x63825363` in hexadecimal) that marks the beginning of the DHCP-specific options area in a BOOTP/DHCP packet. It allows DHCP servers and clients to distinguish DHCP messages from older BOOTP messages.
*   **DHCPDISCOVER**: The first message sent by a DHCP client when it attempts to connect to a network. It's a broadcast message used to locate available DHCP servers. (Message Type 1)
*   **DHCPOFFER**: A message sent by a DHCP server in response to a DHCPDISCOVER message. It "offers" an IP address and other network configuration parameters to the client. (Message Type 2)
*   **DHCPREQUEST**: A message sent by a DHCP client in response to one or more DHCPOFFER messages. The client uses this message to formally request the offered IP address from a specific server. It's also used by clients to renew an existing lease or to verify an existing IP address after a reboot. (Message Type 3)
*   **DHCPACK (Acknowledge)**: A message sent by a DHCP server to a client to confirm that the IP address lease is finalized and to provide any remaining configuration parameters. This message completes the DHCP lease process for a new client. (Message Type 5)
*   **DHCPNAK (Negative Acknowledge)**: A message sent by a DHCP server to a client to indicate that the client's notion of a network address is incorrect (e.g., client requested an invalid IP address or its lease has expired and the IP is no longer available). (Message Type 6)
*   **DHCPRELEASE**: A message sent by a DHCP client to a DHCP server to terminate its lease and return the IP address to the server's pool of available addresses. (Message Type 7)
*   **DHCPINFORM**: A message sent by a DHCP client that already has an IP address (e.g., manually configured) to obtain other local configuration details from a DHCP server, such as DNS server addresses or a domain name. (Message Type 8)
*   **`chaddr` (Client Hardware Address)**: A field in the DHCP packet header that contains the MAC address of the client.
*   **`yiaddr` (Your IP Address)**: A field in the DHCP packet header. In a DHCPOFFER or DHCPACK message, this field contains the IP address that the server is offering or assigning to the client.
*   **`siaddr` (Server IP Address)**: A field in the DHCP packet header. In DHCPOFFER and DHCPACK messages, this usually contains the IP address of the DHCP server itself. It can also be used to indicate the next server to use in network booting.
*   **`xid` (Transaction ID)**: A random 32-bit identifier generated by the client and used to match requests with replies in the DHCP message exchange.
*   **Option 53 (DHCP Message Type)**: A DHCP option that specifies the type of the DHCP message (e.g., DHCPDISCOVER, DHCPOFFER, DHCPREQUEST, DHCPACK).
*   **Option 114 (Captive-Portal URI)**: A DHCP option (defined in RFC 8910) used by a DHCP server to inform clients of the URI for accessing the captive portal API or login page. This helps clients reliably detect the presence of a captive portal.

