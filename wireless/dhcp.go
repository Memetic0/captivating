package wireless

import (
	"captivating/utils"
	"fmt"
	"log"
	"net"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// DHCPServer interface defines the methods a DHCP server should implement
type DHCPServer interface {
	Start() error
	Stop()
}

// DHCPServerConfig contains configuration for the DHCP server
type DHCPServerConfig struct {
	InterfaceName string
	ServerIP      string
	StopChan      chan struct{}
}

// SimpleDHCPServer implements the DHCPServer interface
type SimpleDHCPServer struct {
	config        DHCPServerConfig
	conn          *net.UDPConn
	leases        map[string]net.IP
	lastIP        net.IP
	leaseDuration uint32
}

// NewDHCPServer creates a new DHCP server instance
func NewDHCPServer(config DHCPServerConfig) (DHCPServer, error) {
	// Check if DHCP port (67) is already in use
	inUse, processName, pid, err := utils.IsPortInUse(67)
	if err == nil && inUse {
		return nil, fmt.Errorf("DHCP port (67) is already in use by %s (PID %d)", processName, pid)
	}

	// Calculate initial last IP for assignment
	serverIP := net.ParseIP(config.ServerIP).To4()
	lastIP := make(net.IP, 4)
	copy(lastIP, serverIP)
	lastIP[3] = 100

	return &SimpleDHCPServer{
		config:        config,
		leases:        make(map[string]net.IP),
		lastIP:        lastIP,
		leaseDuration: 24 * 60 * 60, // 24 hours in seconds
	}, nil
}

// Start initializes and runs the DHCP server
func (s *SimpleDHCPServer) Start() error {
	// Bind to DHCP server port (67)
	addr, err := net.ResolveUDPAddr("udp4", s.config.ServerIP+":67")
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	s.conn, err = net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on port 67: %w", err)
	}
	// Configure socket for broadcast and bind to specific interface
	f, err := s.conn.File()
	if err == nil {
		defer f.Close()
		syscall.SetsockoptInt(syscall.Handle(f.Fd()), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)

		// Bind to specific interface
		if runtime.GOOS == "linux" {
			// Linux-specific code to bind to interface
			interfaceNameBytes := []byte(s.config.InterfaceName)
			// SO_BINDTODEVICE constant value is 25 on Linux
			const SO_BINDTODEVICE = 25
			err = syscall.Setsockopt(syscall.Handle(f.Fd()), syscall.SOL_SOCKET, SO_BINDTODEVICE,
				(*byte)(unsafe.Pointer(&interfaceNameBytes[0])), int32(len(interfaceNameBytes)))
			if err != nil {
				log.Printf("DHCP: Warning: failed to bind to interface %s: %v", s.config.InterfaceName, err)
				// Depending on policy, you might want to return an error here
				// For now, we'll just log a warning and continue
			}
		}
	}

	log.Printf("DHCP: Server listening on %s:67", s.config.ServerIP)

	// Start the packet processing loop in a goroutine
	go s.processPackets()

	return nil
}

// Stop terminates the DHCP server
func (s *SimpleDHCPServer) Stop() {
	if s.conn != nil {
		s.conn.Close()
	}
}

// processPackets handles DHCP packet processing
func (s *SimpleDHCPServer) processPackets() {
	// Create buffer for incoming packets
	buffer := make([]byte, 1500)

	// Network configuration
	ipNet := &net.IPNet{
		IP:   net.ParseIP(s.config.ServerIP).To4(),
		Mask: net.CIDRMask(24, 32),
	}

	// Main packet processing loop
	for {
		// Set read deadline to allow checking for program termination
		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, _, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if we should stop the server
				select {
				case <-s.config.StopChan:
					log.Printf("DHCP: Server shutting down")
					return
				default:
					// Continue listening
				}
				continue
			}
			log.Printf("DHCP: Error reading from UDP: %v", err)
			continue
		}

		// Get the packet data
		dhcpPacket := buffer[:n]

		// Validate DHCP packet (minimum size + BOOTP op code)
		if n < 240 || dhcpPacket[0] != 1 { // BOOTREQUEST
			continue
		}

		// Extract client MAC address
		clientMAC := net.HardwareAddr(dhcpPacket[28:34])
		macStr := clientMAC.String()

		// Find DHCP message type from options
		var msgType byte
		for i := 240; i < n-2; {
			if dhcpPacket[i] == 53 { // DHCP Message Type option
				msgType = dhcpPacket[i+2]
				break
			}
			if dhcpPacket[i] == 255 { // End option
				break
			}
			if dhcpPacket[i] == 0 { // Padding
				i++
				continue
			}
			i += int(dhcpPacket[i+1]) + 2 // Skip to next option
		}

		var response []byte

		// Handle different DHCP message types
		switch msgType {
		case 1: // DHCPDISCOVER - Client is looking for a DHCP server
			log.Printf("DHCP: Received DISCOVER from %s", macStr)

			// Assign an IP address
			assignedIP := net.IP{}
			if ip, ok := s.leases[macStr]; ok {
				// Use existing lease if client has one
				assignedIP = ip
			} else {
				// Assign new IP from pool
				assignedIP = make(net.IP, 4)
				copy(assignedIP, s.lastIP)

				// Increment last IP for next assignment
				s.lastIP = net.IP{s.lastIP[0], s.lastIP[1], s.lastIP[2], s.lastIP[3] + 1}
				if s.lastIP[3] > 250 {
					s.lastIP[3] = 100 // Wrap around to start of range
				}

				// Store the lease
				s.leases[macStr] = assignedIP
			}

			log.Printf("DHCP: Offering %s to %s", assignedIP.String(), macStr)

			// Create DHCPOFFER message
			response = buildDHCPMessage(
				2,                                    // BOOTREPLY
				dhcpPacket[4:8],                      // XID (transaction ID)
				assignedIP.To4(),                     // Your IP
				net.ParseIP(s.config.ServerIP).To4(), // Server IP
				clientMAC,                            // Client MAC
				2,                                    // DHCPOFFER
				s.leaseDuration,
				net.ParseIP(s.config.ServerIP).To4(), // Router (gateway)
				ipNet.Mask,                           // Subnet mask
			)

		case 3: // DHCPREQUEST - Client requesting the offered IP
			log.Printf("DHCP: Received REQUEST from %s", macStr)

			// Extract requested IP and server ID from options
			var requestedIP net.IP
			var serverID net.IP

			for i := 240; i < n-5; {
				if dhcpPacket[i] == 50 && dhcpPacket[i+1] == 4 { // Requested IP
					requestedIP = net.IP(dhcpPacket[i+2 : i+6])
				}
				if dhcpPacket[i] == 54 && dhcpPacket[i+1] == 4 { // Server ID
					serverID = net.IP(dhcpPacket[i+2 : i+6])
				}
				if dhcpPacket[i] == 255 { // End option
					break
				}
				if dhcpPacket[i] == 0 { // Padding
					i++
					continue
				}
				i += int(dhcpPacket[i+1]) + 2 // Skip to next option
			}

			// Only respond if this request is for our server
			if serverID != nil && serverID.Equal(net.ParseIP(s.config.ServerIP)) {
				if requestedIP == nil {
					// Use the offered IP from the client's 'ciaddr' field
					requestedIP = net.IP(dhcpPacket[12:16])
				}

				// Update lease
				s.leases[macStr] = requestedIP

				log.Printf("DHCP: Acknowledging %s to %s", requestedIP.String(), macStr)

				// Create DHCPACK message
				response = buildDHCPMessage(
					2,                                    // BOOTREPLY
					dhcpPacket[4:8],                      // XID (transaction ID)
					requestedIP.To4(),                    // Your IP
					net.ParseIP(s.config.ServerIP).To4(), // Server IP
					clientMAC,                            // Client MAC
					5,                                    // DHCPACK
					s.leaseDuration,
					net.ParseIP(s.config.ServerIP).To4(), // Router (gateway)
					ipNet.Mask,                           // Subnet mask
				)
			}
		}

		// Send response if we have one
		if response != nil {
			// Send to broadcast address on client port
			broadcastAddr := &net.UDPAddr{
				IP:   net.IPv4bcast,
				Port: 68,
			}

			_, err = s.conn.WriteToUDP(response, broadcastAddr)
			if err != nil {
				log.Printf("DHCP: Error sending response: %v", err)
			}
		}
	}
}

// buildDHCPMessage creates a DHCP packet with the specified parameters
func buildDHCPMessage(
	op byte, // Operation: 1=BOOTREQUEST, 2=BOOTREPLY
	xid []byte, // Transaction ID
	yiaddr net.IP, // Your (client) IP address
	siaddr net.IP, // Server IP address
	chaddr net.HardwareAddr, // Client hardware address
	msgType byte, // DHCP message type: 1=DISCOVER, 2=OFFER, 3=REQUEST, 5=ACK
	leaseTime uint32, // Lease time in seconds
	router net.IP, // Router/gateway IP
	subnetMask net.IPMask, // Subnet mask
) []byte {
	packet := make([]byte, 576) // Standard DHCP packet size

	// Standard BOOTP header
	packet[0] = op         // Operation code
	packet[1] = 1          // Hardware type: Ethernet
	packet[2] = 6          // Hardware address length: 6 bytes for MAC
	packet[3] = 0          // Hops
	copy(packet[4:8], xid) // Transaction ID

	// IP addresses
	copy(packet[16:20], yiaddr) // Your IP address
	copy(packet[20:24], siaddr) // Server IP address

	// Client hardware address (MAC)
	copy(packet[28:34], chaddr)

	// DHCP magic cookie (rfc1497)
	packet[236] = 99
	packet[237] = 130
	packet[238] = 83
	packet[239] = 99

	// DHCP Options section
	pos := 240

	// Option 53: DHCP message type
	packet[pos] = 53        // Option code
	packet[pos+1] = 1       // Length
	packet[pos+2] = msgType // Value
	pos += 3

	// Option 54: DHCP server identifier
	packet[pos] = 54                  // Option code
	packet[pos+1] = 4                 // Length
	copy(packet[pos+2:pos+6], siaddr) // Value
	pos += 6

	// Option 51: IP address lease time
	packet[pos] = 51                      // Option code
	packet[pos+1] = 4                     // Length
	packet[pos+2] = byte(leaseTime >> 24) // Value (4 bytes, big endian)
	packet[pos+3] = byte(leaseTime >> 16)
	packet[pos+4] = byte(leaseTime >> 8)
	packet[pos+5] = byte(leaseTime)
	pos += 6

	// Option 1: Subnet mask
	packet[pos] = 1                       // Option code
	packet[pos+1] = 4                     // Length
	copy(packet[pos+2:pos+6], subnetMask) // Value
	pos += 6

	// Option 3: Router
	packet[pos] = 3                   // Option code
	packet[pos+1] = 4                 // Length
	copy(packet[pos+2:pos+6], router) // Value
	pos += 6

	// Option 6: DNS server (use router IP as DNS server)
	packet[pos] = 6                   // Option code
	packet[pos+1] = 4                 // Length
	copy(packet[pos+2:pos+6], router) // Value
	pos += 6

	// Option 28: Broadcast address
	broadcastIP := net.IP{yiaddr[0], yiaddr[1], yiaddr[2], 255}
	packet[pos] = 28                       // Option code
	packet[pos+1] = 4                      // Length
	copy(packet[pos+2:pos+6], broadcastIP) // Value
	pos += 6

	// Option 12: Hostname
	hostName := "captiveportal"
	packet[pos] = 12                    // Option code
	packet[pos+1] = byte(len(hostName)) // Length
	copy(packet[pos+2:], hostName)      // Value
	pos += 2 + len(hostName)

	// Option 15: Domain name
	domainName := "local"
	packet[pos] = 15                      // Option code
	packet[pos+1] = byte(len(domainName)) // Length
	copy(packet[pos+2:], domainName)      // Value
	pos += 2 + len(domainName)

	// Option 255: End
	packet[pos] = 255
	pos++

	return packet[:pos]
}
