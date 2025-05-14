package dns

import (
	"fmt"
	"log"
	"net"
)

// NewServer creates a new DNS server for the captive portal
func NewServer(port int, portalIP string) *Server {
	log.Printf("DNS: Creating new DNS server on port %d with portal IP %s", port, portalIP)
	return &Server{
		port:     port,
		stopChan: make(chan struct{}),
		portalIP: net.ParseIP(portalIP),
	}
}

// Start begins listening for DNS requests
func (s *Server) Start() error {
	log.Printf("DNS: Starting server on port %d", s.port)
	addr := &net.UDPAddr{Port: s.port, IP: net.ParseIP("0.0.0.0")}
	var err error
	s.conn, err = net.ListenUDP("udp4", addr)
	if err != nil {
		log.Printf("DNS: Failed to listen on UDP port %d: %v", s.port, err)
		return fmt.Errorf("failed to start DNS server: %v", err)
	}

	log.Printf("DNS: Server listening on 0.0.0.0:%d", s.port)
	go s.serve()
	return nil
}

// Stop gracefully shuts down the DNS server
func (s *Server) Stop() {
	log.Printf("DNS: Stopping server")
	s.stopOnce.Do(func() {
		close(s.stopChan)
		if s.conn != nil {
			s.conn.Close()
			log.Printf("DNS: Connection closed")
		}
	})
}

// serve handles incoming DNS requests in a loop
func (s *Server) serve() {
	log.Printf("DNS: Server routine started")
	buffer := make([]byte, 512) // Standard DNS UDP packet size

	for {
		select {
		case <-s.stopChan:
			log.Printf("DNS: Received stop signal, exiting serve routine")
			return
		default:
			n, clientAddr, err := s.conn.ReadFromUDP(buffer)
			if err != nil {
				log.Printf("DNS: Error reading from UDP: %v", err)
				continue
			}

			log.Printf("DNS: Received %d bytes from %s", n, clientAddr.String())

			// Process request in a goroutine to continue handling new requests
			go func(data []byte, addr *net.UDPAddr) {
				response := s.handleDNSRequest(data)
				if response != nil {
					_, err := s.conn.WriteToUDP(response, addr)
					if err != nil {
						log.Printf("DNS: Error sending DNS response: %v", err)
					}
				}
			}(buffer[:n], clientAddr)
		}
	}
}
