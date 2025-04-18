package dns

import (
	"net"
	"sync"
)

// Server represents a DNS server for the captive portal
type Server struct {
	port     int
	conn     *net.UDPConn
	stopChan chan struct{}
	stopOnce sync.Once
	portalIP net.IP // IP address where all DNS requests will be redirected
}
