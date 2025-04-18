package wireless

import (
	"captivating/netfilter"
	"fmt"
	"log"
)

// NetworkConfig contains the configuration for network setup
type NetworkConfig struct {
	InterfaceName string
	ServerIP      string
}

// ConfigureNetworking sets up IP forwarding and network routing rules
// to direct traffic to the captive portal
func ConfigureNetworking(config NetworkConfig) error {
	iptablesManager := netfilter.NewManager()

	// Enable IP forwarding in the kernel
	if err := netfilter.SetIPForwarding(true); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Find the interface connected to the internet
	mainIface, err := GetMainInterface()
	if err != nil {
		log.Printf("Warning: Could not determine main interface: %v", err)
		// Continue anyway - users can still connect to our portal
	} else {
		// Set up NAT for internet access
		if err := iptablesManager.SetupNAT(mainIface); err != nil {
			return fmt.Errorf("failed to set up NAT: %w", err)
		}
	}

	// === Base Traffic Rules ===

	// Allow all traffic on the wireless interface
	if err := iptablesManager.AddRule(netfilter.Rule{
		Table:       "filter",
		Chain:       "INPUT",
		InInterface: config.InterfaceName,
		Target:      "ACCEPT",
	}); err != nil {
		return fmt.Errorf("failed to add input traffic rule: %w", err)
	}

	if err := iptablesManager.AddRule(netfilter.Rule{
		Table:        "filter",
		Chain:        "OUTPUT",
		OutInterface: config.InterfaceName,
		Target:       "ACCEPT",
	}); err != nil {
		return fmt.Errorf("failed to add output traffic rule: %w", err)
	}

	if err := iptablesManager.AddRule(netfilter.Rule{
		Table:       "filter",
		Chain:       "FORWARD",
		InInterface: config.InterfaceName,
		Target:      "ACCEPT",
	}); err != nil {
		return fmt.Errorf("failed to add forward traffic rule: %w", err)
	}

	// === DHCP Rules ===

	// Allow DHCP server traffic
	if err := iptablesManager.AddRule(netfilter.Rule{
		Table:       "filter",
		Chain:       "INPUT",
		Protocol:    "udp",
		InInterface: config.InterfaceName,
		DestPort:    67,
		Target:      "ACCEPT",
	}); err != nil {
		return fmt.Errorf("failed to add DHCP server rule: %w", err)
	}

	// Allow DHCP client traffic
	if err := iptablesManager.AddRule(netfilter.Rule{
		Table:        "filter",
		Chain:        "OUTPUT",
		Protocol:     "udp",
		OutInterface: config.InterfaceName,
		SourcePort:   67,
		DestPort:     68,
		Target:       "ACCEPT",
	}); err != nil {
		return fmt.Errorf("failed to add DHCP client rule: %w", err)
	}

	// Allow DHCP broadcast traffic
	if err := iptablesManager.AddRule(netfilter.Rule{
		Table:       "filter",
		Chain:       "INPUT",
		Protocol:    "udp",
		InInterface: config.InterfaceName,
		DestPort:    68,
		Target:      "ACCEPT",
	}); err != nil {
		return fmt.Errorf("failed to add DHCP broadcast rule: %w", err)
	}

	// Allow broadcast traffic for DHCP discovery
	if err := iptablesManager.AddRule(netfilter.Rule{
		Table:       "filter",
		Chain:       "INPUT",
		InInterface: config.InterfaceName,
		Destination: "255.255.255.255",
		Target:      "ACCEPT",
	}); err != nil {
		return fmt.Errorf("failed to add broadcast input rule: %w", err)
	}

	if err := iptablesManager.AddRule(netfilter.Rule{
		Table:        "filter",
		Chain:        "OUTPUT",
		OutInterface: config.InterfaceName,
		Destination:  "255.255.255.255",
		Target:       "ACCEPT",
	}); err != nil {
		return fmt.Errorf("failed to add broadcast output rule: %w", err)
	}

	// === Traffic Redirection Rules ===

	// Redirect DNS queries to our DNS server
	if err := iptablesManager.RedirectToHost(config.InterfaceName, "udp", 53, config.ServerIP, 53); err != nil {
		return fmt.Errorf("failed to redirect DNS traffic: %w", err)
	}

	// Redirect TCP DNS traffic (used by some systems)
	if err := iptablesManager.RedirectToHost(config.InterfaceName, "tcp", 53, config.ServerIP, 53); err != nil {
		log.Printf("Warning: Failed to redirect TCP DNS traffic: %v", err)
	}

	// Redirect HTTP traffic to our portal
	if err := iptablesManager.RedirectToHost(config.InterfaceName, "tcp", 80, config.ServerIP, 80); err != nil {
		return fmt.Errorf("failed to redirect HTTP traffic: %w", err)
	}

	// Redirect HTTPS traffic to our portal
	if err := iptablesManager.RedirectToHost(config.InterfaceName, "tcp", 443, config.ServerIP, 443); err != nil {
		return fmt.Errorf("failed to redirect HTTPS traffic: %w", err)
	}

	// === Captive Portal Detection Support ===

	// Allow local HTTP/HTTPS traffic
	if err := iptablesManager.AddRule(netfilter.Rule{
		Table:       "filter",
		Chain:       "INPUT",
		Protocol:    "tcp",
		Destination: config.ServerIP,
		DestPort:    80,
		Target:      "ACCEPT",
	}); err != nil {
		log.Printf("Warning: Failed to add HTTP accept rule: %v", err)
	}

	if err := iptablesManager.AddRule(netfilter.Rule{
		Table:       "filter",
		Chain:       "INPUT",
		Protocol:    "tcp",
		Destination: config.ServerIP,
		DestPort:    443,
		Target:      "ACCEPT",
	}); err != nil {
		log.Printf("Warning: Failed to add HTTPS accept rule: %v", err)
	}

	// Block external DNS to ensure our DNS server is used
	if err := iptablesManager.AddRule(netfilter.Rule{
		Table:    "filter",
		Chain:    "FORWARD",
		Protocol: "udp",
		DestPort: 53,
		Target:   "DROP",
	}); err != nil {
		log.Printf("Warning: Failed to add DNS blocking rule: %v", err)
	}

	log.Printf("Network configuration completed successfully")
	return nil
}
