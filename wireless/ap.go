package wireless

import (
	"captivating/netfilter"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
)

// AP represents a wireless access point that creates an open WiFi network
// and handles the network configuration for the captive portal
type AP struct {
	SSID                 string             // WiFi network name
	InterfaceName        string             // Wireless interface to use
	Channel              int                // WiFi channel (1-11)
	IP                   string             // IP address for the access point
	wpaSupplicantProcess *exec.Cmd          // Process handle for wpa_supplicant
	dhcpServer           DHCPServer         // DHCP server for IP assignment
	iptablesManager      *netfilter.Manager // Manager for firewall/NAT rules
	stopOnce             sync.Once          // Ensures cleanup only happens once
	temporaryFiles       []string           // List of temp files to clean up on exit
	stopChan             chan struct{}      // Channel to signal DHCP server to stop
}

// NewAP creates a new wireless access point instance with the specified parameters
func NewAP(ssid, interfaceName string, channel int, ipAddress string) *AP {
	return &AP{
		SSID:            ssid,
		InterfaceName:   interfaceName,
		Channel:         channel,
		IP:              ipAddress,
		iptablesManager: netfilter.NewManager(),
		stopChan:        make(chan struct{}),
	}
}

// Start configures and starts the wireless access point
// This includes setting up the interface, WiFi network, DHCP, and network routing
func (ap *AP) Start() error {
	// 1. Find available wireless interfaces if not specified
	if ap.InterfaceName == "" {
		iface, err := FindWirelessInterface()
		if err != nil {
			return fmt.Errorf("no suitable wireless interface found: %w", err)
		}
		ap.InterfaceName = iface
		log.Printf("Using wireless interface: %s", ap.InterfaceName)
	}

	// 2. Configure the wireless interface
	if err := ConfigureInterface(ap.InterfaceName, ap.IP); err != nil {
		return fmt.Errorf("failed to configure interface: %w", err)
	}

	// 3. Setup wpa_supplicant for access point mode
	if err := ap.setupWPASupplicant(); err != nil {
		return fmt.Errorf("failed to setup wpa_supplicant: %w", err)
	}

	// 4. Setup DHCP server to assign IPs to clients
	if err := ap.setupDHCPServer(); err != nil {
		ap.cleanup()
		return fmt.Errorf("failed to setup DHCP server: %w", err)
	}

	// 5. Configure IP forwarding and network routing
	if err := ap.configureNetworking(); err != nil {
		ap.cleanup()
		return fmt.Errorf("failed to configure networking: %w", err)
	}

	log.Printf("Wireless AP '%s' started successfully on interface %s (Channel: %d)",
		ap.SSID, ap.InterfaceName, ap.Channel)

	return nil
}

// Stop gracefully shuts down the wireless access point
// and cleans up all system configurations
func (ap *AP) Stop() {
	ap.stopOnce.Do(func() {
		// Signal to stop the DHCP server
		close(ap.stopChan)
		ap.cleanup()
	})
}

// cleanup terminates all running processes and restores network configuration
func (ap *AP) cleanup() {
	// Stop wpa_supplicant
	if ap.wpaSupplicantProcess != nil && ap.wpaSupplicantProcess.Process != nil {
		log.Println("Stopping wpa_supplicant...")
		ap.wpaSupplicantProcess.Process.Kill()
	}

	// Stop DHCP server
	if ap.dhcpServer != nil {
		log.Println("Stopping DHCP server...")
		ap.dhcpServer.Stop()
	}

	// Remove iptables rules
	if ap.iptablesManager != nil {
		log.Println("Removing iptables rules...")
		ap.iptablesManager.RemoveAllRules()
	}

	// Remove temporary files
	for _, file := range ap.temporaryFiles {
		os.Remove(file)
	}

	// Reset interface to default state
	exec.Command("ip", "link", "set", ap.InterfaceName, "down").Run()
	exec.Command("ip", "addr", "flush", "dev", ap.InterfaceName).Run()

	log.Println("Wireless AP cleanup completed.")
}

// setupWPASupplicant configures and starts the wpa_supplicant with the AP configuration
func (ap *AP) setupWPASupplicant() error {
	configPath := "/tmp/wpa_supplicant.conf"

	config := WPASupplicantConfig{
		SSID:          ap.SSID,
		InterfaceName: ap.InterfaceName,
		Channel:       ap.Channel,
		ConfigPath:    configPath,
	}

	process, err := SetupWPASupplicant(config)
	if err != nil {
		return err
	}

	ap.wpaSupplicantProcess = process
	ap.temporaryFiles = append(ap.temporaryFiles, configPath)

	return nil
}

// setupDHCPServer initializes and starts the DHCP server
func (ap *AP) setupDHCPServer() error {
	config := DHCPServerConfig{
		InterfaceName: ap.InterfaceName,
		ServerIP:      ap.IP,
		StopChan:      ap.stopChan,
	}

	dhcpServer, err := NewDHCPServer(config)
	if err != nil {
		return err
	}

	ap.dhcpServer = dhcpServer

	return ap.dhcpServer.Start()
}

// configureNetworking sets up networking rules for the AP
func (ap *AP) configureNetworking() error {
	config := NetworkConfig{
		InterfaceName: ap.InterfaceName,
		ServerIP:      ap.IP,
	}

	return ConfigureNetworking(config)
}
