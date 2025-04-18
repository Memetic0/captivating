package wireless

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// FindWirelessInterface automatically detects an available wireless interface
// that can be used for the access point
func FindWirelessInterface() (string, error) {
	// Look for wireless interfaces in /sys/class/net
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		ifname := entry.Name()
		// Skip loopback interface
		if ifname == "lo" {
			continue
		}

		// Check if it's a wireless interface by looking for the wireless directory
		_, err := os.Stat(filepath.Join("/sys/class/net", ifname, "wireless"))
		if err == nil {
			// Check if the interface is not already in use (UP state)
			ipInfo, err := exec.Command("ip", "addr", "show", ifname).Output()
			if err != nil {
				continue
			}
			if !strings.Contains(string(ipInfo), "UP") {
				return ifname, nil
			}
		}
	}

	return "", fmt.Errorf("no available wireless interface found")
}

// ConfigureInterface sets up the wireless interface with the proper IP address
func ConfigureInterface(interfaceName, ipAddress string) error {
	// Bring interface down first to make changes
	cmd := exec.Command("ip", "link", "set", interfaceName, "down")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface down: %w", err)
	}

	// Remove any existing IP addresses
	cmd = exec.Command("ip", "addr", "flush", "dev", interfaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to flush interface IP: %w", err)
	}

	// Set the interface IP address with /24 subnet mask
	cmd = exec.Command("ip", "addr", "add", ipAddress+"/24", "dev", interfaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set interface IP: %w", err)
	}

	// Bring interface up to activate settings
	cmd = exec.Command("ip", "link", "set", interfaceName, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	return nil
}

// GetMainInterface determines the interface with the default route
// (the one that provides internet connectivity)
func GetMainInterface() (string, error) {
	// Get the default route information
	output, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get default route: %w", err)
	}

	// Parse the output to extract the interface name
	// Example: "default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.2 metric 303"
	outputStr := string(output)
	fields := strings.Fields(outputStr)

	// Find the interface (after "dev")
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", fmt.Errorf("could not find main interface in route output")
}
