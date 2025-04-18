package wireless

import (
	"bufio"
	"captivating/utils"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"
)

// WPASupplicantConfig contains the configuration for the wpa_supplicant
type WPASupplicantConfig struct {
	SSID           string
	InterfaceName  string
	Channel        int
	ConfigPath     string
	TemporaryFiles []string
}

// SetupWPASupplicant configures and starts the wpa_supplicant daemon
// in access point mode to create the wireless network
func SetupWPASupplicant(config WPASupplicantConfig) (*exec.Cmd, error) {
	// Check if wpa_supplicant is installed
	_, err := exec.LookPath("wpa_supplicant")
	if err != nil {
		return nil, fmt.Errorf("wpa_supplicant is not installed: %w", err)
	}

	// Check if wpa_supplicant port is available
	inUse, processName, pid, err := utils.IsPortInUse(6667) // control port
	if err == nil && inUse {
		return nil, fmt.Errorf("wpa_supplicant port is already in use by %s (PID %d)", processName, pid)
	}

	// Create wpa_supplicant config file with AP settings
	configPath := "/tmp/wpa_supplicant.conf"
	if config.ConfigPath != "" {
		configPath = config.ConfigPath
	}

	configContent := fmt.Sprintf(`
# wpa_supplicant configuration for captivating portal

# AP mode configuration
ctrl_interface=/var/run/wpa_supplicant
ap_scan=2
country=GB

# Network configuration
network={
    ssid="%s"
    mode=2
    frequency=%d
    key_mgmt=NONE
    auth_alg=OPEN
}
`,
		config.SSID, 2412+(config.Channel-1)*5) // Convert channel to frequency (2.4GHz band)

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write wpa_supplicant config: %w", err)
	}

	// Start wpa_supplicant with the nl80211 driver
	wpaSupplicantProcess := exec.Command("wpa_supplicant", "-i", config.InterfaceName, "-c", configPath, "-D", "nl80211")

	// Redirect output to logs
	stdout, err := wpaSupplicantProcess.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get wpa_supplicant stdout: %w", err)
	}

	if err := wpaSupplicantProcess.Start(); err != nil {
		return nil, fmt.Errorf("failed to start wpa_supplicant: %w", err)
	}

	// Read and log wpa_supplicant output
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			log.Printf("[wpa_supplicant] %s", scanner.Text())
		}
	}()

	// Wait for wpa_supplicant to initialize
	time.Sleep(2 * time.Second)

	return wpaSupplicantProcess, nil
}
