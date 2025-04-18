package main

import (
	"bufio"
	"captivating/dns"
	"captivating/portal"
	"captivating/utils"
	"captivating/wireless"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// askToStopProcess prompts the user if they want to stop a conflicting process
// Returns true if the user chose to stop the process
func askToStopProcess(processName string, pid int, port int) bool {
	fmt.Printf("Port %d is already in use by %s (PID %d). Do you want to stop it? [y/N]: ",
		port, processName, pid)
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

// stopProcess attempts to stop a process by sending a SIGTERM signal
func stopProcess(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(syscall.SIGTERM)
}

// checkPortsAndPrompt checks if required ports are available and prompts to stop conflicting processes
// Returns an error if any required port cannot be used
func checkPortsAndPrompt(ports ...int) error {
	for _, port := range ports {
		inUse, processName, pid, err := utils.IsPortInUse(port)
		if err != nil {
			log.Printf("Warning: Could not check if port %d is in use: %v", port, err)
			continue
		}

		if inUse {
			if pid == 0 {
				return fmt.Errorf("port %d is already in use by an unknown process", port)
			}

			if askToStopProcess(processName, pid, port) {
				log.Printf("Stopping process %s (PID %d)...", processName, pid)
				if err := stopProcess(pid); err != nil {
					return fmt.Errorf("failed to stop process %s (PID %d): %v", processName, pid, err)
				}
				// Give the process a moment to stop
				log.Printf("Waiting for port %d to be released...", port)
				time.Sleep(2 * time.Second)
			} else {
				return fmt.Errorf("port %d is required but already in use by %s (PID %d)",
					port, processName, pid)
			}
		}
	}
	return nil
}

func main() {
	// Define command line flags with descriptions
	ssid := flag.String("ssid", "CaptivePortal", "SSID of the wireless network")
	wifiInterface := flag.String("interface", "", "Name of the wireless interface to use (auto-detect if empty)")
	channel := flag.Int("channel", 6, "WiFi channel (1-11)")
	portalIP := flag.String("ip", "192.168.1.1", "IP address for the captive portal")
	dnsPort := flag.Int("dns-port", 53, "Port for the DNS server")
	httpPort := flag.Int("http-port", 80, "Port for the HTTP server")
	httpsPort := flag.Int("https-port", 443, "Port for the HTTPS server")
	redirectURL := flag.String("redirect", "/portal", "URL to redirect users to")

	flag.Parse()

	// Check for root permissions (required to create WiFi access point and bind to privileged ports)
	if os.Geteuid() != 0 {
		log.Fatalf("This program must be run as root to create an access point (sudo)")
	}

	// Check if required ports are available
	log.Println("Checking if required ports are available...")
	if err := checkPortsAndPrompt(*dnsPort, *httpPort, *httpsPort); err != nil {
		log.Fatalf("Port conflict: %v", err)
	}

	// Start the services in the correct order
	startServices(*ssid, *wifiInterface, *channel, *portalIP, *dnsPort, *httpPort, *httpsPort, *redirectURL)

	// Setup signal handling for graceful shutdown
	waitForShutdown()
}

// startServices starts the wireless AP, DNS server, and portal server
func startServices(ssid, wifiInterface string, channel int, portalIP string,
	dnsPort, httpPort, httpsPort int, redirectURL string) {
	// Start wireless AP
	log.Println("Starting wireless access point...")
	wirelessAP := wireless.NewAP(ssid, wifiInterface, channel, portalIP)
	go func() {
		if err := wirelessAP.Start(); err != nil {
			log.Printf("Failed to start wireless AP: %v", err)
			log.Println("Continuing without wireless AP - you can still access the portal via other means")
		}
	}()

	// Start DNS server for captive portal redirection
	dnsServer := dns.NewServer(dnsPort, portalIP)
	go func() {
		log.Printf("Starting DNS server on port %d", dnsPort)
		if err := dnsServer.Start(); err != nil {
			// Try fallback port if standard port 53 fails (common on many systems)
			if strings.Contains(err.Error(), "address already in use") {
				fallbackPort := 5453
				log.Printf("Port %d is in use, falling back to port %d", dnsPort, fallbackPort)
				dnsServer = dns.NewServer(fallbackPort, portalIP)

				// Add iptables rule to redirect port 53 to our fallback port
				log.Printf("Adding iptables rule to redirect DNS traffic from port 53 to %d", fallbackPort)
				redirectCmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp",
					"--dport", "53", "-j", "REDIRECT", "--to-port", strconv.Itoa(fallbackPort))
				if err := redirectCmd.Run(); err != nil {
					log.Printf("Warning: Failed to set up port redirection: %v", err)
				}

				// Start DNS server on fallback port
				if err := dnsServer.Start(); err != nil {
					log.Fatalf("Failed to start DNS server on fallback port: %v", err)
				}
			} else {
				log.Fatalf("Failed to start DNS server: %v", err)
			}
		}
	}()

	// Start HTTP/HTTPS portal server
	portalServer := portal.NewServer(httpPort, httpsPort, redirectURL)
	go func() {
		log.Printf("Starting captive portal on ports %d (HTTP) and %d (HTTPS)", httpPort, httpsPort)
		if err := portalServer.Start(); err != nil {
			log.Fatalf("Failed to start portal server: %v", err)
		}
	}()

	log.Printf("Captive portal is running at http://%s", portalIP)
	log.Println("Connect to the WiFi network and browse to any website to access the portal")
	log.Println("Press Ctrl+C to stop")
}

// waitForShutdown waits for SIGINT or SIGTERM signals to gracefully shutdown
func waitForShutdown() {
	// Handle graceful shutdown on Ctrl+C or kill
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	fmt.Printf("\nReceived signal %s. Shutting down servers...\n", sig)
	fmt.Println("Shutdown complete")
}
