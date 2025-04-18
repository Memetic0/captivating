package netfilter

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// Rule represents an iptables rule with its components
type Rule struct {
	Table         string            // Table name: nat, filter, mangle, etc.
	Chain         string            // Chain name: PREROUTING, POSTROUTING, etc.
	Protocol      string            // Protocol: tcp, udp, etc. (optional)
	Source        string            // Source IP/network (optional)
	Destination   string            // Destination IP/network (optional)
	InInterface   string            // Input interface (optional)
	OutInterface  string            // Output interface (optional)
	SourcePort    int               // Source port (optional)
	DestPort      int               // Destination port (optional)
	Target        string            // Target action: ACCEPT, DROP, REJECT, DNAT, SNAT, etc.
	TargetOptions map[string]string // Options for target (e.g. --to-destination for DNAT)
}

// Manager is responsible for managing iptables rules safely
type Manager struct {
	rules      []Rule     // List of rules added by this manager
	rulesMutex sync.Mutex // Mutex to protect concurrent rule additions/removals
}

// NewManager creates a new iptables manager
func NewManager() *Manager {
	return &Manager{
		rules: make([]Rule, 0),
	}
}

// AddRule adds a rule to iptables and stores it for later removal
func (m *Manager) AddRule(rule Rule) error {
	// Build the iptables command arguments
	args := []string{"-t", rule.Table, "-A", rule.Chain}

	// Add each specified rule component
	if rule.Protocol != "" {
		args = append(args, "-p", rule.Protocol)
	}

	if rule.Source != "" {
		args = append(args, "-s", rule.Source)
	}

	if rule.Destination != "" {
		args = append(args, "-d", rule.Destination)
	}

	if rule.InInterface != "" {
		args = append(args, "-i", rule.InInterface)
	}

	if rule.OutInterface != "" {
		args = append(args, "-o", rule.OutInterface)
	}

	if rule.SourcePort > 0 {
		args = append(args, "--sport", fmt.Sprintf("%d", rule.SourcePort))
	}

	if rule.DestPort > 0 {
		args = append(args, "--dport", fmt.Sprintf("%d", rule.DestPort))
	}

	// Add the target action (e.g., ACCEPT, DNAT, etc.)
	args = append(args, "-j", rule.Target)

	// Add target options (e.g., --to-destination for DNAT)
	for k, v := range rule.TargetOptions {
		// Handle option format (with or without leading --)
		optKey := k
		if !strings.HasPrefix(k, "--") {
			optKey = "--" + k
		}

		if v != "" {
			args = append(args, optKey, v)
		} else {
			args = append(args, optKey)
		}
	}

	// Execute iptables command
	cmd := exec.Command("iptables", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add iptables rule: %v, output: %s", err, string(output))
	}

	// Store the rule for later removal
	m.rulesMutex.Lock()
	m.rules = append(m.rules, rule)
	m.rulesMutex.Unlock()

	return nil
}

// RemoveRule removes a specific rule from iptables
func (m *Manager) RemoveRule(rule Rule) error {
	// Build the iptables command arguments (same as AddRule but with -D instead of -A)
	args := []string{"-t", rule.Table, "-D", rule.Chain}

	if rule.Protocol != "" {
		args = append(args, "-p", rule.Protocol)
	}

	if rule.Source != "" {
		args = append(args, "-s", rule.Source)
	}

	if rule.Destination != "" {
		args = append(args, "-d", rule.Destination)
	}

	if rule.InInterface != "" {
		args = append(args, "-i", rule.InInterface)
	}

	if rule.OutInterface != "" {
		args = append(args, "-o", rule.OutInterface)
	}

	if rule.SourcePort > 0 {
		args = append(args, "--sport", fmt.Sprintf("%d", rule.SourcePort))
	}

	if rule.DestPort > 0 {
		args = append(args, "--dport", fmt.Sprintf("%d", rule.DestPort))
	}

	args = append(args, "-j", rule.Target)

	// Add target options
	for k, v := range rule.TargetOptions {
		optKey := k
		if !strings.HasPrefix(k, "--") {
			optKey = "--" + k
		}

		if v != "" {
			args = append(args, optKey, v)
		} else {
			args = append(args, optKey)
		}
	}

	// Execute iptables command
	cmd := exec.Command("iptables", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove iptables rule: %v, output: %s", err, string(output))
	}

	return nil
}

// RemoveAllRules removes all rules added by this manager
// This is typically called during cleanup/shutdown
func (m *Manager) RemoveAllRules() {
	m.rulesMutex.Lock()
	defer m.rulesMutex.Unlock()

	for _, rule := range m.rules {
		// Ignore errors, we want to try to remove all rules
		_ = m.RemoveRule(rule)
	}

	// Clear the rules list
	m.rules = make([]Rule, 0)
}

// SetupNAT sets up Network Address Translation for the given interface
// This allows clients to access the internet through the host
func (m *Manager) SetupNAT(outInterface string) error {
	rule := Rule{
		Table:        "nat",
		Chain:        "POSTROUTING",
		OutInterface: outInterface,
		Target:       "MASQUERADE",
	}

	return m.AddRule(rule)
}

// RedirectToHost redirects traffic on a specific port to the host
// Useful for redirecting standard ports (80, 443) to the captive portal
func (m *Manager) RedirectToHost(inInterface string, proto string, port int, hostIP string, hostPort int) error {
	rule := Rule{
		Table:       "nat",
		Chain:       "PREROUTING",
		InInterface: inInterface,
		Protocol:    proto,
		DestPort:    port,
		Target:      "DNAT",
		TargetOptions: map[string]string{
			"to-destination": fmt.Sprintf("%s:%d", hostIP, hostPort),
		},
	}

	return m.AddRule(rule)
}

// SetIPForwarding enables or disables IP forwarding in the kernel
// This is necessary for NAT to work
func SetIPForwarding(enable bool) error {
	val := "0"
	if enable {
		val = "1"
	}

	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(val), 0644)
}
