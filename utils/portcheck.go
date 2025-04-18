package utils

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// PortInfo contains information about a port in use
type PortInfo struct {
	Port        int
	ProcessName string
	PID         int
}

// IsPortInUse checks if a TCP or UDP port is in use
// Returns whether the port is in use, and if so, the process name and PID using it
func IsPortInUse(port int) (bool, string, int, error) {
	// First check TCP port
	tcpAddr := net.TCPAddr{Port: port}
	tcpConn, tcpErr := net.ListenTCP("tcp", &tcpAddr)

	// If we can listen, the port is free
	if tcpErr == nil {
		tcpConn.Close()

		// Also check UDP, as some services might only use UDP
		udpAddr := net.UDPAddr{Port: port}
		udpConn, udpErr := net.ListenUDP("udp", &udpAddr)

		if udpErr == nil {
			udpConn.Close()
			return false, "", 0, nil
		}
	}

	// Port is in use, try to find the process using it
	return findProcessForPort(port)
}

// findProcessForPort tries to determine which process is using a port
// This is OS-specific, but works on Linux
func findProcessForPort(port int) (bool, string, int, error) {
	// For Linux, we can look at /proc/net/tcp and /proc/net/udp
	processes, err := findProcessesFromProcNet(port)
	if err != nil {
		return true, "unknown", 0, err
	}

	if len(processes) > 0 {
		// Return the first process found
		return true, processes[0].ProcessName, processes[0].PID, nil
	}

	// Port is in use but we couldn't determine the process
	return true, "unknown", 0, nil
}

// findProcessesFromProcNet searches through /proc/net/tcp and /proc/net/udp
// to find processes using the specified port
func findProcessesFromProcNet(port int) ([]PortInfo, error) {
	var results []PortInfo

	// Check both TCP and UDP
	for _, protocol := range []string{"tcp", "udp", "tcp6", "udp6"} {
		filename := fmt.Sprintf("/proc/net/%s", protocol)

		data, err := os.ReadFile(filename)
		if err != nil {
			continue
		}

		lines := strings.Split(string(data), "\n")

		// First line is a header
		for _, line := range lines[1:] {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}

			// Local address is in the format: 0100007F:1234 (hex IP:port)
			localAddr := fields[1]
			parts := strings.Split(localAddr, ":")
			if len(parts) != 2 {
				continue
			}

			// Convert hex port to decimal
			hexPort := parts[1]
			portNum, err := strconv.ParseInt(hexPort, 16, 32)
			if err != nil {
				continue
			}

			// Check if this is the port we're looking for
			if int(portNum) == port {
				// Inode is in field 9
				inode := fields[9]

				// Now find the process that has this inode open
				pid, name, err := findProcessByInode(inode)
				if err != nil || pid == 0 {
					continue
				}

				results = append(results, PortInfo{
					Port:        port,
					ProcessName: name,
					PID:         pid,
				})
			}
		}
	}

	return results, nil
}

// findProcessByInode scans /proc to find which process has the given inode open
func findProcessByInode(inode string) (int, string, error) {
	// Scan all processes in /proc
	procDirs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, "", err
	}

	for _, dir := range procDirs {
		// Check if the directory name is a number (PID)
		pid, err := strconv.Atoi(dir.Name())
		if err != nil {
			continue
		}

		// Check the file descriptors for this process
		fdPath := filepath.Join("/proc", dir.Name(), "fd")
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			// Read the symlink target (should point to socket:[inode])
			link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
			if err != nil {
				continue
			}

			// Check if this is a socket with the inode we're looking for
			if strings.Contains(link, "socket:["+inode+"]") {
				// Found the process, now get its name
				cmdlinePath := filepath.Join("/proc", dir.Name(), "cmdline")
				cmdline, err := os.ReadFile(cmdlinePath)
				if err != nil {
					return pid, "unknown", nil
				}

				// Extract the process name (first part of cmdline)
				cmdStr := string(cmdline)
				cmdParts := strings.Split(cmdStr, "\x00")

				// Get the executable name from the path
				name := filepath.Base(cmdParts[0])
				if name == "" {
					name = "unknown"
				}

				return pid, name, nil
			}
		}
	}

	return 0, "", nil
}
