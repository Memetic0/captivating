package portal

import (
	"net"
	"net/http"
	"strings"
)

// getClientIP extracts the client IP address from a request
func getClientIP(r *http.Request) string {
	// Try X-Forwarded-For header first (for proxied requests)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Use the first IP in the list
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // Return as is if no port
	}
	return ip
}

// contains checks if a string slice contains a specific value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

// containsSubstring checks if a string contains any of the substrings
func containsSubstring(s string, substrings ...string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
