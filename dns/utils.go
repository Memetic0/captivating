package dns

import (
	"fmt"
	"strings"
)

// isDomainInList checks if a domain is in a list of domains (with suffix matching)
func isDomainInList(domain string, domainList []string) bool {
	for _, listedDomain := range domainList {
		if domain == listedDomain || strings.HasSuffix(domain, "."+listedDomain) {
			return true
		}
	}
	return false
}

// decodeDomain decodes a domain name from a DNS message using the DNS compression scheme
func decodeDomain(msg []byte, offset int) (string, int, error) {
	if offset >= len(msg) {
		return "", offset, fmt.Errorf("offset out of bounds")
	}

	var parts []string

	for {
		if offset >= len(msg) {
			return "", offset, fmt.Errorf("offset out of bounds during domain parsing")
		}

		length := int(msg[offset])
		offset++

		// Check for compression pointer (first two bits are '11')
		if length&0xC0 == 0xC0 {
			if offset >= len(msg) {
				return "", offset, fmt.Errorf("compression pointer incomplete")
			}

			// Calculate pointer offset (14 bits)
			pointerOffset := ((int(length) & 0x3F) << 8) | int(msg[offset])
			offset++

			// Recursively decode the referenced domain
			suffix, _, err := decodeDomain(msg, pointerOffset)
			if err != nil {
				return "", offset, err
			}

			if len(parts) > 0 {
				return strings.Join(parts, ".") + "." + suffix, offset, nil
			}
			return suffix, offset, nil
		}

		// End of domain name
		if length == 0 {
			break
		}

		// Regular label
		if offset+length > len(msg) {
			return "", offset, fmt.Errorf("domain name label exceeds message bounds")
		}

		part := string(msg[offset : offset+length])
		parts = append(parts, part)
		offset += length
	}

	return strings.Join(parts, "."), offset, nil
}
