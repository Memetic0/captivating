package dns

import (
	"encoding/binary"
	"log"
)

// handleDNSRequest processes a DNS request and returns a response
// For most domains, it redirects A record queries to the captive portal IP
func (s *Server) handleDNSRequest(request []byte) []byte {
	// Validate packet size
	if len(request) < headerSize {
		log.Printf("DNS: Request too short (%d bytes), minimum is %d bytes", len(request), headerSize)
		return nil
	}

	// Extract header fields
	id := binary.BigEndian.Uint16(request[headerIDOffset : headerIDOffset+2])
	flags := binary.BigEndian.Uint16(request[headerFlagsOffset : headerFlagsOffset+2])
	qdCount := binary.BigEndian.Uint16(request[headerQDCountOffset : headerQDCountOffset+2])

	log.Printf("DNS: Request ID: 0x%04x, Flags: 0x%04x, Questions: %d", id, flags, qdCount)

	// Only handle standard queries
	if (flags&flagQR) != 0 || qdCount == 0 {
		log.Printf("DNS: Ignoring non-query or zero-question request")
		return nil
	}

	// Create response buffer (copying request headers)
	response := make([]byte, 512)
	copy(response, request)

	// Set response flags: QR (response), AA (authoritative), and preserve RD
	respFlags := flagQR | flagAA | (flags & flagRD)
	binary.BigEndian.PutUint16(response[headerFlagsOffset:headerFlagsOffset+2], respFlags)

	// Parse the questions
	offset := headerSize
	var domain string
	var qType, qClass uint16

	// Read the domain name and query type from the question
	domain, offset, err := decodeDomain(request, offset)
	if err != nil {
		log.Printf("DNS: Error decoding domain: %v", err)
		return nil
	}

	// Read question type and class
	if offset+4 > len(request) {
		log.Printf("DNS: Request truncated, can't read type and class")
		return nil
	}
	qType = binary.BigEndian.Uint16(request[offset : offset+2])
	qClass = binary.BigEndian.Uint16(request[offset+2 : offset+4])
	offset += 4

	log.Printf("DNS: Query for domain=%s, type=%d, class=%d", domain, qType, qClass)

	// Get the domain lists
	captivePortalDomains := GetCaptivePortalDomains()
	httpsOnlyDomains := GetHttpsOnlyDomains()

	// Check if this is a captive portal detection domain
	isCaptivePortalDetection := isDomainInList(domain, captivePortalDomains)
	isHttpsDomain := isDomainInList(domain, httpsOnlyDomains)

	// Handle A record requests (IPv4 addresses)
	if qType == typeA && qClass == classIN {
		// For HTTPS domains, don't redirect (let client use default DNS)
		if isHttpsDomain {
			binary.BigEndian.PutUint16(response[headerANCountOffset:headerANCountOffset+2], 0)
			binary.BigEndian.PutUint16(response[headerNSCountOffset:headerNSCountOffset+2], 0)
			binary.BigEndian.PutUint16(response[headerARCountOffset:headerARCountOffset+2], 0)
			log.Printf("DNS: Not redirecting HTTPS domain %s", domain)
		} else {
			// Redirect all other domains to our portal
			log.Printf("DNS: Redirecting domain %s to portal %s", domain, s.portalIP.String())

			// Set the number of answers to 1
			binary.BigEndian.PutUint16(response[headerANCountOffset:headerANCountOffset+2], 1)

			// Add answer section with portal IP
			response[offset] = 0xC0   // Pointer to domain name
			response[offset+1] = 0x0C // Pointer offset (to the domain in question section)
			offset += 2

			// Type A
			binary.BigEndian.PutUint16(response[offset:offset+2], typeA)
			// Class IN
			binary.BigEndian.PutUint16(response[offset+2:offset+4], classIN)
			offset += 4

			// TTL (time to live in seconds)
			ttl := uint32(60) // Regular domains
			if isCaptivePortalDetection {
				ttl = 1 // Very short TTL for captive portal domains to avoid caching
			}
			binary.BigEndian.PutUint32(response[offset:offset+4], ttl)

			// Data length (4 bytes for IPv4)
			binary.BigEndian.PutUint16(response[offset+4:offset+6], 4)
			offset += 6

			// Copy the IP address (portal IP)
			copy(response[offset:offset+4], s.portalIP.To4())
			offset += 4

			// Zero out authority and additional records
			binary.BigEndian.PutUint16(response[headerNSCountOffset:headerNSCountOffset+2], 0)
			binary.BigEndian.PutUint16(response[headerARCountOffset:headerARCountOffset+2], 0)
		}
	} else if qType == typeAAAA && qClass == classIN {
		// For IPv6 queries, return empty result to force IPv4
		binary.BigEndian.PutUint16(response[headerANCountOffset:headerANCountOffset+2], 0)
		binary.BigEndian.PutUint16(response[headerNSCountOffset:headerNSCountOffset+2], 0)
		binary.BigEndian.PutUint16(response[headerARCountOffset:headerARCountOffset+2], 0)
	} else {
		// For other query types, return empty result
		binary.BigEndian.PutUint16(response[headerANCountOffset:headerANCountOffset+2], 0)
		binary.BigEndian.PutUint16(response[headerNSCountOffset:headerNSCountOffset+2], 0)
		binary.BigEndian.PutUint16(response[headerARCountOffset:headerARCountOffset+2], 0)
	}

	return response[:offset]
}
