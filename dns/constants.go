package dns

// DNS packet constants
const (
	// DNS header offsets
	headerIDOffset      = 0
	headerFlagsOffset   = 2
	headerQDCountOffset = 4
	headerANCountOffset = 6
	headerNSCountOffset = 8
	headerARCountOffset = 10
	headerSize          = 12

	// DNS flags
	flagQR    = 0x8000 // Query Response flag - indicates if packet is a query (0) or response (1)
	flagAA    = 0x0400 // Authoritative Answer - server is authoritative for the domain
	flagTC    = 0x0200 // Truncated Response - message was truncated
	flagRD    = 0x0100 // Recursion Desired - client wants recursive resolution
	flagRA    = 0x0080 // Recursion Available - server supports recursive resolution
	flagZ     = 0x0040 // Reserved
	flagAD    = 0x0020 // Authentic Data - DNSSEC related
	flagCD    = 0x0010 // Checking Disabled - DNSSEC related
	flagRCODE = 0x000F // Response Code - indicates status of response

	// DNS record types
	typeA     = 1  // IPv4 address record
	typeNS    = 2  // Name server record
	typeCNAME = 5  // Canonical name record
	typeSOA   = 6  // Start of authority record
	typePTR   = 12 // Pointer record
	typeMX    = 15 // Mail exchange record
	typeTXT   = 16 // Text record
	typeAAAA  = 28 // IPv6 address record

	// DNS classes
	classIN = 1 // Internet class
)
