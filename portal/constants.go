package portal

// Common URL patterns for captive portal detection
var (
	// URLs that should return 204 No Content
	NoContentURLs = []string{
		"/generate_204",
		"/gen_204",
	}

	// URLs that should return "Success" for Apple devices
	AppleSuccessURLs = []string{
		"/hotspot-detect.html",
		"/library/test/success.html",
	}

	// URL patterns that indicate captive portal detection
	CaptivePortalDetectionPatterns = []string{
		"captive.apple.com",
		"connectivitycheck.gstatic.com",
		"clients3.google.com",
		"/ncsi.txt",
		"/connecttest.txt",
		"/success.txt",
	}
)
