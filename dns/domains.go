package dns

// GetCaptivePortalDomains returns a list of domains typically used by devices
// to detect the presence of a captive portal
func GetCaptivePortalDomains() []string {
	return []string{
		"captive.apple.com", "www.apple.com", "apple.com",
		"connectivitycheck.gstatic.com", "connectivitycheck.android.com",
		"clients3.google.com", "google.com", "www.google.com",
		"www.msftconnecttest.com", "www.msftncsi.com",
		"detectportal.firefox.com", "success.ubuntu.com",
		"nmcheck.gnome.org", "network-test.debian.org",
	}
}

// GetHttpsOnlyDomains returns a list of domains that should bypass redirection
// because they typically use HTTPS and would fail with certificate errors
func GetHttpsOnlyDomains() []string {
	return []string{
		// Google services
		"google.com", "www.google.com", "accounts.google.com",
		"mail.google.com", "drive.google.com", "docs.google.com",
		"sheets.google.com", "play.google.com",
		"youtube.com", "www.youtube.com",

		// Microsoft services
		"microsoft.com", "www.microsoft.com", "login.microsoft.com",
		"office.com", "www.office.com", "outlook.com", "www.outlook.com",

		// Apple services
		"apple.com", "www.apple.com", "icloud.com", "www.icloud.com",

		// Social media
		"facebook.com", "www.facebook.com", "twitter.com", "www.twitter.com",
		"instagram.com", "www.instagram.com", "linkedin.com", "www.linkedin.com",

		// Secure services
		"github.com", "www.github.com", "banking.example.com",
		"paypal.com", "www.paypal.com",

		// CDNs
		"cloudfront.net", "akamaiedge.net", "googleapis.com", "gstatic.com",
	}
}
