package portal

import (
	"log"
	"net/http"
	"os"
)

// Handler manages HTTP handlers for the captive portal
type Handler struct {
	server          *Server
	auth            *Auth
	templateManager *TemplateManager
}

// NewHandler creates a new Handler instance
func NewHandler(server *Server, auth *Auth, templateManager *TemplateManager) *Handler {
	return &Handler{
		server:          server,
		auth:            auth,
		templateManager: templateManager,
	}
}

// ServeHTTP implements the http.Handler interface
// This is the main entry point for all HTTP(S) requests to the captive portal
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Log the request
	clientIP := getClientIP(r)
	log.Printf("Portal access from %s: %s %s (TLS: %v)", clientIP, r.Method, r.URL.Path, r.TLS != nil)

	// Handle HTTPS requests differently than HTTP
	if r.TLS != nil {
		h.handleHTTPSRequest(w, r, clientIP)
		return
	}

	// Handle HTTP requests
	h.handleHTTPRequest(w, r, clientIP)
}

// handleHTTPSRequest handles all HTTPS requests to the portal
func (h *Handler) handleHTTPSRequest(w http.ResponseWriter, r *http.Request, clientIP string) {
	// For HTTPS, don't try to redirect - just return appropriate responses
	// This helps avoid TLS certificate errors

	// Set cache control headers
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// Check if the client is authorized
	isAuthorized := h.auth.IsClientAuthorized(clientIP)

	if isAuthorized {
		// If authorized, return success for all requests
		if contains(NoContentURLs, r.URL.Path) {
			w.WriteHeader(http.StatusNoContent)
			return
		} else {
			// For all other URLs, return a success page
			h.templateManager.RenderSuccess(w, &SuccessTemplateData{
				ClientIP:   clientIP,
				ExpiryTime: h.auth.GetClientExpiryTime(clientIP).Format("2006-01-02 15:04:05"),
			})
			return
		}
	} else {
		// If not authorized, still succeed for captive portal detection
		// This is important - we never want to show certificate errors
		// Instead, we rely on DNS redirection for HTTP sites
		if contains(NoContentURLs, r.URL.Path) {
			w.WriteHeader(http.StatusNoContent)
			return
		} else {
			// For all other HTTPS requests, return a minimal success page
			// The device's HTTP requests will still be redirected via DNS
			h.templateManager.RenderSuccess(w, &SuccessTemplateData{
				ClientIP:   clientIP,
				ExpiryTime: h.auth.GetClientExpiryTime(clientIP).Format("2006-01-02 15:04:05"),
			})
			return
		}
	}
}

// handleHTTPRequest handles all HTTP requests to the portal
func (h *Handler) handleHTTPRequest(w http.ResponseWriter, r *http.Request, clientIP string) {
	// Handle login request
	if r.URL.Path == "/login" {
		h.auth.HandleLogin(w, r)
		return
	}

	// Check if this is a captive portal detection URL
	isCaptivePortalCheck := false
	if contains(AppleSuccessURLs, r.URL.Path) ||
		containsSubstring(r.URL.Path, CaptivePortalDetectionPatterns...) ||
		contains(NoContentURLs, r.URL.Path) {
		isCaptivePortalCheck = true
	}

	// Handle favicon request
	if r.URL.Path == "/favicon.ico" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Handle portal page
	if r.URL.Path == "/portal" {
		h.portalHandler(w, r)
		return
	}

	// Check if client is already authorized
	isAuthorized := h.auth.IsClientAuthorized(clientIP)

	// Handle HTTP-specific captive portal detection
	if !isAuthorized && isCaptivePortalCheck {
		// Redirect any captive portal detection to the portal
		http.Redirect(w, r, "http://"+r.Host+"/portal", http.StatusFound)
		return
	}

	// Handle root path
	if r.URL.Path == "/" {
		if isAuthorized {
			// Success page for authenticated users
			h.successHandler(w, r, clientIP)
		} else {
			// Redirect to the portal
			http.Redirect(w, r, "/portal", http.StatusFound)
		}
		return
	}

	// Handle auth endpoint
	if r.URL.Path == "/auth" {
		h.auth.HandleAuth(w, r, clientIP)
		return
	}

	// For all other paths, check if client is authorized
	if isAuthorized {
		// If the user is authorized and requests a static file, serve it
		if h.server.StaticDir() != "" {
			filePath := h.server.StaticDir() + r.URL.Path
			if _, err := os.Stat(filePath); err == nil {
				http.ServeFile(w, r, filePath)
				return
			}
		}

		// If the file doesn't exist or staticDir is not set, redirect to root
		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		// If client is not authorized, redirect to the portal page
		http.Redirect(w, r, "/portal", http.StatusFound)
	}
}

// portalHandler shows the captive portal login page
func (h *Handler) portalHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	// If already authorized, redirect to success page
	if h.auth.IsClientAuthorized(clientIP) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Prepare template data
	data := &PortalTemplateData{
		ClientIP: clientIP,
		Error:    r.URL.Query().Get("error") == "1",
	}

	// Render the login template
	h.templateManager.RenderLogin(w, data)
}

// successHandler shows the success page after login
func (h *Handler) successHandler(w http.ResponseWriter, r *http.Request, clientIP string) {
	// Prepare template data
	data := &SuccessTemplateData{
		ClientIP:   clientIP,
		ExpiryTime: h.auth.GetClientExpiryTime(clientIP).Format("2006-01-02 15:04:05"),
	}

	// Render the success template
	h.templateManager.RenderSuccess(w, data)
}
