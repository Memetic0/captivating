package portal

import (
	"log"
	"net/http"
	"sync"
	"time"
)

// Auth handles user authentication logic for the portal
type Auth struct {
	authLock          sync.RWMutex        // Lock for the authorizedClients map
	authorizedClients map[string]struct { // Map of authorized clients by IP
		expiry time.Time // When the authorization expires
	}
}

// NewAuth creates a new Auth instance
func NewAuth() *Auth {
	return &Auth{
		authorizedClients: make(map[string]struct{ expiry time.Time }),
	}
}

// HandleLogin processes login attempts
func (a *Auth) HandleLogin(w http.ResponseWriter, r *http.Request) {
	// Only handle POST requests
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/portal", http.StatusFound)
		return
	}

	// Parse form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	clientIP := getClientIP(r)
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	log.Printf("Login attempt from %s with username: %s", clientIP, username)

	// For this demo, accept any non-empty username and password
	if username != "" && password != "" {
		// Authorize the client
		a.AuthorizeClient(clientIP)

		// For AJAX requests, return JSON
		if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"message":"Login successful"}`))
		} else {
			// For regular form submissions, redirect to success page
			log.Printf("Client %s successfully authenticated, redirecting to /", clientIP)
			http.Redirect(w, r, "/", http.StatusFound)
		}
		return
	}

	// Invalid credentials
	log.Printf("Failed authentication attempt from %s - Empty username or password", clientIP)

	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"success":false,"message":"Invalid credentials"}`))
	} else {
		// Show error for regular form submissions by redirecting to portal with error
		http.Redirect(w, r, "/portal?error=1", http.StatusFound)
	}
}

// HandleAuth processes authentication requests
func (a *Auth) HandleAuth(w http.ResponseWriter, r *http.Request, clientIP string) {
	// Parse form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	// Get username and password from form
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	log.Printf("Auth request from %s with username: %s", clientIP, username)

	// Validate credentials (simplified for demonstration)
	if username != "" && password != "" {
		// Add to authorized clients
		a.AuthorizeClient(clientIP)

		// Redirect to success page
		log.Printf("Client %s successfully authenticated through /auth", clientIP)
		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		// Show error and back to login form
		log.Printf("Failed authentication attempt from %s - Empty username or password", clientIP)
		http.Redirect(w, r, "/portal?error=1", http.StatusFound)
	}
}

// AuthorizeClient adds a client to the authorized list with an expiry time
func (a *Auth) AuthorizeClient(clientIP string) {
	a.authLock.Lock()
	defer a.authLock.Unlock()

	// Add the client with an expiry time (24 hours)
	a.authorizedClients[clientIP] = struct{ expiry time.Time }{
		expiry: time.Now().Add(24 * time.Hour),
	}
}

// IsClientAuthorized checks if a client IP is authorized and not expired
func (a *Auth) IsClientAuthorized(clientIP string) bool {
	a.authLock.RLock()
	defer a.authLock.RUnlock()

	auth, exists := a.authorizedClients[clientIP]
	if !exists {
		return false
	}

	// Check if auth has expired
	return time.Now().Before(auth.expiry)
}

// GetClientExpiryTime returns the expiry time for a client
func (a *Auth) GetClientExpiryTime(clientIP string) time.Time {
	a.authLock.RLock()
	defer a.authLock.RUnlock()

	auth, exists := a.authorizedClients[clientIP]
	if !exists {
		return time.Time{}
	}

	return auth.expiry
}
