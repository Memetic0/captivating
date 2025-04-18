package portal

import (
	"crypto/tls"
	"embed"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

//go:embed templates
var templateFS embed.FS

// Server represents the captive portal web server that handles both HTTP and HTTPS
type Server struct {
	httpPort    int          // Port for HTTP server
	httpsPort   int          // Port for HTTPS server
	redirectURL string       // URL to redirect users to (usually "/portal")
	httpServer  *http.Server // HTTP server instance
	httpsServer *http.Server // HTTPS server instance
	certPEM     []byte       // Certificate in PEM format
	keyPEM      []byte       // Private key in PEM format
	stopOnce    sync.Once    // Ensures Stop() only executes once
	staticDir   string       // Directory for static files (if any)
	handler     http.Handler // HTTP handler for both servers
}

// NewServer creates a new captive portal web server
func NewServer(httpPort, httpsPort int, redirectURL string) *Server {
	// Initialize components
	auth := NewAuth()
	templateManager := NewTemplateManager(templateFS)

	server := &Server{
		httpPort:    httpPort,
		httpsPort:   httpsPort,
		redirectURL: redirectURL,
	}

	// Create and set the HTTP handler
	handler := NewHandler(server, auth, templateManager)
	server.handler = handler

	return server
}

// Start initializes and starts both HTTP and HTTPS servers
func (s *Server) Start() error {
	// Generate a self-signed certificate for HTTPS
	var err error
	s.certPEM, s.keyPEM, err = GenerateSelfSignedCertPEM()
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Start HTTP server in a goroutine
	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.httpPort),
		Handler: s.handler,
	}

	go func() {
		log.Printf("Starting HTTP server on port %d", s.httpPort)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Start HTTPS server with self-signed cert in a goroutine
	cert, err := tls.X509KeyPair(s.certPEM, s.keyPEM)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	s.httpsServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.httpsPort),
		Handler: s.handler,
		// Increase timeouts to handle slower clients
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			// Accept older TLS versions for compatibility with all clients
			MinVersion: tls.VersionTLS10,
			// Use the certificate regardless of the hostname requested
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				log.Printf("TLS ClientHello SNI: %s", info.ServerName)
				return &cert, nil
			},
		},
	}

	go func() {
		log.Printf("Starting HTTPS server on port %d", s.httpsPort)
		if err := s.httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTPS server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down both HTTP and HTTPS servers
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		if s.httpServer != nil {
			s.httpServer.Close()
		}
		if s.httpsServer != nil {
			s.httpsServer.Close()
		}
	})
}

// SetStaticDir sets the directory for static files
func (s *Server) SetStaticDir(dir string) {
	s.staticDir = dir
}

// StaticDir returns the directory for static files
func (s *Server) StaticDir() string {
	return s.staticDir
}
