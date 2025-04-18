package portal

import (
	"embed"
	"html/template"
	"log"
	"net/http"
)

// Template data structures
type PortalTemplateData struct {
	ClientIP string
	Error    bool
}

type SuccessTemplateData struct {
	ClientIP   string
	ExpiryTime string
}

// TemplateManager handles template parsing and rendering
type TemplateManager struct {
	templates *template.Template
}

// NewTemplateManager creates a new TemplateManager with the given template filesystem
func NewTemplateManager(templateFS embed.FS) *TemplateManager {
	templates := template.Must(template.ParseFS(templateFS, "templates/*.html"))
	return &TemplateManager{
		templates: templates,
	}
}

// RenderLogin renders the login template
func (tm *TemplateManager) RenderLogin(w http.ResponseWriter, data *PortalTemplateData) {
	w.Header().Set("Content-Type", "text/html")
	err := tm.templates.ExecuteTemplate(w, "login.html", data)
	if err != nil {
		log.Printf("Error rendering login template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// RenderSuccess renders the success template
func (tm *TemplateManager) RenderSuccess(w http.ResponseWriter, data *SuccessTemplateData) {
	w.Header().Set("Content-Type", "text/html")
	err := tm.templates.ExecuteTemplate(w, "success.html", data)
	if err != nil {
		log.Printf("Error rendering success template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
