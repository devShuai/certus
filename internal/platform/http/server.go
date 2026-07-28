package httpserver

import (
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/oauth"
	"certus/web"
)

type server struct {
	cfg       config.Config
	logger    *slog.Logger
	templates *template.Template
	clients   client.Repository
}

func New(cfg config.Config, logger *slog.Logger) http.Handler {
	clients := client.NewMemoryRepository(client.Client{
		ID:           "specus",
		Name:         "Specus",
		Description:  "示例接入系统",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		LoginMethods: []client.LoginMethod{client.LoginPassword, client.LoginLDAP},
		Enabled:      true,
	})
	return NewWithClients(cfg, logger, clients)
}

func NewWithClients(cfg config.Config, logger *slog.Logger, clients client.Repository) http.Handler {
	templates := template.Must(template.ParseFS(web.Files, "templates/*.html"))
	s := &server{cfg: cfg, logger: logger, templates: templates, clients: clients}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.health)
	mux.HandleFunc("GET /", s.home)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("GET /portal", s.portal)
	mux.HandleFunc("GET /api/v1/clients", s.listClients)
	mux.HandleFunc("GET /api/v1/clients/{clientID}", s.getClient)
	mux.HandleFunc("GET /oauth2/authorize", s.authorize)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)

	assets, err := fs.Sub(web.Files, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(assets)))
	return requestID(logging(securityHeaders(mux), logger))
}

func (s *server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		s.logger.Error("render template", "template", name, "error", err)
	}
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) home(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/portal", http.StatusTemporaryRedirect)
}

type loginPage struct {
	Title   string
	Client  client.Client
	Methods []loginMethodView
}

type loginMethodView struct {
	Label string
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	page := loginPage{Title: "登录 Certus"}
	if clientID := r.URL.Query().Get("client_id"); clientID != "" {
		item, err := s.clients.Find(r.Context(), clientID)
		if err != nil {
			http.Error(w, "未知的接入系统", http.StatusBadRequest)
			return
		}
		page.Client = item
		for _, method := range item.LoginMethods {
			page.Methods = append(page.Methods, loginMethodView{Label: loginMethodLabel(method)})
		}
	}
	s.render(w, "login.html", page)
}

func (s *server) portal(w http.ResponseWriter, r *http.Request) {
	clients, err := s.clients.List(r.Context())
	if err != nil {
		http.Error(w, "读取系统列表失败", http.StatusInternalServerError)
		return
	}
	s.render(w, "portal.html", struct {
		Title   string
		Clients []client.Client
	}{Title: "Certus 统一认证中心", Clients: clients})
}

func (s *server) listClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.clients.List(r.Context())
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取客户端失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": clients})
}

func (s *server) getClient(w http.ResponseWriter, r *http.Request) {
	item, err := s.clients.Find(r.Context(), r.PathValue("clientID"))
	if errors.Is(err, client.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "客户端不存在")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取客户端失败")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *server) authorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	registered, err := s.clients.Find(r.Context(), clientID)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "未知的 client_id")
		return
	}
	if _, err := oauth.ParseAuthorizationRequest(r.URL.Query(), registered); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	target := &url.URL{Path: "/login", RawQuery: r.URL.RawQuery}
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *server) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.cfg.Issuer,
		"authorization_endpoint":                s.cfg.Issuer + "/oauth2/authorize",
		"token_endpoint":                        s.cfg.Issuer + "/oauth2/token",
		"jwks_uri":                              s.cfg.Issuer + "/oauth2/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func loginMethodLabel(method client.LoginMethod) string {
	switch method {
	case client.LoginPassword:
		return "账号密码"
	case client.LoginLDAP:
		return "企业 LDAP"
	case client.LoginOIDC:
		return "外部身份提供商"
	default:
		return string(method)
	}
}

func logging(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Info("http request", "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(start).Milliseconds(), "request_id", w.Header().Get("X-Request-ID"))
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
