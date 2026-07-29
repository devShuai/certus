package httpserver

import (
	"context"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"certus/internal/cas"
	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/federation"
	"certus/internal/identity"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/session"
	"certus/web"
)

type server struct {
	cfg              config.Config
	logger           *slog.Logger
	templates        *template.Template
	clients          client.Repository
	users            identity.UserRepository
	externalUsers    identity.ExternalIdentityRepository
	passwords        *identity.PasswordService
	sessions         *session.Service
	oauth            oauth.Repository
	cas              cas.Repository
	signer           *oidc.Signer
	outbound         *http.Client
	ldap             *federation.LDAPAuthenticator
	externalOIDC     *federation.OIDCAuthenticator
	now              func() time.Time
	deviceAttemptsMu sync.Mutex
	deviceAttempts   map[string]deviceAttemptWindow
}

func New(cfg config.Config, logger *slog.Logger) http.Handler {
	clients := client.NewMemoryRepository(client.Client{
		ID:              "specus",
		Name:            "Specus",
		Description:     "示例接入系统",
		ApplicationType: client.ApplicationPublic,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken},
		RedirectURIs:    []string{"http://localhost:3000/callback"},
		LoginMethods:    []client.LoginMethod{client.LoginPassword, client.LoginLDAP},
		AllowedScopes:   []string{"openid", "profile", "email"},
		Enabled:         true,
	})
	return NewWithClients(cfg, logger, clients)
}

func NewWithClients(cfg config.Config, logger *slog.Logger, clients client.Repository) http.Handler {
	return NewWithRepositories(cfg, logger, clients, identity.NewMemoryUserRepository())
}

func NewWithRepositories(cfg config.Config, logger *slog.Logger, clients client.Repository, users identity.UserRepository) http.Handler {
	passwords, ok := users.(identity.PasswordRepository)
	if !ok {
		panic("user repository does not implement password repository")
	}
	handler, err := NewWithDependencies(context.Background(), cfg, logger, Dependencies{
		Clients:   clients,
		Users:     users,
		Passwords: passwords,
		Sessions:  session.NewMemoryRepository(),
		OAuth:     oauth.NewMemoryRepository(),
		CAS:       cas.NewMemoryRepository(),
		Keys:      &oidc.MemoryKeyRepository{},
	})
	if err != nil {
		panic(err)
	}
	return handler
}

type Dependencies struct {
	Clients            client.Repository
	Users              identity.UserRepository
	ExternalIdentities identity.ExternalIdentityRepository
	Passwords          identity.PasswordRepository
	Sessions           session.Repository
	OAuth              oauth.Repository
	CAS                cas.Repository
	Keys               oidc.KeyRepository
	OutboundHTTPClient *http.Client
}

func NewWithDependencies(ctx context.Context, cfg config.Config, logger *slog.Logger, dependencies Dependencies) (http.Handler, error) {
	templates := template.Must(template.ParseFS(web.Files, "templates/*.html"))
	signer, err := oidc.NewSigner(ctx, dependencies.Keys)
	if err != nil {
		return nil, err
	}
	externalUsers := dependencies.ExternalIdentities
	if externalUsers == nil {
		var ok bool
		externalUsers, ok = dependencies.Users.(identity.ExternalIdentityRepository)
		if !ok {
			return nil, errors.New("user repository does not implement external identity repository")
		}
	}
	outbound := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	if dependencies.OutboundHTTPClient != nil {
		configured := *dependencies.OutboundHTTPClient
		if configured.Timeout == 0 || configured.Timeout > 5*time.Second {
			configured.Timeout = 5 * time.Second
		}
		configured.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		outbound = &configured
	}
	s := &server{
		cfg:           cfg,
		logger:        logger,
		templates:     templates,
		clients:       dependencies.Clients,
		users:         dependencies.Users,
		externalUsers: externalUsers,
		passwords:     identity.NewPasswordService(dependencies.Passwords),
		sessions:      session.NewService(dependencies.Sessions, 12*time.Hour),
		oauth:         dependencies.OAuth,
		cas:           dependencies.CAS,
		signer:        signer,
		outbound:      outbound,
		ldap:          federation.NewLDAPAuthenticator(cfg.LDAP),
		externalOIDC: federation.NewOIDCAuthenticator(
			cfg.ExternalOIDC,
			cfg.Issuer+"/login/oidc/callback",
			outbound,
		),
		now:            time.Now,
		deviceAttempts: make(map[string]deviceAttemptWindow),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.health)
	mux.HandleFunc("GET /", s.home)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPassword)
	mux.HandleFunc("POST /login/ldap", s.loginLDAP)
	mux.HandleFunc("GET /login/oidc", s.loginOIDC)
	mux.HandleFunc("GET /login/oidc/callback", s.loginOIDCCallback)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /portal", s.portal)
	mux.HandleFunc("GET /admin/clients", s.adminClientsPage)
	mux.HandleFunc("GET /api/v1/clients", s.listClients)
	mux.HandleFunc("GET /api/v1/clients/{clientID}", s.getClient)
	mux.Handle("GET /api/v1/admin/users", s.requireAdmin(http.HandlerFunc(s.listUsers)))
	mux.Handle("POST /api/v1/admin/users", s.requireAdmin(http.HandlerFunc(s.createUser)))
	mux.Handle("GET /api/v1/admin/users/{userID}", s.requireAdmin(http.HandlerFunc(s.getUser)))
	mux.Handle("PUT /api/v1/admin/users/{userID}", s.requireAdmin(http.HandlerFunc(s.replaceUser)))
	mux.Handle("PUT /api/v1/admin/users/{userID}/password", s.requireAdmin(http.HandlerFunc(s.setUserPassword)))
	mux.Handle("GET /api/v1/admin/clients", s.requireAdmin(http.HandlerFunc(s.listAdminClients)))
	mux.Handle("POST /api/v1/admin/clients", s.requireAdmin(http.HandlerFunc(s.createClient)))
	mux.Handle("GET /api/v1/admin/clients/{clientID}", s.requireAdmin(http.HandlerFunc(s.getAdminClient)))
	mux.Handle("PUT /api/v1/admin/clients/{clientID}", s.requireAdmin(http.HandlerFunc(s.replaceClient)))
	mux.Handle("DELETE /api/v1/admin/clients/{clientID}", s.requireAdmin(http.HandlerFunc(s.archiveClient)))
	mux.Handle("POST /api/v1/admin/clients/{clientID}/secret", s.requireAdmin(http.HandlerFunc(s.rotateClientSecret)))
	mux.Handle("GET /api/v1/admin/clients/{clientID}/integration", s.requireAdmin(http.HandlerFunc(s.getClientIntegration)))
	mux.HandleFunc("GET /oauth2/authorize", s.authorize)
	mux.HandleFunc("POST /oauth2/token", s.token)
	mux.HandleFunc("POST /oauth2/introspect", s.introspect)
	mux.HandleFunc("POST /oauth2/revoke", s.revokeToken)
	mux.HandleFunc("POST /oauth2/device_authorization", s.deviceAuthorization)
	mux.HandleFunc("GET /oauth2/userinfo", s.userinfo)
	mux.HandleFunc("POST /oauth2/userinfo", s.userinfo)
	mux.HandleFunc("GET /oauth2/jwks", s.jwks)
	mux.HandleFunc("GET /device", s.devicePage)
	mux.HandleFunc("POST /device", s.deviceDecision)
	mux.HandleFunc("GET /cas/login", s.casLogin)
	mux.HandleFunc("GET /cas/validate", s.casValidate)
	mux.HandleFunc("GET /cas/serviceValidate", s.casServiceValidate)
	mux.HandleFunc("GET /cas/p3/serviceValidate", s.casServiceValidate)
	mux.HandleFunc("GET /cas/proxyValidate", s.casProxyValidate)
	mux.HandleFunc("GET /cas/p3/proxyValidate", s.casProxyValidate)
	mux.HandleFunc("GET /cas/proxy", s.casProxy)
	mux.HandleFunc("GET /cas/logout", s.casLogout)
	mux.HandleFunc("POST /cas/logout", s.casLogout)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)

	assets, err := fs.Sub(web.Files, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(assets)))
	return requestID(logging(securityHeaders(mux, s.secureCookies()), logger)), nil
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

func (s *server) portal(w http.ResponseWriter, r *http.Request) {
	clients, err := s.clients.List(r.Context())
	if err != nil {
		http.Error(w, "读取系统列表失败", http.StatusInternalServerError)
		return
	}
	s.render(w, "portal.html", struct {
		Title   string
		Clients []client.Client
	}{Title: "Certus 统一认证中心", Clients: activeClients(clients)})
}

func (s *server) adminClientsPage(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "admin-clients.html", map[string]string{"Title": "配置接入系统 · Certus"})
}

func (s *server) listClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.clients.List(r.Context())
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取客户端失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": activeClients(clients)})
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
	if !item.Enabled || item.ArchivedAt != nil {
		writeProblem(w, http.StatusNotFound, "not_found", "客户端不存在")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func activeClients(items []client.Client) []client.Client {
	result := make([]client.Client, 0, len(items))
	for _, item := range items {
		if item.Enabled && item.ArchivedAt == nil {
			result = append(result, item)
		}
	}
	return result
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

func securityHeaders(next http.Handler, secure bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if secure {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}
