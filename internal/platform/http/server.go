package httpserver

import (
	"context"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"certus/internal/access"
	"certus/internal/administration"
	"certus/internal/audit"
	"certus/internal/cas"
	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/federation"
	"certus/internal/identity"
	"certus/internal/maintenance"
	"certus/internal/metrics"
	"certus/internal/mfa"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/ratelimit"
	"certus/internal/session"
	"certus/web"
)

type server struct {
	cfg             config.Config
	logger          *slog.Logger
	templates       *template.Template
	clients         client.Repository
	users           identity.UserRepository
	externalUsers   identity.ExternalIdentityRepository
	identitySources *federation.SourceService
	passwords       *identity.PasswordService
	sessions        *session.Service
	oauth           oauth.Repository
	cas             cas.Repository
	accessControl   access.Repository
	administrators  administration.Repository
	audit           audit.Repository
	mfa             *mfa.Service
	maintenance     *maintenance.Service
	signer          *oidc.Signer
	rateLimits      *ratelimit.Service
	metrics         *metrics.Registry
	readiness       func(context.Context) error
	outbound        *http.Client
	ldap            *federation.LDAPAuthenticator
	externalOIDC    *federation.OIDCAuthenticator
	now             func() time.Time
}

func New(cfg config.Config, logger *slog.Logger) http.Handler {
	clients := client.NewMemoryRepository(client.Client{
		ID:                      "specus",
		Name:                    "Specus",
		Description:             "示例接入系统",
		ApplicationType:         client.ApplicationPublic,
		TokenEndpointAuthMethod: client.TokenEndpointAuthNone,
		Protocols:               []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:              []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken},
		RedirectURIs:            []string{"http://localhost:3000/callback"},
		LoginMethods:            []client.LoginMethod{client.LoginPassword, client.LoginLDAP},
		AllowedScopes:           []string{"openid", "profile", "email"},
		Enabled:                 true,
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
	Access             access.Repository
	Administration     administration.Repository
	Audit              audit.Repository
	MFA                mfa.Repository
	Maintenance        *maintenance.Service
	Keys               oidc.KeyRepository
	RateLimits         ratelimit.Repository
	Metrics            *metrics.Registry
	Readiness          func(context.Context) error
	OutboundHTTPClient *http.Client
	IdentitySources    federation.SourceRepository
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
	if dependencies.Access == nil {
		dependencies.Access = access.NewMemoryRepository()
	}
	if dependencies.Administration == nil {
		dependencies.Administration = administration.NewMemoryRepository()
	}
	if dependencies.Audit == nil {
		dependencies.Audit = audit.NewMemoryRepository()
	}
	if dependencies.MFA == nil {
		dependencies.MFA = mfa.NewMemoryRepository()
	}
	if dependencies.RateLimits == nil {
		dependencies.RateLimits = ratelimit.NewMemoryRepository()
	}
	if dependencies.IdentitySources == nil {
		dependencies.IdentitySources = federation.NewMemorySourceRepository()
	}
	if dependencies.Metrics == nil {
		dependencies.Metrics = metrics.NewRegistry()
	}
	if dependencies.Readiness == nil {
		dependencies.Readiness = func(context.Context) error { return nil }
	}
	if dependencies.Maintenance == nil {
		dependencies.Maintenance = maintenance.NewService(
			maintenance.NewMemoryRepository(dependencies.Keys),
			cfg.AuditRetention,
			cfg.SigningKeyRetention,
		)
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
		identitySources: federation.NewSourceService(
			dependencies.IdentitySources,
			cfg.SecretEncryptionKeys,
		),
		passwords:      identity.NewPasswordService(dependencies.Passwords),
		sessions:       session.NewService(dependencies.Sessions, 12*time.Hour),
		oauth:          dependencies.OAuth,
		cas:            dependencies.CAS,
		accessControl:  dependencies.Access,
		administrators: dependencies.Administration,
		audit:          dependencies.Audit,
		mfa:            mfa.NewServiceWithKeyRing(dependencies.MFA, cfg.SecretEncryptionKeys, cfg.MFAEncryptionKey, "Certus"),
		maintenance:    dependencies.Maintenance,
		signer:         signer,
		rateLimits:     ratelimit.NewService(dependencies.RateLimits),
		metrics:        dependencies.Metrics,
		readiness:      dependencies.Readiness,
		outbound:       outbound,
		ldap:           federation.NewLDAPAuthenticator(cfg.LDAP),
		externalOIDC: federation.NewOIDCAuthenticator(
			cfg.ExternalOIDC,
			cfg.Issuer+"/login/oidc/callback",
			outbound,
		),
		now: time.Now,
	}
	if cfg.SigningKeyRotation > 0 {
		go s.runSigningKeyRotation(ctx, cfg.SigningKeyRotation)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPassword)
	mux.HandleFunc("POST /login/ldap", s.loginLDAP)
	mux.HandleFunc("GET /login/oidc", s.loginOIDC)
	mux.HandleFunc("GET /login/oidc/callback", s.loginOIDCCallback)
	mux.HandleFunc("GET /login/mfa", s.mfaLoginPage)
	mux.HandleFunc("POST /login/mfa", s.mfaLoginVerify)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /portal", s.portal)
	mux.HandleFunc("GET /account", s.accountPage)
	mux.HandleFunc("GET /admin", s.adminClientsPage)
	mux.HandleFunc("GET /admin/clients", s.adminClientsPage)
	mux.HandleFunc("GET /api/v1/clients", s.listClients)
	mux.HandleFunc("GET /api/v1/clients/{clientID}", s.getClient)
	mux.Handle("GET /api/v1/admin/me", s.requireAdmin("", http.HandlerFunc(s.adminMe)))
	mux.Handle("GET /api/v1/admin/roles", s.requireAdmin(administration.PermissionAdminRolesRead, http.HandlerFunc(s.listAdministratorRoleDefinitions)))
	mux.Handle("GET /api/v1/admin/users", s.requireAdmin(administration.PermissionUsersRead, http.HandlerFunc(s.listUsers)))
	mux.Handle("POST /api/v1/admin/users", s.requireAdmin(administration.PermissionUsersWrite, http.HandlerFunc(s.createUser)))
	mux.Handle("GET /api/v1/admin/users/{userID}", s.requireAdmin(administration.PermissionUsersRead, http.HandlerFunc(s.getUser)))
	mux.Handle("PUT /api/v1/admin/users/{userID}", s.requireAdmin(administration.PermissionUsersWrite, http.HandlerFunc(s.replaceUser)))
	mux.Handle("PUT /api/v1/admin/users/{userID}/password", s.requireAdmin(administration.PermissionUsersWrite, http.HandlerFunc(s.setUserPassword)))
	mux.Handle("POST /api/v1/admin/users/{userID}/password-reset", s.requireAdmin(administration.PermissionUsersWrite, http.HandlerFunc(s.issueUserPasswordReset)))
	mux.Handle("GET /api/v1/admin/users/{userID}/sessions", s.requireAdmin(administration.PermissionUsersRead, http.HandlerFunc(s.listAdminUserSessions)))
	mux.Handle("DELETE /api/v1/admin/users/{userID}/sessions", s.requireAdmin(administration.PermissionUsersWrite, http.HandlerFunc(s.revokeAllAdminUserSessions)))
	mux.Handle("DELETE /api/v1/admin/users/{userID}/sessions/{sessionID}", s.requireAdmin(administration.PermissionUsersWrite, http.HandlerFunc(s.revokeAdminUserSession)))
	mux.Handle("DELETE /api/v1/admin/users/{userID}/mfa", s.requireAdmin(administration.PermissionUsersWrite, http.HandlerFunc(s.resetAdminUserMFA)))
	mux.Handle("GET /api/v1/admin/users/{userID}/admin-roles", s.requireAdmin(administration.PermissionAdminRolesRead, http.HandlerFunc(s.listUserAdministratorRoles)))
	mux.Handle("PUT /api/v1/admin/users/{userID}/admin-roles", s.requireAdmin(administration.PermissionAdminRolesWrite, http.HandlerFunc(s.replaceUserAdministratorRoles)))
	mux.Handle("GET /api/v1/admin/audit-events", s.requireAdmin(administration.PermissionAuditRead, http.HandlerFunc(s.listAuditEvents)))
	mux.Handle("GET /api/v1/admin/signing-keys", s.requireAdmin(administration.PermissionSecurityRead, http.HandlerFunc(s.listSigningKeys)))
	mux.Handle("POST /api/v1/admin/signing-keys/rotate", s.requireAdmin(administration.PermissionSecurityWrite, http.HandlerFunc(s.rotateSigningKey)))
	mux.Handle("POST /api/v1/admin/maintenance/cleanup", s.requireAdmin(administration.PermissionMaintenanceExecute, http.HandlerFunc(s.runMaintenance)))
	mux.Handle("GET /api/v1/admin/identity-sources", s.requireAdmin(administration.PermissionSourcesRead, http.HandlerFunc(s.listIdentitySources)))
	mux.Handle("POST /api/v1/admin/identity-sources", s.requireAdmin(administration.PermissionSourcesWrite, http.HandlerFunc(s.createIdentitySource)))
	mux.Handle("GET /api/v1/admin/identity-sources/{sourceID}", s.requireAdmin(administration.PermissionSourcesRead, http.HandlerFunc(s.getIdentitySource)))
	mux.Handle("PUT /api/v1/admin/identity-sources/{sourceID}", s.requireAdmin(administration.PermissionSourcesWrite, http.HandlerFunc(s.replaceIdentitySource)))
	mux.Handle("DELETE /api/v1/admin/identity-sources/{sourceID}", s.requireAdmin(administration.PermissionSourcesWrite, http.HandlerFunc(s.archiveIdentitySource)))
	mux.Handle("POST /api/v1/admin/identity-sources/{sourceID}/probe", s.requireAdmin(administration.PermissionSourcesWrite, http.HandlerFunc(s.probeIdentitySource)))
	mux.Handle("GET /api/v1/admin/clients", s.requireAdmin(administration.PermissionClientsRead, http.HandlerFunc(s.listAdminClients)))
	mux.Handle("POST /api/v1/admin/clients", s.requireAdmin(administration.PermissionClientsWrite, http.HandlerFunc(s.createClient)))
	mux.Handle("GET /api/v1/admin/clients/{clientID}", s.requireAdmin(administration.PermissionClientsRead, http.HandlerFunc(s.getAdminClient)))
	mux.Handle("PUT /api/v1/admin/clients/{clientID}", s.requireAdmin(administration.PermissionClientsWrite, http.HandlerFunc(s.replaceClient)))
	mux.Handle("DELETE /api/v1/admin/clients/{clientID}", s.requireAdmin(administration.PermissionClientsWrite, http.HandlerFunc(s.archiveClient)))
	mux.Handle("POST /api/v1/admin/clients/{clientID}/secret", s.requireAdmin(administration.PermissionClientsWrite, http.HandlerFunc(s.rotateClientSecret)))
	mux.Handle("GET /api/v1/admin/clients/{clientID}/integration", s.requireAdmin(administration.PermissionClientsRead, http.HandlerFunc(s.getClientIntegration)))
	mux.Handle("GET /api/v1/admin/clients/{clientID}/roles", s.requireAdmin(administration.PermissionAccessRead, http.HandlerFunc(s.listRoles)))
	mux.Handle("POST /api/v1/admin/clients/{clientID}/roles", s.requireAdmin(administration.PermissionAccessWrite, http.HandlerFunc(s.createRole)))
	mux.Handle("GET /api/v1/admin/clients/{clientID}/roles/{roleID}", s.requireAdmin(administration.PermissionAccessRead, http.HandlerFunc(s.getRole)))
	mux.Handle("PUT /api/v1/admin/clients/{clientID}/roles/{roleID}", s.requireAdmin(administration.PermissionAccessWrite, http.HandlerFunc(s.replaceRole)))
	mux.Handle("DELETE /api/v1/admin/clients/{clientID}/roles/{roleID}", s.requireAdmin(administration.PermissionAccessWrite, http.HandlerFunc(s.deleteRole)))
	mux.Handle("GET /api/v1/admin/clients/{clientID}/permissions", s.requireAdmin(administration.PermissionAccessRead, http.HandlerFunc(s.listPermissions)))
	mux.Handle("POST /api/v1/admin/clients/{clientID}/permissions", s.requireAdmin(administration.PermissionAccessWrite, http.HandlerFunc(s.createPermission)))
	mux.Handle("GET /api/v1/admin/clients/{clientID}/permissions/{permissionID}", s.requireAdmin(administration.PermissionAccessRead, http.HandlerFunc(s.getPermission)))
	mux.Handle("PUT /api/v1/admin/clients/{clientID}/permissions/{permissionID}", s.requireAdmin(administration.PermissionAccessWrite, http.HandlerFunc(s.replacePermission)))
	mux.Handle("DELETE /api/v1/admin/clients/{clientID}/permissions/{permissionID}", s.requireAdmin(administration.PermissionAccessWrite, http.HandlerFunc(s.deletePermission)))
	mux.Handle("GET /api/v1/admin/clients/{clientID}/roles/{roleID}/permissions", s.requireAdmin(administration.PermissionAccessRead, http.HandlerFunc(s.listRolePermissions)))
	mux.Handle("PUT /api/v1/admin/clients/{clientID}/roles/{roleID}/permissions", s.requireAdmin(administration.PermissionAccessWrite, http.HandlerFunc(s.replaceRolePermissions)))
	mux.Handle("GET /api/v1/admin/users/{userID}/roles", s.requireAdmin(administration.PermissionAccessRead, http.HandlerFunc(s.listUserRoles)))
	mux.Handle("PUT /api/v1/admin/users/{userID}/roles", s.requireAdmin(administration.PermissionAccessWrite, http.HandlerFunc(s.replaceUserRoles)))
	mux.HandleFunc("GET /api/v1/access/users/{userID}", s.getEffectiveAccess)
	mux.HandleFunc("GET /api/v1/account/profile", s.getAccountProfile)
	mux.HandleFunc("GET /api/v1/account/sessions", s.listAccountSessions)
	mux.HandleFunc("DELETE /api/v1/account/sessions/{sessionID}", s.revokeAccountSession)
	mux.HandleFunc("GET /api/v1/account/consents", s.listAccountConsents)
	mux.HandleFunc("DELETE /api/v1/account/consents/{clientID}", s.revokeAccountConsent)
	mux.HandleFunc("PUT /api/v1/account/password", s.changeAccountPassword)
	mux.HandleFunc("POST /api/v1/account/password/reset", s.resetAccountPassword)
	mux.HandleFunc("GET /api/v1/account/mfa", s.getAccountMFA)
	mux.HandleFunc("POST /api/v1/account/mfa/totp/setup", s.setupAccountMFA)
	mux.HandleFunc("POST /api/v1/account/mfa/totp/enable", s.enableAccountMFA)
	mux.HandleFunc("POST /api/v1/account/mfa/recovery-codes", s.regenerateAccountMFARecoveryCodes)
	mux.HandleFunc("DELETE /api/v1/account/mfa/totp", s.disableAccountMFA)
	mux.HandleFunc("GET /oauth2/authorize", s.authorize)
	mux.HandleFunc("POST /oauth2/authorize/consent", s.oauthConsentDecision)
	mux.HandleFunc("POST /oauth2/token", s.token)
	mux.HandleFunc("POST /oauth2/introspect", s.introspect)
	mux.HandleFunc("POST /oauth2/revoke", s.revokeToken)
	mux.HandleFunc("GET /oauth2/logout", s.oidcLogout)
	mux.HandleFunc("POST /oauth2/logout", s.oidcLogout)
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
	if cfg.MetricsToken != "" {
		mux.HandleFunc("GET /metrics", s.metricsEndpoint)
	}

	assets, err := fs.Sub(web.Files, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(assets)))
	return requestID(logging(securityHeaders(s.metrics.Middleware(s.auditMutations(mux)), s.secureCookies()), logger)), nil
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

func (s *server) ready(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.readiness(ctx); err != nil {
		s.metrics.RecordReadiness("unavailable")
		s.metrics.RecordBackground("readiness", "failure", time.Since(started))
		s.logger.Warn("readiness check failed", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	s.metrics.RecordReadiness("ready")
	s.metrics.RecordBackground("readiness", "success", time.Since(started))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
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
	var currentUser *identity.User
	administrator := false
	csrfToken := ""
	if current, ok := s.currentSession(r); ok {
		if user, findErr := s.users.Find(r.Context(), current.UserID); findErr == nil {
			currentUser = &user
			csrfToken = s.ensureCSRF(w, r)
			if access, accessErr := s.administrators.Effective(r.Context(), current.UserID); accessErr == nil {
				administrator = len(access.Roles) > 0
			}
		}
	}
	s.render(w, "portal.html", struct {
		Title         string
		Clients       []client.Client
		User          *identity.User
		Administrator bool
		CSRFToken     string
	}{
		Title:         "Certus 统一认证中心",
		Clients:       activeClients(clients),
		User:          currentUser,
		Administrator: administrator,
		CSRFToken:     csrfToken,
	})
}

func (s *server) adminClientsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	current, ok := s.currentSession(r)
	if !ok {
		http.Redirect(
			w,
			r,
			"/login?continue="+url.QueryEscape(r.URL.Path),
			http.StatusSeeOther,
		)
		return
	}
	administratorAccess, err := s.administrators.Effective(r.Context(), current.UserID)
	if err != nil {
		s.logger.Error("read administrator page access", "user_id", current.UserID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取管理员权限失败")
		return
	}
	if len(administratorAccess.Roles) == 0 {
		writeProblem(w, http.StatusForbidden, "not_administrator", "当前账号不是 Certus 管理员")
		return
	}
	if !administratorMFA(current) {
		status, statusErr := s.mfa.Status(r.Context(), current.UserID)
		if statusErr != nil {
			writeProblem(w, http.StatusServiceUnavailable, "mfa_unavailable", "无法确认管理员多因素认证状态")
			return
		}
		if !status.Enabled {
			http.Redirect(w, r, "/account?admin_mfa=required", http.StatusSeeOther)
			return
		}
		http.Redirect(
			w,
			r,
			"/login?continue="+url.QueryEscape(r.URL.Path),
			http.StatusSeeOther,
		)
		return
	}
	user, err := s.users.Find(r.Context(), current.UserID)
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "管理员账号不可用")
		return
	}
	s.render(w, "admin-clients.html", adminPageData{
		Title:       "管理控制台 · Certus",
		CSRFToken:   s.ensureCSRF(w, r),
		User:        user,
		Roles:       administratorAccess.Roles,
		Permissions: administratorAccess.Permissions,
	})
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
