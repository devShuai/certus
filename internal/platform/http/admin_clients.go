package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"certus/internal/client"
	"certus/internal/federation"
)

type clientRegistrationResponse struct {
	Client      client.Client         `json:"client"`
	Integration integrationParameters `json:"integration"`
}

type integrationParameters struct {
	SupportedProtocols               []client.Protocol  `json:"supported_protocols"`
	Issuer                           string             `json:"issuer,omitempty"`
	DiscoveryURL                     string             `json:"discovery_url,omitempty"`
	ClientID                         string             `json:"client_id"`
	LaunchURI                        string             `json:"launch_uri,omitempty"`
	ClientSecret                     string             `json:"client_secret,omitempty"`
	ClientAuthenticationMethod       string             `json:"client_authentication_method,omitempty"`
	IdentitySourceIDs                []string           `json:"identity_source_ids,omitempty"`
	AuthorizationEndpoint            string             `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                    string             `json:"token_endpoint,omitempty"`
	IntrospectionEndpoint            string             `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint               string             `json:"revocation_endpoint,omitempty"`
	DeviceAuthorizationEndpoint      string             `json:"device_authorization_endpoint,omitempty"`
	UserInfoEndpoint                 string             `json:"userinfo_endpoint,omitempty"`
	EndSessionEndpoint               string             `json:"end_session_endpoint,omitempty"`
	JWKSURI                          string             `json:"jwks_uri,omitempty"`
	RedirectURIs                     []string           `json:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs           []string           `json:"post_logout_redirect_uris,omitempty"`
	BackchannelLogoutURI             string             `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired bool               `json:"backchannel_logout_session_required,omitempty"`
	Scopes                           []string           `json:"scopes,omitempty"`
	ResponseTypes                    []string           `json:"response_types,omitempty"`
	GrantTypes                       []client.GrantType `json:"grant_types,omitempty"`
	PKCE                             map[string]any     `json:"pkce,omitempty"`
	CAS                              *casIntegration    `json:"cas,omitempty"`
}

type casIntegration struct {
	Version            client.CASVersion `json:"version"`
	ServiceURLs        []string          `json:"service_urls"`
	LoginURL           string            `json:"login_url"`
	LogoutURL          string            `json:"logout_url"`
	ValidateURL        string            `json:"validate_url"`
	ServiceValidateURL string            `json:"service_validate_url,omitempty"`
	ProxyValidateURL   string            `json:"proxy_validate_url,omitempty"`
	ProxyURL           string            `json:"proxy_url,omitempty"`
	Gateway            bool              `json:"gateway"`
	Renew              bool              `json:"renew"`
	SingleLogout       bool              `json:"single_logout"`
}

func (s *server) listAdminClients(w http.ResponseWriter, r *http.Request) {
	items, err := s.clients.List(r.Context())
	if err != nil {
		s.logger.Error("list admin clients", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取接入系统失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) getAdminClient(w http.ResponseWriter, r *http.Request) {
	item, err := s.clients.Find(r.Context(), r.PathValue("clientID"))
	if errors.Is(err, client.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "接入系统不存在")
		return
	}
	if err != nil {
		s.logger.Error("find admin client", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取接入系统失败")
		return
	}
	writeJSON(w, http.StatusOK, clientRegistrationResponse{
		Client:      item,
		Integration: s.integrationParameters(item, ""),
	})
}

func (s *server) createClient(w http.ResponseWriter, r *http.Request) {
	var input client.CreateClient
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	item, secret, err := client.New(input)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_client", err.Error())
		return
	}
	if err := s.validateClientIdentitySources(r.Context(), item); err != nil {
		writeClientIdentitySourceError(w, err)
		return
	}
	item, err = s.clients.Create(r.Context(), item)
	if errors.Is(err, client.ErrConflict) {
		writeProblem(w, http.StatusConflict, "client_conflict", "client_id 已存在")
		return
	}
	if err != nil {
		s.logger.Error("create client", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建接入系统失败")
		return
	}
	w.Header().Set("Location", "/api/v1/admin/clients/"+item.ID)
	writeJSON(w, http.StatusCreated, clientRegistrationResponse{
		Client:      item,
		Integration: s.integrationParameters(item, secret),
	})
}

func (s *server) replaceClient(w http.ResponseWriter, r *http.Request) {
	current, err := s.clients.Find(r.Context(), r.PathValue("clientID"))
	if errors.Is(err, client.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "接入系统不存在")
		return
	}
	if err != nil {
		s.logger.Error("find client for replacement", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取接入系统失败")
		return
	}
	var input client.ReplaceClient
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	item, err := client.Replace(current, input)
	if errors.Is(err, client.ErrArchived) {
		writeProblem(w, http.StatusConflict, "client_archived", "已归档的接入系统不能修改")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_client", err.Error())
		return
	}
	if err := s.validateClientIdentitySources(r.Context(), item); err != nil {
		writeClientIdentitySourceError(w, err)
		return
	}
	item, err = s.clients.Replace(r.Context(), item)
	if errors.Is(err, client.ErrArchived) {
		writeProblem(w, http.StatusConflict, "client_archived", "已归档的接入系统不能修改")
		return
	}
	if err != nil {
		s.logger.Error("replace client", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "更新接入系统失败")
		return
	}
	if !item.Enabled {
		if err := s.oauth.RevokeClientTokens(r.Context(), item.ID, s.now().UTC()); err != nil {
			s.logger.Error("revoke OAuth tokens for disabled client", "client_id", item.ID, "error", err)
			writeProblem(w, http.StatusInternalServerError, "server_error", "禁用接入系统后撤销令牌失败")
			return
		}
	}
	writeJSON(w, http.StatusOK, clientRegistrationResponse{
		Client:      item,
		Integration: s.integrationParameters(item, ""),
	})
}

func (s *server) validateClientIdentitySources(ctx context.Context, item client.Client) error {
	for _, sourceID := range item.IdentitySourceIDs {
		source, err := s.identitySources.Find(ctx, sourceID)
		if err != nil {
			return err
		}
		if source.ArchivedAt != nil {
			return fmt.Errorf("%w: identity source %q is archived", federation.ErrInvalidSource, sourceID)
		}
		if !source.Enabled {
			return fmt.Errorf("%w: identity source %q is disabled", federation.ErrInvalidSource, sourceID)
		}
		switch source.Type {
		case federation.SourceLDAP:
			if !slices.Contains(item.LoginMethods, client.LoginLDAP) {
				return fmt.Errorf(
					"%w: LDAP identity source %q requires the ldap login method",
					federation.ErrInvalidSource,
					sourceID,
				)
			}
		case federation.SourceOIDC:
			if !slices.Contains(item.LoginMethods, client.LoginOIDC) {
				return fmt.Errorf(
					"%w: OIDC identity source %q requires the oidc login method",
					federation.ErrInvalidSource,
					sourceID,
				)
			}
		default:
			return fmt.Errorf("%w: unsupported identity source %q", federation.ErrInvalidSource, sourceID)
		}
	}
	return nil
}

func writeClientIdentitySourceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, federation.ErrSourceNotFound):
		writeProblem(w, http.StatusBadRequest, "invalid_identity_source", "客户端绑定的身份源不存在")
	case errors.Is(err, federation.ErrInvalidSource):
		writeProblem(w, http.StatusBadRequest, "invalid_identity_source", err.Error())
	default:
		writeProblem(w, http.StatusInternalServerError, "server_error", "校验客户端身份源失败")
	}
}

func (s *server) rotateClientSecret(w http.ResponseWriter, r *http.Request) {
	current, err := s.clients.Find(r.Context(), r.PathValue("clientID"))
	if errors.Is(err, client.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "接入系统不存在")
		return
	}
	if err != nil {
		s.logger.Error("find client for secret rotation", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取接入系统失败")
		return
	}
	rotated, secret, err := client.RotateSecret(current)
	if errors.Is(err, client.ErrArchived) {
		writeProblem(w, http.StatusConflict, "client_archived", "已归档的接入系统不能轮换密钥")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_client", err.Error())
		return
	}
	item, err := s.clients.RotateSecret(r.Context(), rotated.ID, rotated.SecretHash)
	if err != nil {
		s.logger.Error("rotate client secret", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "轮换客户端密钥失败")
		return
	}
	writeJSON(w, http.StatusOK, clientRegistrationResponse{
		Client:      item,
		Integration: s.integrationParameters(item, secret),
	})
}

func (s *server) archiveClient(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("clientID")
	now := s.now().UTC()
	err := s.clients.Archive(r.Context(), clientID, now)
	if errors.Is(err, client.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "接入系统不存在")
		return
	}
	if err != nil {
		s.logger.Error("archive client", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "归档接入系统失败")
		return
	}
	if err := s.oauth.RevokeClientTokens(r.Context(), clientID, now); err != nil {
		s.logger.Error("revoke OAuth tokens for archived client", "client_id", clientID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "归档接入系统后撤销令牌失败")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) getClientIntegration(w http.ResponseWriter, r *http.Request) {
	item, err := s.clients.Find(r.Context(), r.PathValue("clientID"))
	if errors.Is(err, client.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "接入系统不存在")
		return
	}
	if err != nil {
		s.logger.Error("find client integration", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取接入参数失败")
		return
	}
	writeJSON(w, http.StatusOK, s.integrationParameters(item, ""))
}

func (s *server) integrationParameters(item client.Client, secret string) integrationParameters {
	parameters := integrationParameters{
		SupportedProtocols: item.Protocols,
		ClientID:           item.ID,
		LaunchURI:          item.LaunchURI,
		ClientSecret:       secret,
		IdentitySourceIDs:  item.IdentitySourceIDs,
	}
	if item.SupportsOAuth() {
		parameters.Issuer = s.cfg.Issuer
		parameters.DiscoveryURL = s.cfg.Issuer + "/.well-known/openid-configuration"
		parameters.AuthorizationEndpoint = s.cfg.Issuer + "/oauth2/authorize"
		parameters.TokenEndpoint = s.cfg.Issuer + "/oauth2/token"
		parameters.IntrospectionEndpoint = s.cfg.Issuer + "/oauth2/introspect"
		parameters.RevocationEndpoint = s.cfg.Issuer + "/oauth2/revoke"
		parameters.UserInfoEndpoint = s.cfg.Issuer + "/oauth2/userinfo"
		parameters.EndSessionEndpoint = s.cfg.Issuer + "/oauth2/logout"
		parameters.JWKSURI = s.cfg.Issuer + "/oauth2/jwks"
		parameters.RedirectURIs = item.RedirectURIs
		parameters.PostLogoutRedirectURIs = item.PostLogoutRedirectURIs
		parameters.BackchannelLogoutURI = item.BackchannelLogoutURI
		parameters.BackchannelLogoutSessionRequired = item.BackchannelLogoutSessionRequired
		parameters.Scopes = item.AllowedScopes
		parameters.GrantTypes = item.GrantTypes
		parameters.ClientAuthenticationMethod = string(item.EffectiveTokenEndpointAuthMethod())
		if item.SupportsGrant(client.GrantAuthorizationCode) {
			parameters.ResponseTypes = []string{"code"}
			parameters.PKCE = map[string]any{
				"required":         true,
				"challenge_method": "S256",
			}
		}
		if item.SupportsGrant(client.GrantDeviceCode) {
			parameters.DeviceAuthorizationEndpoint = s.cfg.Issuer + "/oauth2/device_authorization"
		}
	}
	if item.SupportsProtocol(client.ProtocolCAS) {
		cas := &casIntegration{
			Version:      item.CASVersion,
			ServiceURLs:  item.CASServiceURLs,
			LoginURL:     s.cfg.Issuer + "/cas/login",
			LogoutURL:    s.cfg.Issuer + "/cas/logout",
			Gateway:      item.CASGateway,
			Renew:        item.CASRenew,
			SingleLogout: item.CASSingleLogout,
		}
		switch item.CASVersion {
		case client.CASVersion1:
			cas.ValidateURL = s.cfg.Issuer + "/cas/validate"
		case client.CASVersion2:
			cas.ValidateURL = s.cfg.Issuer + "/cas/serviceValidate"
			cas.ServiceValidateURL = cas.ValidateURL
			if item.CASProxy {
				cas.ProxyValidateURL = s.cfg.Issuer + "/cas/proxyValidate"
				cas.ProxyURL = s.cfg.Issuer + "/cas/proxy"
			}
		case client.CASVersion3:
			cas.ValidateURL = s.cfg.Issuer + "/cas/p3/serviceValidate"
			cas.ServiceValidateURL = cas.ValidateURL
			if item.CASProxy {
				cas.ProxyValidateURL = s.cfg.Issuer + "/cas/p3/proxyValidate"
				cas.ProxyURL = s.cfg.Issuer + "/cas/proxy"
			}
		}
		parameters.CAS = cas
	}
	return parameters
}
