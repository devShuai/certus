package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound       = errors.New("client not found")
	ErrConflict       = errors.New("client already exists")
	ErrInvalid        = errors.New("invalid client")
	ErrArchived       = errors.New("client is archived")
	ErrNotArchived    = errors.New("client is not archived")
	ErrSystemNotFound = errors.New("system not found")
	ErrSystemConflict = errors.New("system already exists")
	ErrSystemInUse    = errors.New("system still has clients")
)

const (
	DefaultAccessTokenLifetime  = 15 * time.Minute
	MinAccessTokenLifetime      = time.Minute
	MaxAccessTokenLifetime      = 24 * time.Hour
	DefaultRefreshTokenLifetime = 30 * 24 * time.Hour
	MinRefreshTokenLifetime     = time.Hour
	MaxRefreshTokenLifetime     = 365 * 24 * time.Hour
)

type LoginMethod string

const (
	LoginPassword LoginMethod = "password"
	LoginLDAP     LoginMethod = "ldap"
	LoginOIDC     LoginMethod = "oidc"
)

type ApplicationType string

const (
	ApplicationPublic       ApplicationType = "public"
	ApplicationConfidential ApplicationType = "confidential"
)

type TokenEndpointAuthMethod string

const (
	TokenEndpointAuthNone        TokenEndpointAuthMethod = "none"
	TokenEndpointAuthSecretBasic TokenEndpointAuthMethod = "client_secret_basic"
	TokenEndpointAuthSecretPost  TokenEndpointAuthMethod = "client_secret_post"
)

type Protocol string

const (
	ProtocolOAuth20 Protocol = "oauth2.0"
	ProtocolOAuth21 Protocol = "oauth2.1"
	ProtocolCAS     Protocol = "cas"
)

type GrantType string

const (
	GrantAuthorizationCode GrantType = "authorization_code"
	GrantRefreshToken      GrantType = "refresh_token"
	GrantClientCredentials GrantType = "client_credentials"
	GrantDeviceCode        GrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

type CASVersion string

const (
	CASVersion1 CASVersion = "1.0"
	CASVersion2 CASVersion = "2.0"
	CASVersion3 CASVersion = "3.0"
)

// System is the user-facing application shown in the portal. One system can
// own multiple protocol clients with independent credentials and policies.
type System struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	FaviconURL    string `json:"favicon_url,omitempty"`
	LaunchURI     string `json:"launch_uri,omitempty"`
	PortalVisible bool   `json:"portal_visible"`
}

type CreateSystem struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	FaviconURL    string `json:"favicon_url"`
	LaunchURI     string `json:"launch_uri"`
	PortalVisible *bool  `json:"portal_visible"`
}

type ReplaceSystemInput struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	FaviconURL    string `json:"favicon_url"`
	LaunchURI     string `json:"launch_uri"`
	PortalVisible bool   `json:"portal_visible"`
}

type Client struct {
	ID                               string                  `json:"id"`
	SystemID                         string                  `json:"system_id"`
	System                           *System                 `json:"system,omitempty"`
	Name                             string                  `json:"name"`
	Description                      string                  `json:"description,omitempty"`
	FaviconURL                       string                  `json:"favicon_url,omitempty"`
	LaunchURI                        string                  `json:"launch_uri,omitempty"`
	ApplicationType                  ApplicationType         `json:"application_type"`
	TokenEndpointAuthMethod          TokenEndpointAuthMethod `json:"token_endpoint_auth_method"`
	Protocols                        []Protocol              `json:"protocols"`
	GrantTypes                       []GrantType             `json:"grant_types,omitempty"`
	RedirectURIs                     []string                `json:"redirect_uris"`
	PostLogoutRedirectURIs           []string                `json:"post_logout_redirect_uris,omitempty"`
	BackchannelLogoutURI             string                  `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired bool                    `json:"backchannel_logout_session_required"`
	LoginMethods                     []LoginMethod           `json:"login_methods"`
	IdentitySourceIDs                []string                `json:"identity_source_ids,omitempty"`
	IntrospectableBy                 []string                `json:"introspectable_by,omitempty"`
	AllowedScopes                    []string                `json:"allowed_scopes"`
	AccessTokenLifetimeSeconds       int64                   `json:"access_token_lifetime_seconds,omitempty"`
	RefreshTokenLifetimeSeconds      int64                   `json:"refresh_token_lifetime_seconds,omitempty"`
	CASVersion                       CASVersion              `json:"cas_version,omitempty"`
	CASServiceURLs                   []string                `json:"cas_service_urls,omitempty"`
	CASProxy                         bool                    `json:"cas_proxy"`
	CASGateway                       bool                    `json:"cas_gateway"`
	CASRenew                         bool                    `json:"cas_renew"`
	CASSingleLogout                  bool                    `json:"cas_single_logout"`
	Enabled                          bool                    `json:"enabled"`
	ArchivedAt                       *time.Time              `json:"archived_at,omitempty"`
	SecretHash                       []byte                  `json:"-"`
}

type CreateClient struct {
	ID                               string                  `json:"id"`
	SystemID                         string                  `json:"system_id"`
	Name                             string                  `json:"name"`
	Description                      string                  `json:"description"`
	FaviconURL                       string                  `json:"favicon_url"`
	LaunchURI                        string                  `json:"launch_uri"`
	ApplicationType                  ApplicationType         `json:"application_type"`
	TokenEndpointAuthMethod          TokenEndpointAuthMethod `json:"token_endpoint_auth_method"`
	Protocols                        []Protocol              `json:"protocols"`
	GrantTypes                       []GrantType             `json:"grant_types"`
	RedirectURIs                     []string                `json:"redirect_uris"`
	PostLogoutRedirectURIs           []string                `json:"post_logout_redirect_uris"`
	BackchannelLogoutURI             string                  `json:"backchannel_logout_uri"`
	BackchannelLogoutSessionRequired bool                    `json:"backchannel_logout_session_required"`
	LoginMethods                     []LoginMethod           `json:"login_methods"`
	IdentitySourceIDs                []string                `json:"identity_source_ids"`
	IntrospectableBy                 []string                `json:"introspectable_by"`
	AllowedScopes                    []string                `json:"allowed_scopes"`
	AccessTokenLifetimeSeconds       int64                   `json:"access_token_lifetime_seconds"`
	RefreshTokenLifetimeSeconds      int64                   `json:"refresh_token_lifetime_seconds"`
	CASVersion                       CASVersion              `json:"cas_version"`
	CASServiceURLs                   []string                `json:"cas_service_urls"`
	CASProxy                         bool                    `json:"cas_proxy"`
	CASGateway                       bool                    `json:"cas_gateway"`
	CASRenew                         bool                    `json:"cas_renew"`
	CASSingleLogout                  bool                    `json:"cas_single_logout"`
	Enabled                          *bool                   `json:"enabled"`
}

type ReplaceClient struct {
	SystemID                         string                  `json:"system_id"`
	Name                             string                  `json:"name"`
	Description                      string                  `json:"description"`
	FaviconURL                       string                  `json:"favicon_url"`
	LaunchURI                        string                  `json:"launch_uri"`
	TokenEndpointAuthMethod          TokenEndpointAuthMethod `json:"token_endpoint_auth_method"`
	Protocols                        []Protocol              `json:"protocols"`
	GrantTypes                       []GrantType             `json:"grant_types"`
	RedirectURIs                     []string                `json:"redirect_uris"`
	PostLogoutRedirectURIs           []string                `json:"post_logout_redirect_uris"`
	BackchannelLogoutURI             string                  `json:"backchannel_logout_uri"`
	BackchannelLogoutSessionRequired bool                    `json:"backchannel_logout_session_required"`
	LoginMethods                     []LoginMethod           `json:"login_methods"`
	IdentitySourceIDs                []string                `json:"identity_source_ids"`
	IntrospectableBy                 []string                `json:"introspectable_by"`
	AllowedScopes                    []string                `json:"allowed_scopes"`
	AccessTokenLifetimeSeconds       int64                   `json:"access_token_lifetime_seconds"`
	RefreshTokenLifetimeSeconds      int64                   `json:"refresh_token_lifetime_seconds"`
	CASVersion                       CASVersion              `json:"cas_version"`
	CASServiceURLs                   []string                `json:"cas_service_urls"`
	CASProxy                         bool                    `json:"cas_proxy"`
	CASGateway                       bool                    `json:"cas_gateway"`
	CASRenew                         bool                    `json:"cas_renew"`
	CASSingleLogout                  bool                    `json:"cas_single_logout"`
	Enabled                          *bool                   `json:"enabled"`
}

func (c Client) AllowsRedirectURI(candidate string) bool {
	parsed, err := url.Parse(candidate)
	if err != nil || !parsed.IsAbs() || parsed.Fragment != "" {
		return false
	}
	return slices.Contains(c.RedirectURIs, candidate)
}

func (c Client) AllowsPostLogoutRedirectURI(candidate string) bool {
	parsed, err := url.Parse(candidate)
	if err != nil || !parsed.IsAbs() || parsed.Fragment != "" {
		return false
	}
	return slices.Contains(c.PostLogoutRedirectURIs, candidate)
}

func (c Client) AllowsIntrospectionBy(candidate string) bool {
	return c.ID == candidate || slices.Contains(c.IntrospectableBy, candidate)
}

func (c Client) AccessTokenLifetime() time.Duration {
	return effectiveTokenLifetime(c.AccessTokenLifetimeSeconds, DefaultAccessTokenLifetime)
}

func (c Client) RefreshTokenLifetime() time.Duration {
	return effectiveTokenLifetime(c.RefreshTokenLifetimeSeconds, DefaultRefreshTokenLifetime)
}

func (c Client) DisplayName() string {
	if c.System != nil {
		return c.System.Name
	}
	return c.Name
}

func (c Client) DisplayDescription() string {
	if c.System != nil {
		return c.System.Description
	}
	return c.Description
}

func (c Client) DisplayFaviconURL() string {
	if c.System != nil {
		return c.System.FaviconURL
	}
	return c.FaviconURL
}

type Repository interface {
	ListSystems(context.Context) ([]System, error)
	FindSystem(context.Context, string) (System, error)
	CreateSystem(context.Context, System) (System, error)
	ReplaceSystem(context.Context, System) (System, error)
	DeleteSystem(context.Context, string) error
	List(context.Context) ([]Client, error)
	Find(context.Context, string) (Client, error)
	Create(context.Context, Client) (Client, error)
	Replace(context.Context, Client) (Client, error)
	RotateSecret(context.Context, string, []byte) (Client, error)
	Archive(context.Context, string, time.Time) error
	DeleteArchived(context.Context, string) error
}

type MemoryRepository struct {
	mu          sync.RWMutex
	systems     map[string]System
	systemOrder []string
	clients     map[string]Client
	order       []string
}

func NewMemoryRepository(clients ...Client) *MemoryRepository {
	repository := &MemoryRepository{
		systems:     make(map[string]System),
		systemOrder: make([]string, 0, len(clients)),
		clients:     make(map[string]Client),
		order:       make([]string, 0, len(clients)),
	}
	for _, item := range clients {
		item = withDefaultTokenLifetimes(item)
		item.SystemID = effectiveSystemID(item.SystemID, item.ID)
		repository.ensureSystem(item)
		repository.clients[item.ID] = clone(item)
		repository.order = append(repository.order, item.ID)
	}
	return repository
}

func (r *MemoryRepository) ListSystems(_ context.Context) ([]System, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]System, 0, len(r.systemOrder))
	for _, id := range r.systemOrder {
		result = append(result, r.systems[id])
	}
	return result, nil
}

func (r *MemoryRepository) FindSystem(_ context.Context, id string) (System, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	item, ok := r.systems[id]
	if !ok {
		return System{}, ErrSystemNotFound
	}
	return item, nil
}

func (r *MemoryRepository) CreateSystem(_ context.Context, item System) (System, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.systems[item.ID]; exists {
		return System{}, ErrSystemConflict
	}
	r.systems[item.ID] = item
	r.systemOrder = append(r.systemOrder, item.ID)
	return item, nil
}

func (r *MemoryRepository) ReplaceSystem(_ context.Context, item System) (System, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.systems[item.ID]; !exists {
		return System{}, ErrSystemNotFound
	}
	r.systems[item.ID] = item
	return item, nil
}

func (r *MemoryRepository) DeleteSystem(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.systems[id]; !exists {
		return ErrSystemNotFound
	}
	for _, item := range r.clients {
		if item.SystemID == id {
			return ErrSystemInUse
		}
	}
	delete(r.systems, id)
	r.systemOrder = slices.DeleteFunc(r.systemOrder, func(candidate string) bool { return candidate == id })
	return nil
}

func (r *MemoryRepository) ensureSystem(item Client) {
	if _, exists := r.systems[item.SystemID]; exists {
		return
	}
	r.systems[item.SystemID] = systemFromClient(item)
	r.systemOrder = append(r.systemOrder, item.SystemID)
}

func (r *MemoryRepository) List(_ context.Context) ([]Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Client, 0, len(r.order))
	for _, id := range r.order {
		result = append(result, r.cloneWithSystem(r.clients[id]))
	}
	return result, nil
}

func (r *MemoryRepository) Find(_ context.Context, id string) (Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	item, ok := r.clients[id]
	if !ok {
		return Client{}, ErrNotFound
	}
	return r.cloneWithSystem(item), nil
}

func (r *MemoryRepository) Create(_ context.Context, item Client) (Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	item = withDefaultTokenLifetimes(item)
	item.SystemID = effectiveSystemID(item.SystemID, item.ID)
	if _, exists := r.clients[item.ID]; exists {
		return Client{}, ErrConflict
	}
	r.ensureSystem(item)
	r.clients[item.ID] = clone(item)
	r.order = append(r.order, item.ID)
	return r.cloneWithSystem(item), nil
}

func (r *MemoryRepository) Replace(_ context.Context, item Client) (Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	item = withDefaultTokenLifetimes(item)
	item.SystemID = effectiveSystemID(item.SystemID, item.ID)
	current, exists := r.clients[item.ID]
	if !exists {
		return Client{}, ErrNotFound
	}
	if current.ArchivedAt != nil {
		return Client{}, ErrArchived
	}
	r.clients[item.ID] = clone(item)
	return r.cloneWithSystem(item), nil
}

func (r *MemoryRepository) RotateSecret(_ context.Context, id string, hash []byte) (Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	item, exists := r.clients[id]
	if !exists {
		return Client{}, ErrNotFound
	}
	if item.ArchivedAt != nil {
		return Client{}, ErrArchived
	}
	item.SecretHash = append([]byte(nil), hash...)
	r.clients[id] = item
	return r.cloneWithSystem(item), nil
}

func (r *MemoryRepository) Archive(_ context.Context, id string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	item, exists := r.clients[id]
	if !exists {
		return ErrNotFound
	}
	if item.ArchivedAt == nil {
		value := now.UTC()
		item.ArchivedAt = &value
		item.Enabled = false
		r.clients[id] = item
	}
	return nil
}

func (r *MemoryRepository) DeleteArchived(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	item, exists := r.clients[id]
	if !exists {
		return ErrNotFound
	}
	if item.ArchivedAt == nil {
		return ErrNotArchived
	}
	delete(r.clients, id)
	r.order = slices.DeleteFunc(r.order, func(candidate string) bool { return candidate == id })
	for otherID, other := range r.clients {
		if slices.Contains(other.IntrospectableBy, id) {
			other.IntrospectableBy = slices.DeleteFunc(
				other.IntrospectableBy,
				func(candidate string) bool { return candidate == id },
			)
			r.clients[otherID] = other
		}
	}
	return nil
}

func clone(item Client) Client {
	if item.System != nil {
		value := *item.System
		item.System = &value
	}
	item.RedirectURIs = slices.Clone(item.RedirectURIs)
	item.PostLogoutRedirectURIs = slices.Clone(item.PostLogoutRedirectURIs)
	item.LoginMethods = slices.Clone(item.LoginMethods)
	item.IdentitySourceIDs = slices.Clone(item.IdentitySourceIDs)
	item.IntrospectableBy = slices.Clone(item.IntrospectableBy)
	item.AllowedScopes = slices.Clone(item.AllowedScopes)
	item.Protocols = slices.Clone(item.Protocols)
	item.GrantTypes = slices.Clone(item.GrantTypes)
	item.CASServiceURLs = slices.Clone(item.CASServiceURLs)
	item.SecretHash = slices.Clone(item.SecretHash)
	if item.ArchivedAt != nil {
		value := *item.ArchivedAt
		item.ArchivedAt = &value
	}
	return item
}

func (r *MemoryRepository) cloneWithSystem(item Client) Client {
	result := clone(item)
	if system, exists := r.systems[item.SystemID]; exists {
		value := system
		result.System = &value
	}
	return result
}

var clientIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,62}$`)
var scopePattern = regexp.MustCompile(`^[a-zA-Z0-9._:/-]{1,64}$`)

func New(input CreateClient) (Client, string, error) {
	clientID := strings.ToLower(strings.TrimSpace(input.ID))
	item := Client{
		ID:                               clientID,
		SystemID:                         effectiveSystemID(input.SystemID, clientID),
		Name:                             strings.TrimSpace(input.Name),
		Description:                      strings.TrimSpace(input.Description),
		FaviconURL:                       strings.TrimSpace(input.FaviconURL),
		LaunchURI:                        strings.TrimSpace(input.LaunchURI),
		ApplicationType:                  input.ApplicationType,
		TokenEndpointAuthMethod:          input.TokenEndpointAuthMethod,
		Protocols:                        uniqueProtocols(input.Protocols),
		GrantTypes:                       uniqueGrantTypes(input.GrantTypes),
		RedirectURIs:                     uniqueStrings(input.RedirectURIs),
		PostLogoutRedirectURIs:           uniqueStrings(input.PostLogoutRedirectURIs),
		BackchannelLogoutURI:             strings.TrimSpace(input.BackchannelLogoutURI),
		BackchannelLogoutSessionRequired: input.BackchannelLogoutSessionRequired,
		LoginMethods:                     uniqueMethods(input.LoginMethods),
		IdentitySourceIDs:                uniqueSourceIDs(input.IdentitySourceIDs),
		IntrospectableBy:                 uniqueClientIDs(input.IntrospectableBy),
		AllowedScopes:                    uniqueStrings(input.AllowedScopes),
		AccessTokenLifetimeSeconds:       normalizedTokenLifetimeSeconds(input.AccessTokenLifetimeSeconds, DefaultAccessTokenLifetime),
		RefreshTokenLifetimeSeconds:      normalizedTokenLifetimeSeconds(input.RefreshTokenLifetimeSeconds, DefaultRefreshTokenLifetime),
		CASVersion:                       input.CASVersion,
		CASServiceURLs:                   uniqueStrings(input.CASServiceURLs),
		CASProxy:                         input.CASProxy,
		CASGateway:                       input.CASGateway,
		CASRenew:                         input.CASRenew,
		CASSingleLogout:                  input.CASSingleLogout,
		Enabled:                          true,
	}
	if input.Enabled != nil {
		item.Enabled = *input.Enabled
	}
	if item.ApplicationType == "" {
		item.ApplicationType = ApplicationPublic
	}
	if item.TokenEndpointAuthMethod == "" {
		item.TokenEndpointAuthMethod = defaultTokenEndpointAuthMethod(item.ApplicationType)
	}
	if len(item.Protocols) == 0 {
		item.Protocols = []Protocol{ProtocolOAuth21}
	}
	if item.SupportsOAuth() && len(item.GrantTypes) == 0 {
		item.GrantTypes = []GrantType{GrantAuthorizationCode, GrantRefreshToken}
	}
	if item.SupportsProtocol(ProtocolCAS) && item.CASVersion == "" {
		item.CASVersion = CASVersion3
	}
	if len(item.AllowedScopes) == 0 {
		item.AllowedScopes = []string{"openid", "profile", "email"}
	}
	if err := item.Validate(); err != nil {
		return Client{}, "", err
	}
	if item.ApplicationType == ApplicationPublic {
		return item, "", nil
	}
	secret, hash, err := newSecret()
	if err != nil {
		return Client{}, "", fmt.Errorf("generate client secret: %w", err)
	}
	item.SecretHash = hash
	return item, secret, nil
}

func Replace(current Client, input ReplaceClient) (Client, error) {
	if current.ArchivedAt != nil {
		return Client{}, ErrArchived
	}
	enabled := current.Enabled
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	accessTokenLifetimeSeconds := input.AccessTokenLifetimeSeconds
	if accessTokenLifetimeSeconds == 0 {
		accessTokenLifetimeSeconds = normalizedTokenLifetimeSeconds(
			current.AccessTokenLifetimeSeconds,
			DefaultAccessTokenLifetime,
		)
	}
	refreshTokenLifetimeSeconds := input.RefreshTokenLifetimeSeconds
	if refreshTokenLifetimeSeconds == 0 {
		refreshTokenLifetimeSeconds = normalizedTokenLifetimeSeconds(
			current.RefreshTokenLifetimeSeconds,
			DefaultRefreshTokenLifetime,
		)
	}
	item := Client{
		ID:                               current.ID,
		SystemID:                         effectiveSystemID(input.SystemID, current.SystemID),
		Name:                             strings.TrimSpace(input.Name),
		Description:                      strings.TrimSpace(input.Description),
		FaviconURL:                       strings.TrimSpace(input.FaviconURL),
		LaunchURI:                        strings.TrimSpace(input.LaunchURI),
		ApplicationType:                  current.ApplicationType,
		TokenEndpointAuthMethod:          input.TokenEndpointAuthMethod,
		Protocols:                        uniqueProtocols(input.Protocols),
		GrantTypes:                       uniqueGrantTypes(input.GrantTypes),
		RedirectURIs:                     uniqueStrings(input.RedirectURIs),
		PostLogoutRedirectURIs:           uniqueStrings(input.PostLogoutRedirectURIs),
		BackchannelLogoutURI:             strings.TrimSpace(input.BackchannelLogoutURI),
		BackchannelLogoutSessionRequired: input.BackchannelLogoutSessionRequired,
		LoginMethods:                     uniqueMethods(input.LoginMethods),
		IdentitySourceIDs:                uniqueSourceIDs(input.IdentitySourceIDs),
		IntrospectableBy:                 uniqueClientIDs(input.IntrospectableBy),
		AllowedScopes:                    uniqueStrings(input.AllowedScopes),
		AccessTokenLifetimeSeconds:       accessTokenLifetimeSeconds,
		RefreshTokenLifetimeSeconds:      refreshTokenLifetimeSeconds,
		CASVersion:                       input.CASVersion,
		CASServiceURLs:                   uniqueStrings(input.CASServiceURLs),
		CASProxy:                         input.CASProxy,
		CASGateway:                       input.CASGateway,
		CASRenew:                         input.CASRenew,
		CASSingleLogout:                  input.CASSingleLogout,
		Enabled:                          enabled,
		SecretHash:                       slices.Clone(current.SecretHash),
	}
	if item.TokenEndpointAuthMethod == "" {
		item.TokenEndpointAuthMethod = defaultTokenEndpointAuthMethod(item.ApplicationType)
	}
	if item.SupportsOAuth() && len(item.GrantTypes) == 0 {
		item.GrantTypes = []GrantType{GrantAuthorizationCode, GrantRefreshToken}
	}
	if item.SupportsProtocol(ProtocolCAS) && item.CASVersion == "" {
		item.CASVersion = CASVersion3
	}
	if len(item.AllowedScopes) == 0 {
		item.AllowedScopes = []string{"openid", "profile", "email"}
	}
	if err := item.Validate(); err != nil {
		return Client{}, err
	}
	return item, nil
}

func RotateSecret(current Client) (Client, string, error) {
	if current.ArchivedAt != nil {
		return Client{}, "", ErrArchived
	}
	if current.ApplicationType != ApplicationConfidential {
		return Client{}, "", fmt.Errorf("%w: only confidential clients have secrets", ErrInvalid)
	}
	secret, hash, err := newSecret()
	if err != nil {
		return Client{}, "", fmt.Errorf("generate client secret: %w", err)
	}
	current.SecretHash = hash
	return current, secret, nil
}

func (c Client) Validate() error {
	if !clientIDPattern.MatchString(c.ID) {
		return fmt.Errorf("%w: id must be 2-63 lowercase letters, digits, underscores or hyphens", ErrInvalid)
	}
	if !clientIDPattern.MatchString(c.SystemID) {
		return fmt.Errorf("%w: system_id must be 2-63 lowercase letters, digits, underscores or hyphens", ErrInvalid)
	}
	if c.Name == "" || len([]rune(c.Name)) > 128 {
		return fmt.Errorf("%w: name must be 1-128 characters", ErrInvalid)
	}
	if c.FaviconURL != "" && (len(c.FaviconURL) > 2048 || !validEndpointURL(c.FaviconURL)) {
		return fmt.Errorf("%w: favicon_url must be an absolute HTTPS URL (HTTP is allowed only for loopback hosts)", ErrInvalid)
	}
	if c.LaunchURI != "" && (len(c.LaunchURI) > 2048 || !validEndpointURL(c.LaunchURI)) {
		return fmt.Errorf("%w: launch_uri must be an absolute HTTPS URL (HTTP is allowed only for loopback hosts)", ErrInvalid)
	}
	if c.ApplicationType != ApplicationPublic && c.ApplicationType != ApplicationConfidential {
		return fmt.Errorf("%w: unsupported application_type", ErrInvalid)
	}
	switch c.ApplicationType {
	case ApplicationPublic:
		if c.TokenEndpointAuthMethod != TokenEndpointAuthNone {
			return fmt.Errorf("%w: public clients require token_endpoint_auth_method none", ErrInvalid)
		}
	case ApplicationConfidential:
		if c.TokenEndpointAuthMethod != TokenEndpointAuthSecretBasic &&
			c.TokenEndpointAuthMethod != TokenEndpointAuthSecretPost {
			return fmt.Errorf("%w: confidential clients require client_secret_basic or client_secret_post", ErrInvalid)
		}
	}
	if len(c.Protocols) == 0 {
		return fmt.Errorf("%w: at least one protocol is required", ErrInvalid)
	}
	for _, protocol := range c.Protocols {
		if protocol != ProtocolOAuth20 && protocol != ProtocolOAuth21 && protocol != ProtocolCAS {
			return fmt.Errorf("%w: unsupported protocol %q", ErrInvalid, protocol)
		}
	}
	if c.SupportsOAuth() {
		if len(c.GrantTypes) == 0 {
			return fmt.Errorf("%w: OAuth clients require grant_types", ErrInvalid)
		}
		for _, grant := range c.GrantTypes {
			switch grant {
			case GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials, GrantDeviceCode:
			default:
				return fmt.Errorf("%w: unsupported or unsafe grant_type %q", ErrInvalid, grant)
			}
		}
		if c.SupportsGrant(GrantClientCredentials) && c.ApplicationType != ApplicationConfidential {
			return fmt.Errorf("%w: client_credentials requires a confidential client", ErrInvalid)
		}
		if c.SupportsGrant(GrantRefreshToken) &&
			!c.SupportsGrant(GrantAuthorizationCode) &&
			!c.SupportsGrant(GrantDeviceCode) {
			return fmt.Errorf("%w: refresh_token requires authorization_code or device_code", ErrInvalid)
		}
		if c.SupportsGrant(GrantAuthorizationCode) && len(c.RedirectURIs) == 0 {
			return fmt.Errorf("%w: authorization_code requires redirect_uris", ErrInvalid)
		}
	}
	if len(c.RedirectURIs) > 20 {
		return fmt.Errorf("%w: redirect_uris supports at most 20 entries", ErrInvalid)
	}
	for _, redirectURI := range c.RedirectURIs {
		if !validEndpointURL(redirectURI) {
			return fmt.Errorf("%w: invalid redirect_uri %q", ErrInvalid, redirectURI)
		}
	}
	if len(c.PostLogoutRedirectURIs) > 20 {
		return fmt.Errorf("%w: post_logout_redirect_uris supports at most 20 entries", ErrInvalid)
	}
	if len(c.PostLogoutRedirectURIs) > 0 && !c.SupportsOAuth() {
		return fmt.Errorf("%w: post_logout_redirect_uris require OAuth/OIDC", ErrInvalid)
	}
	for _, redirectURI := range c.PostLogoutRedirectURIs {
		if !validEndpointURL(redirectURI) {
			return fmt.Errorf("%w: invalid post_logout_redirect_uri %q", ErrInvalid, redirectURI)
		}
	}
	if c.BackchannelLogoutURI != "" {
		if !c.SupportsOAuth() {
			return fmt.Errorf("%w: backchannel_logout_uri requires OAuth/OIDC", ErrInvalid)
		}
		if !validEndpointURL(c.BackchannelLogoutURI) {
			return fmt.Errorf("%w: invalid backchannel_logout_uri %q", ErrInvalid, c.BackchannelLogoutURI)
		}
	} else if c.BackchannelLogoutSessionRequired {
		return fmt.Errorf("%w: backchannel_logout_session_required requires backchannel_logout_uri", ErrInvalid)
	}
	interactive := c.SupportsProtocol(ProtocolCAS) ||
		c.SupportsGrant(GrantAuthorizationCode) ||
		c.SupportsGrant(GrantDeviceCode)
	if interactive && len(c.LoginMethods) == 0 {
		return fmt.Errorf("%w: at least one login_method is required", ErrInvalid)
	}
	for _, method := range c.LoginMethods {
		if method != LoginPassword && method != LoginLDAP && method != LoginOIDC {
			return fmt.Errorf("%w: unsupported login_method %q", ErrInvalid, method)
		}
	}
	if len(c.IdentitySourceIDs) > 20 {
		return fmt.Errorf("%w: identity_source_ids supports at most 20 entries", ErrInvalid)
	}
	if len(c.IdentitySourceIDs) > 0 &&
		!slices.Contains(c.LoginMethods, LoginLDAP) &&
		!slices.Contains(c.LoginMethods, LoginOIDC) {
		return fmt.Errorf("%w: identity_source_ids require ldap or oidc login methods", ErrInvalid)
	}
	for _, sourceID := range c.IdentitySourceIDs {
		if !clientIDPattern.MatchString(sourceID) {
			return fmt.Errorf("%w: invalid identity_source_id %q", ErrInvalid, sourceID)
		}
	}
	if len(c.IntrospectableBy) > 20 {
		return fmt.Errorf("%w: introspectable_by supports at most 20 entries", ErrInvalid)
	}
	if len(c.IntrospectableBy) > 0 && !c.SupportsOAuth() {
		return fmt.Errorf("%w: introspectable_by requires OAuth/OIDC", ErrInvalid)
	}
	for _, introspectorID := range c.IntrospectableBy {
		if !clientIDPattern.MatchString(introspectorID) {
			return fmt.Errorf("%w: invalid introspectable_by client id %q", ErrInvalid, introspectorID)
		}
		if introspectorID == c.ID {
			return fmt.Errorf("%w: introspectable_by must not contain the issuing client", ErrInvalid)
		}
	}
	for _, scope := range c.AllowedScopes {
		if !scopePattern.MatchString(scope) {
			return fmt.Errorf("%w: invalid scope %q", ErrInvalid, scope)
		}
	}
	if err := validateTokenLifetime(
		"access_token_lifetime_seconds",
		c.AccessTokenLifetimeSeconds,
		MinAccessTokenLifetime,
		MaxAccessTokenLifetime,
	); err != nil {
		return err
	}
	if err := validateTokenLifetime(
		"refresh_token_lifetime_seconds",
		c.RefreshTokenLifetimeSeconds,
		MinRefreshTokenLifetime,
		MaxRefreshTokenLifetime,
	); err != nil {
		return err
	}
	if c.RefreshTokenLifetime() < c.AccessTokenLifetime() {
		return fmt.Errorf("%w: refresh_token_lifetime_seconds must not be shorter than access_token_lifetime_seconds", ErrInvalid)
	}
	if c.SupportsProtocol(ProtocolCAS) {
		if c.CASVersion != CASVersion1 && c.CASVersion != CASVersion2 && c.CASVersion != CASVersion3 {
			return fmt.Errorf("%w: unsupported cas_version", ErrInvalid)
		}
		if len(c.CASServiceURLs) == 0 || len(c.CASServiceURLs) > 20 {
			return fmt.Errorf("%w: CAS requires 1-20 cas_service_urls", ErrInvalid)
		}
		for _, serviceURL := range c.CASServiceURLs {
			if !validEndpointURL(serviceURL) {
				return fmt.Errorf("%w: invalid CAS service URL %q", ErrInvalid, serviceURL)
			}
		}
		if c.CASProxy && c.CASVersion == CASVersion1 {
			return fmt.Errorf("%w: CAS proxy requires version 2.0 or 3.0", ErrInvalid)
		}
	}
	return nil
}

func (c Client) SupportsProtocol(protocol Protocol) bool {
	return slices.Contains(c.Protocols, protocol)
}

func (c Client) SupportsOAuth() bool {
	return c.SupportsProtocol(ProtocolOAuth20) || c.SupportsProtocol(ProtocolOAuth21)
}

func (c Client) SupportsGrant(grant GrantType) bool {
	return slices.Contains(c.GrantTypes, grant)
}

func (c Client) EffectiveTokenEndpointAuthMethod() TokenEndpointAuthMethod {
	if c.TokenEndpointAuthMethod == "" {
		return defaultTokenEndpointAuthMethod(c.ApplicationType)
	}
	return c.TokenEndpointAuthMethod
}

func defaultTokenEndpointAuthMethod(applicationType ApplicationType) TokenEndpointAuthMethod {
	if applicationType == ApplicationConfidential {
		return TokenEndpointAuthSecretBasic
	}
	return TokenEndpointAuthNone
}

func normalizedTokenLifetimeSeconds(value int64, fallback time.Duration) int64 {
	if value == 0 {
		return int64(fallback / time.Second)
	}
	return value
}

func NewSystem(input CreateSystem) (System, error) {
	portalVisible := true
	if input.PortalVisible != nil {
		portalVisible = *input.PortalVisible
	}
	item := System{
		ID:            strings.ToLower(strings.TrimSpace(input.ID)),
		Name:          strings.TrimSpace(input.Name),
		Description:   strings.TrimSpace(input.Description),
		FaviconURL:    strings.TrimSpace(input.FaviconURL),
		LaunchURI:     strings.TrimSpace(input.LaunchURI),
		PortalVisible: portalVisible,
	}
	if err := item.Validate(); err != nil {
		return System{}, err
	}
	return item, nil
}

func ReplaceSystem(current System, input ReplaceSystemInput) (System, error) {
	item := System{
		ID:            current.ID,
		Name:          strings.TrimSpace(input.Name),
		Description:   strings.TrimSpace(input.Description),
		FaviconURL:    strings.TrimSpace(input.FaviconURL),
		LaunchURI:     strings.TrimSpace(input.LaunchURI),
		PortalVisible: input.PortalVisible,
	}
	if err := item.Validate(); err != nil {
		return System{}, err
	}
	return item, nil
}

func (s System) Validate() error {
	if !clientIDPattern.MatchString(s.ID) {
		return fmt.Errorf("%w: system id must be 2-63 lowercase letters, digits, underscores or hyphens", ErrInvalid)
	}
	if s.Name == "" || len([]rune(s.Name)) > 128 {
		return fmt.Errorf("%w: system name must be 1-128 characters", ErrInvalid)
	}
	if len([]rune(s.Description)) > 512 {
		return fmt.Errorf("%w: system description must not exceed 512 characters", ErrInvalid)
	}
	if s.FaviconURL != "" && (len(s.FaviconURL) > 2048 || !validEndpointURL(s.FaviconURL)) {
		return fmt.Errorf("%w: system favicon_url must be an absolute HTTPS URL (HTTP is allowed only for loopback hosts)", ErrInvalid)
	}
	if s.LaunchURI != "" && (len(s.LaunchURI) > 2048 || !validEndpointURL(s.LaunchURI)) {
		return fmt.Errorf("%w: system launch_uri must be an absolute HTTPS URL (HTTP is allowed only for loopback hosts)", ErrInvalid)
	}
	return nil
}

func effectiveSystemID(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return strings.ToLower(strings.TrimSpace(fallback))
	}
	return value
}

func systemFromClient(item Client) System {
	return System{
		ID:            effectiveSystemID(item.SystemID, item.ID),
		Name:          item.Name,
		Description:   item.Description,
		FaviconURL:    item.FaviconURL,
		LaunchURI:     item.LaunchURI,
		PortalVisible: item.LaunchURI != "",
	}
}

func withDefaultTokenLifetimes(item Client) Client {
	item.AccessTokenLifetimeSeconds = normalizedTokenLifetimeSeconds(
		item.AccessTokenLifetimeSeconds,
		DefaultAccessTokenLifetime,
	)
	item.RefreshTokenLifetimeSeconds = normalizedTokenLifetimeSeconds(
		item.RefreshTokenLifetimeSeconds,
		DefaultRefreshTokenLifetime,
	)
	return item
}

func effectiveTokenLifetime(value int64, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return time.Duration(value) * time.Second
}

func validateTokenLifetime(name string, value int64, minimum, maximum time.Duration) error {
	if value == 0 {
		return nil
	}
	minimumSeconds := int64(minimum / time.Second)
	maximumSeconds := int64(maximum / time.Second)
	if value < minimumSeconds || value > maximumSeconds {
		return fmt.Errorf(
			"%w: %s must be between %d and %d seconds",
			ErrInvalid,
			name,
			minimumSeconds,
			maximumSeconds,
		)
	}
	return nil
}

func validEndpointURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.Fragment != "" || parsed.User != nil {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	hostname := parsed.Hostname()
	ip := net.ParseIP(hostname)
	return strings.EqualFold(hostname, "localhost") || (ip != nil && ip.IsLoopback())
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func uniqueMethods(values []LoginMethod) []LoginMethod {
	result := make([]LoginMethod, 0, len(values))
	seen := make(map[LoginMethod]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func uniqueSourceIDs(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func uniqueClientIDs(values []string) []string {
	return uniqueSourceIDs(values)
}

func uniqueProtocols(values []Protocol) []Protocol {
	result := make([]Protocol, 0, len(values))
	seen := make(map[Protocol]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func uniqueGrantTypes(values []GrantType) []GrantType {
	result := make([]GrantType, 0, len(values))
	seen := make(map[GrantType]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func newSecret() (string, []byte, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", nil, err
	}
	secret := base64.RawURLEncoding.EncodeToString(value)
	hash := sha256.Sum256([]byte(secret))
	return secret, hash[:], nil
}
