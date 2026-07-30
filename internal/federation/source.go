package federation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"certus/internal/secrets"
)

var (
	ErrSourceNotFound              = errors.New("identity source not found")
	ErrSourceConflict              = errors.New("identity source already exists")
	ErrSourceArchived              = errors.New("identity source is archived")
	ErrSourceDisabled              = errors.New("identity source is disabled")
	ErrInvalidSource               = errors.New("invalid identity source")
	ErrSourceEncryptionUnavailable = errors.New("identity source encryption is unavailable")
)

const sourceSecretPurpose = "identity-source-credential"

type SourceType string

const (
	SourceLDAP SourceType = "ldap"
	SourceOIDC SourceType = "oidc"
)

type LDAPSource struct {
	URL                  string `json:"url"`
	StartTLS             bool   `json:"start_tls"`
	BaseDN               string `json:"base_dn"`
	BindDN               string `json:"bind_dn,omitempty"`
	UserFilter           string `json:"user_filter"`
	UsernameAttribute    string `json:"username_attribute"`
	DisplayNameAttribute string `json:"display_name_attribute"`
	EmailAttribute       string `json:"email_attribute"`
}

type OIDCSource struct {
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

type Source struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	Type             SourceType  `json:"type"`
	Enabled          bool        `json:"enabled"`
	LDAP             *LDAPSource `json:"ldap,omitempty"`
	OIDC             *OIDCSource `json:"oidc,omitempty"`
	SecretConfigured bool        `json:"secret_configured"`
	CreatedAt        time.Time   `json:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"`
	ArchivedAt       *time.Time  `json:"archived_at,omitempty"`

	SecretCiphertext []byte `json:"-"`
	SecretKeyID      string `json:"-"`
}

type LDAPSourceInput struct {
	URL                  string `json:"url"`
	StartTLS             bool   `json:"start_tls"`
	BaseDN               string `json:"base_dn"`
	BindDN               string `json:"bind_dn"`
	BindPassword         string `json:"bind_password"`
	UserFilter           string `json:"user_filter"`
	UsernameAttribute    string `json:"username_attribute"`
	DisplayNameAttribute string `json:"display_name_attribute"`
	EmailAttribute       string `json:"email_attribute"`
}

type OIDCSourceInput struct {
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
}

type CreateSource struct {
	ID      string           `json:"id"`
	Name    string           `json:"name"`
	Type    SourceType       `json:"type"`
	Enabled *bool            `json:"enabled"`
	LDAP    *LDAPSourceInput `json:"ldap"`
	OIDC    *OIDCSourceInput `json:"oidc"`
}

type ReplaceSource struct {
	Name        string           `json:"name"`
	Enabled     *bool            `json:"enabled"`
	ClearSecret bool             `json:"clear_secret"`
	LDAP        *LDAPSourceInput `json:"ldap"`
	OIDC        *OIDCSourceInput `json:"oidc"`
}

type SourceRepository interface {
	List(context.Context) ([]Source, error)
	Find(context.Context, string) (Source, error)
	Create(context.Context, Source) (Source, error)
	Replace(context.Context, Source) (Source, error)
	Archive(context.Context, string, time.Time) error
}

type SourceSecretRecord struct {
	ID         string
	Ciphertext []byte
	KeyID      string
}

type SourceSecretRepository interface {
	ListSourceSecretCiphertexts(context.Context) ([]SourceSecretRecord, error)
	ReplaceSourceSecretCiphertext(context.Context, string, []byte, []byte, string) (bool, error)
}

type MemorySourceRepository struct {
	mu      sync.RWMutex
	sources map[string]Source
	order   []string
}

func NewMemorySourceRepository(sources ...Source) *MemorySourceRepository {
	repository := &MemorySourceRepository{
		sources: make(map[string]Source, len(sources)),
		order:   make([]string, 0, len(sources)),
	}
	for _, source := range sources {
		source = cloneSource(source)
		repository.sources[source.ID] = source
		repository.order = append(repository.order, source.ID)
	}
	return repository
}

func (r *MemorySourceRepository) List(context.Context) ([]Source, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Source, 0, len(r.order))
	for _, id := range r.order {
		result = append(result, cloneSource(r.sources[id]))
	}
	return result, nil
}

func (r *MemorySourceRepository) Find(_ context.Context, id string) (Source, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	source, ok := r.sources[id]
	if !ok {
		return Source{}, ErrSourceNotFound
	}
	return cloneSource(source), nil
}

func (r *MemorySourceRepository) Create(_ context.Context, source Source) (Source, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.sources[source.ID]; exists {
		return Source{}, ErrSourceConflict
	}
	r.sources[source.ID] = cloneSource(source)
	r.order = append(r.order, source.ID)
	return cloneSource(source), nil
}

func (r *MemorySourceRepository) Replace(_ context.Context, source Source) (Source, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.sources[source.ID]
	if !exists {
		return Source{}, ErrSourceNotFound
	}
	if current.ArchivedAt != nil {
		return Source{}, ErrSourceArchived
	}
	r.sources[source.ID] = cloneSource(source)
	return cloneSource(source), nil
}

func (r *MemorySourceRepository) Archive(_ context.Context, id string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	source, exists := r.sources[id]
	if !exists {
		return ErrSourceNotFound
	}
	if source.ArchivedAt == nil {
		value := now.UTC()
		source.ArchivedAt = &value
		source.Enabled = false
		source.UpdatedAt = value
		r.sources[id] = source
	}
	return nil
}

func (r *MemorySourceRepository) ListSourceSecretCiphertexts(context.Context) ([]SourceSecretRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]SourceSecretRecord, 0)
	for _, id := range r.order {
		source := r.sources[id]
		if len(source.SecretCiphertext) == 0 {
			continue
		}
		result = append(result, SourceSecretRecord{
			ID:         source.ID,
			Ciphertext: slices.Clone(source.SecretCiphertext),
			KeyID:      source.SecretKeyID,
		})
	}
	return result, nil
}

func (r *MemorySourceRepository) ReplaceSourceSecretCiphertext(
	_ context.Context,
	id string,
	current, replacement []byte,
	keyID string,
) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	source, exists := r.sources[id]
	if !exists {
		return false, ErrSourceNotFound
	}
	if !slices.Equal(source.SecretCiphertext, current) {
		return false, nil
	}
	source.SecretCiphertext = slices.Clone(replacement)
	source.SecretKeyID = keyID
	source.SecretConfigured = len(replacement) > 0
	r.sources[id] = source
	return true, nil
}

type SourceService struct {
	repository SourceRepository
	keyRing    secrets.KeyRing
	now        func() time.Time
}

func NewSourceService(repository SourceRepository, keyRing secrets.KeyRing) *SourceService {
	return &SourceService{repository: repository, keyRing: keyRing, now: time.Now}
}

func (s *SourceService) List(ctx context.Context) ([]Source, error) {
	return s.repository.List(ctx)
}

func (s *SourceService) Find(ctx context.Context, id string) (Source, error) {
	return s.repository.Find(ctx, strings.TrimSpace(id))
}

func (s *SourceService) Create(ctx context.Context, input CreateSource) (Source, error) {
	now := s.now().UTC()
	source, secret, err := newSource(input, now)
	if err != nil {
		return Source{}, err
	}
	if secret != "" {
		source.SecretCiphertext, source.SecretKeyID, err = s.encrypt(source.ID, secret)
		if err != nil {
			return Source{}, err
		}
		source.SecretConfigured = true
	}
	return s.repository.Create(ctx, source)
}

func (s *SourceService) Replace(ctx context.Context, id string, input ReplaceSource) (Source, error) {
	current, err := s.repository.Find(ctx, strings.TrimSpace(id))
	if err != nil {
		return Source{}, err
	}
	source, secret, err := replaceSource(current, input, s.now().UTC())
	if err != nil {
		return Source{}, err
	}
	if secret != "" {
		source.SecretCiphertext, source.SecretKeyID, err = s.encrypt(source.ID, secret)
		if err != nil {
			return Source{}, err
		}
		source.SecretConfigured = true
	}
	return s.repository.Replace(ctx, source)
}

func (s *SourceService) Archive(ctx context.Context, id string) error {
	return s.repository.Archive(ctx, strings.TrimSpace(id), s.now().UTC())
}

func (s *SourceService) LDAPAuthenticator(ctx context.Context, id string) (*LDAPAuthenticator, error) {
	source, secret, err := s.activeSource(ctx, id, SourceLDAP)
	if err != nil {
		return nil, err
	}
	return NewLDAPAuthenticator(LDAPConfig{
		ProviderID:           "identity-source:" + source.ID,
		Label:                source.Name,
		URL:                  source.LDAP.URL,
		StartTLS:             source.LDAP.StartTLS,
		BaseDN:               source.LDAP.BaseDN,
		BindDN:               source.LDAP.BindDN,
		BindPassword:         secret,
		UserFilter:           source.LDAP.UserFilter,
		UsernameAttribute:    source.LDAP.UsernameAttribute,
		DisplayNameAttribute: source.LDAP.DisplayNameAttribute,
		EmailAttribute:       source.LDAP.EmailAttribute,
	}), nil
}

func (s *SourceService) OIDCAuthenticator(
	ctx context.Context,
	id, redirectURL string,
	client *http.Client,
) (*OIDCAuthenticator, error) {
	source, secret, err := s.activeSource(ctx, id, SourceOIDC)
	if err != nil {
		return nil, err
	}
	return NewOIDCAuthenticator(ExternalOIDCConfig{
		ProviderID:   "identity-source:" + source.ID,
		Issuer:       source.OIDC.Issuer,
		ClientID:     source.OIDC.ClientID,
		ClientSecret: secret,
		Label:        source.Name,
		Scopes:       slices.Clone(source.OIDC.Scopes),
	}, redirectURL, client), nil
}

func (s *SourceService) Probe(
	ctx context.Context,
	id, redirectURL string,
	client *http.Client,
) error {
	source, err := s.Find(ctx, id)
	if err != nil {
		return err
	}
	if source.ArchivedAt != nil {
		return ErrSourceArchived
	}
	switch source.Type {
	case SourceLDAP:
		authenticator, err := s.LDAPAuthenticator(ctx, id)
		if err != nil {
			return err
		}
		return authenticator.Probe(ctx)
	case SourceOIDC:
		authenticator, err := s.OIDCAuthenticator(ctx, id, redirectURL, client)
		if err != nil {
			return err
		}
		return authenticator.Probe(ctx)
	default:
		return ErrInvalidSource
	}
}

func (s *SourceService) activeSource(
	ctx context.Context,
	id string,
	expected SourceType,
) (Source, string, error) {
	source, err := s.Find(ctx, id)
	if err != nil {
		return Source{}, "", err
	}
	if source.ArchivedAt != nil {
		return Source{}, "", ErrSourceArchived
	}
	if !source.Enabled {
		return Source{}, "", ErrSourceDisabled
	}
	if source.Type != expected {
		return Source{}, "", fmt.Errorf("%w: source type is %s", ErrInvalidSource, source.Type)
	}
	secret, err := s.decrypt(source)
	if err != nil {
		return Source{}, "", err
	}
	return source, secret, nil
}

func (s *SourceService) encrypt(id, plaintext string) ([]byte, string, error) {
	if !s.keyRing.Available() {
		return nil, "", ErrSourceEncryptionUnavailable
	}
	ciphertext, keyID, err := s.keyRing.Encrypt(sourceSecretPurpose, id, []byte(plaintext))
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrSourceEncryptionUnavailable, err)
	}
	return ciphertext, keyID, nil
}

func (s *SourceService) decrypt(source Source) (string, error) {
	if len(source.SecretCiphertext) == 0 {
		return "", nil
	}
	plaintext, err := s.keyRing.Decrypt(
		sourceSecretPurpose,
		source.ID,
		source.SecretCiphertext,
		source.SecretKeyID,
	)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSourceEncryptionUnavailable, err)
	}
	return string(plaintext), nil
}

func RewrapSourceSecrets(
	ctx context.Context,
	repository SourceSecretRepository,
	keyRing secrets.KeyRing,
) (int, error) {
	records, err := repository.ListSourceSecretCiphertexts(ctx)
	if err != nil {
		return 0, err
	}
	if len(records) == 0 {
		return 0, nil
	}
	if !keyRing.Available() {
		return 0, ErrSourceEncryptionUnavailable
	}
	rewrapped := 0
	for _, record := range records {
		envelopeKeyID, valid := secrets.EnvelopeKeyID(record.Ciphertext)
		if !valid {
			return rewrapped, fmt.Errorf("%w: source %q has an invalid secret envelope", ErrSourceEncryptionUnavailable, record.ID)
		}
		if envelopeKeyID == keyRing.PrimaryID() && (record.KeyID == "" || record.KeyID == envelopeKeyID) {
			continue
		}
		plaintext, err := keyRing.Decrypt(
			sourceSecretPurpose,
			record.ID,
			record.Ciphertext,
			record.KeyID,
		)
		if err != nil {
			return rewrapped, fmt.Errorf("decrypt identity source %q: %w", record.ID, err)
		}
		replacement, keyID, err := keyRing.Encrypt(sourceSecretPurpose, record.ID, plaintext)
		if err != nil {
			return rewrapped, fmt.Errorf("encrypt identity source %q: %w", record.ID, err)
		}
		replaced, err := repository.ReplaceSourceSecretCiphertext(
			ctx,
			record.ID,
			record.Ciphertext,
			replacement,
			keyID,
		)
		if err != nil {
			return rewrapped, err
		}
		if replaced {
			rewrapped++
		}
	}
	return rewrapped, nil
}

func newSource(input CreateSource, now time.Time) (Source, string, error) {
	source := Source{
		ID:        strings.ToLower(strings.TrimSpace(input.ID)),
		Name:      strings.TrimSpace(input.Name),
		Type:      input.Type,
		Enabled:   true,
		CreatedAt: now.UTC(),
		UpdatedAt: now.UTC(),
	}
	if input.Enabled != nil {
		source.Enabled = *input.Enabled
	}
	secret, err := applySourceInput(&source, input.LDAP, input.OIDC, false)
	if err != nil {
		return Source{}, "", err
	}
	source.SecretConfigured = secret != ""
	if err := source.Validate(); err != nil {
		return Source{}, "", err
	}
	return source, secret, nil
}

func replaceSource(current Source, input ReplaceSource, now time.Time) (Source, string, error) {
	if current.ArchivedAt != nil {
		return Source{}, "", ErrSourceArchived
	}
	source := cloneSource(current)
	source.Name = strings.TrimSpace(input.Name)
	source.UpdatedAt = now.UTC()
	if input.Enabled != nil {
		source.Enabled = *input.Enabled
	}
	if input.ClearSecret {
		source.SecretCiphertext = nil
		source.SecretKeyID = ""
		source.SecretConfigured = false
	}
	secret, err := applySourceInput(&source, input.LDAP, input.OIDC, source.SecretConfigured)
	if err != nil {
		return Source{}, "", err
	}
	if secret != "" {
		source.SecretConfigured = true
	}
	if err := source.Validate(); err != nil {
		return Source{}, "", err
	}
	return source, secret, nil
}

func applySourceInput(
	source *Source,
	ldapInput *LDAPSourceInput,
	oidcInput *OIDCSourceInput,
	secretConfigured bool,
) (string, error) {
	validateSecret := func(secret string) (string, error) {
		if len(secret) > 16<<10 {
			return "", fmt.Errorf("%w: source secret is too large", ErrInvalidSource)
		}
		return secret, nil
	}
	switch source.Type {
	case SourceLDAP:
		if ldapInput == nil || oidcInput != nil {
			return "", fmt.Errorf("%w: ldap configuration is required only for LDAP sources", ErrInvalidSource)
		}
		source.LDAP = normalizeLDAPSource(*ldapInput)
		source.OIDC = nil
		secret := ldapInput.BindPassword
		if strings.TrimSpace(source.LDAP.BindDN) != "" && secret == "" && !secretConfigured {
			return "", fmt.Errorf("%w: bind_password is required with bind_dn", ErrInvalidSource)
		}
		if strings.TrimSpace(source.LDAP.BindDN) == "" && secret != "" {
			return "", fmt.Errorf("%w: bind_dn is required with bind_password", ErrInvalidSource)
		}
		return validateSecret(secret)
	case SourceOIDC:
		if oidcInput == nil || ldapInput != nil {
			return "", fmt.Errorf("%w: oidc configuration is required only for OIDC sources", ErrInvalidSource)
		}
		source.OIDC = normalizeOIDCSource(*oidcInput)
		source.LDAP = nil
		if oidcInput.ClientSecret == "" && !secretConfigured {
			return "", fmt.Errorf("%w: client_secret is required", ErrInvalidSource)
		}
		return validateSecret(oidcInput.ClientSecret)
	default:
		return "", fmt.Errorf("%w: unsupported source type %q", ErrInvalidSource, source.Type)
	}
}

func normalizeLDAPSource(input LDAPSourceInput) *LDAPSource {
	userFilter := strings.TrimSpace(input.UserFilter)
	if userFilter == "" {
		userFilter = "(uid={username})"
	}
	usernameAttribute := strings.TrimSpace(input.UsernameAttribute)
	if usernameAttribute == "" {
		usernameAttribute = "uid"
	}
	displayNameAttribute := strings.TrimSpace(input.DisplayNameAttribute)
	if displayNameAttribute == "" {
		displayNameAttribute = "displayName"
	}
	emailAttribute := strings.TrimSpace(input.EmailAttribute)
	if emailAttribute == "" {
		emailAttribute = "mail"
	}
	return &LDAPSource{
		URL:                  strings.TrimRight(strings.TrimSpace(input.URL), "/"),
		StartTLS:             input.StartTLS,
		BaseDN:               strings.TrimSpace(input.BaseDN),
		BindDN:               strings.TrimSpace(input.BindDN),
		UserFilter:           userFilter,
		UsernameAttribute:    usernameAttribute,
		DisplayNameAttribute: displayNameAttribute,
		EmailAttribute:       emailAttribute,
	}
}

func normalizeOIDCSource(input OIDCSourceInput) *OIDCSource {
	scopes := uniqueSourceStrings(input.Scopes)
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	return &OIDCSource{
		Issuer:   strings.TrimRight(strings.TrimSpace(input.Issuer), "/"),
		ClientID: strings.TrimSpace(input.ClientID),
		Scopes:   scopes,
	}
}

var sourceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,62}$`)
var oidcScopePattern = regexp.MustCompile(`^[\x21-\x7E]{1,128}$`)

func (s Source) Validate() error {
	if !sourceIDPattern.MatchString(s.ID) {
		return fmt.Errorf("%w: id must be 2-63 lowercase letters, digits, underscores or hyphens", ErrInvalidSource)
	}
	if s.Name == "" || len([]rune(s.Name)) > 128 {
		return fmt.Errorf("%w: name must be 1-128 characters", ErrInvalidSource)
	}
	switch s.Type {
	case SourceLDAP:
		if s.LDAP == nil || s.OIDC != nil {
			return fmt.Errorf("%w: LDAP source configuration is inconsistent", ErrInvalidSource)
		}
		endpoint, err := url.Parse(s.LDAP.URL)
		if err != nil || endpoint.Host == "" || (endpoint.Scheme != "ldap" && endpoint.Scheme != "ldaps") {
			return fmt.Errorf("%w: LDAP URL must use ldap:// or ldaps://", ErrInvalidSource)
		}
		if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return fmt.Errorf("%w: LDAP URL must not contain credentials, query or fragment", ErrInvalidSource)
		}
		if s.LDAP.StartTLS && endpoint.Scheme != "ldap" {
			return fmt.Errorf("%w: LDAP StartTLS is only valid with ldap://", ErrInvalidSource)
		}
		if s.LDAP.BaseDN == "" {
			return fmt.Errorf("%w: LDAP base_dn is required", ErrInvalidSource)
		}
		if !strings.Contains(s.LDAP.UserFilter, "{username}") {
			return fmt.Errorf("%w: LDAP user_filter must contain {username}", ErrInvalidSource)
		}
		for name, value := range map[string]string{
			"username_attribute":     s.LDAP.UsernameAttribute,
			"display_name_attribute": s.LDAP.DisplayNameAttribute,
			"email_attribute":        s.LDAP.EmailAttribute,
		} {
			if value == "" || len(value) > 128 {
				return fmt.Errorf("%w: LDAP %s must be 1-128 characters", ErrInvalidSource, name)
			}
		}
		if s.LDAP.BindDN != "" && !s.SecretConfigured {
			return fmt.Errorf("%w: LDAP bind password is required", ErrInvalidSource)
		}
		if s.LDAP.BindDN == "" && s.SecretConfigured {
			return fmt.Errorf("%w: LDAP bind_dn is required with a bind password", ErrInvalidSource)
		}
	case SourceOIDC:
		if s.OIDC == nil || s.LDAP != nil {
			return fmt.Errorf("%w: OIDC source configuration is inconsistent", ErrInvalidSource)
		}
		issuer, err := url.Parse(s.OIDC.Issuer)
		if err != nil || issuer.Scheme == "" || issuer.Host == "" ||
			issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
			return fmt.Errorf("%w: OIDC issuer must be an absolute URL without query or fragment", ErrInvalidSource)
		}
		if issuer.Scheme != "https" &&
			!(issuer.Scheme == "http" && isLoopbackHost(issuer.Hostname())) {
			return fmt.Errorf("%w: OIDC issuer must use HTTPS (HTTP is allowed only for loopback hosts)", ErrInvalidSource)
		}
		if s.OIDC.ClientID == "" || len(s.OIDC.ClientID) > 256 {
			return fmt.Errorf("%w: OIDC client_id must be 1-256 characters", ErrInvalidSource)
		}
		if !s.SecretConfigured {
			return fmt.Errorf("%w: OIDC client secret is required", ErrInvalidSource)
		}
		if len(s.OIDC.Scopes) == 0 || len(s.OIDC.Scopes) > 20 || !slices.Contains(s.OIDC.Scopes, "openid") {
			return fmt.Errorf("%w: OIDC scopes must contain openid and at most 20 entries", ErrInvalidSource)
		}
		for _, scope := range s.OIDC.Scopes {
			if !oidcScopePattern.MatchString(scope) {
				return fmt.Errorf("%w: invalid OIDC scope %q", ErrInvalidSource, scope)
			}
		}
	default:
		return fmt.Errorf("%w: unsupported source type %q", ErrInvalidSource, s.Type)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func uniqueSourceStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
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

func cloneSource(source Source) Source {
	if source.LDAP != nil {
		value := *source.LDAP
		source.LDAP = &value
	}
	if source.OIDC != nil {
		value := *source.OIDC
		value.Scopes = slices.Clone(value.Scopes)
		source.OIDC = &value
	}
	source.SecretCiphertext = slices.Clone(source.SecretCiphertext)
	source.SecretConfigured = len(source.SecretCiphertext) > 0 || source.SecretConfigured
	if source.ArchivedAt != nil {
		value := *source.ArchivedAt
		source.ArchivedAt = &value
	}
	return source
}
