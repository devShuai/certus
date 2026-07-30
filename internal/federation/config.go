package federation

import "strings"

type LDAPConfig struct {
	ProviderID           string
	Label                string
	URL                  string
	StartTLS             bool
	BaseDN               string
	BindDN               string
	BindPassword         string
	UserFilter           string
	UsernameAttribute    string
	DisplayNameAttribute string
	EmailAttribute       string
}

func (c LDAPConfig) Enabled() bool {
	return strings.TrimSpace(c.URL) != ""
}

type ExternalOIDCConfig struct {
	ProviderID   string
	Issuer       string
	ClientID     string
	ClientSecret string
	Label        string
	Scopes       []string
}

func (c ExternalOIDCConfig) Enabled() bool {
	return strings.TrimSpace(c.Issuer) != ""
}
