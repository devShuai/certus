package httpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxFaviconPageBytes = 512 << 10

var (
	errInvalidFaviconSite = errors.New("invalid favicon site URL")
	linkTagPattern        = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	linkAttributePattern  = regexp.MustCompile(`(?is)\b(rel|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+))`)
	nonPublicFaviconNets  = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
)

type faviconDiscoveryInput struct {
	SiteURL string `json:"site_url"`
}

type faviconDiscoveryResponse struct {
	FaviconURL string `json:"favicon_url"`
	Source     string `json:"source"`
}

func (s *server) discoverClientFavicon(w http.ResponseWriter, r *http.Request) {
	var input faviconDiscoveryInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	faviconURL, source, err := discoverFavicon(ctx, s.faviconHTTP, input.SiteURL)
	if errors.Is(err, errInvalidFaviconSite) {
		writeProblem(w, http.StatusBadRequest, "invalid_site_url", "自动采集仅支持公开 HTTPS 站点")
		return
	}
	if err != nil {
		s.logger.Warn("discover client favicon", "error", err)
		writeProblem(w, http.StatusBadGateway, "favicon_discovery_failed", "无法从该站点采集 favicon，可手动填写图标 URL")
		return
	}
	writeJSON(w, http.StatusOK, faviconDiscoveryResponse{
		FaviconURL: faviconURL,
		Source:     source,
	})
}

func discoverFavicon(ctx context.Context, client *http.Client, rawSiteURL string) (string, string, error) {
	siteURL, err := parsePublicHTTPSURL(rawSiteURL)
	if err != nil {
		return "", "", err
	}
	siteURL.Path = "/"
	siteURL.RawPath = ""
	siteURL.RawQuery = ""
	siteURL.Fragment = ""

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, siteURL.String(), nil)
	if err != nil {
		return "", "", err
	}
	request.Header.Set("Accept", "text/html,application/xhtml+xml")
	request.Header.Set("User-Agent", "Certus-Favicon-Discovery/1.0")
	response, err := client.Do(request)
	if err != nil {
		return "", "", fmt.Errorf("fetch favicon page: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", "", fmt.Errorf("fetch favicon page: unexpected HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxFaviconPageBytes+1))
	if err != nil {
		return "", "", fmt.Errorf("read favicon page: %w", err)
	}
	if len(body) > maxFaviconPageBytes {
		return "", "", errors.New("favicon page is too large")
	}
	baseURL := siteURL
	if response.Request != nil && response.Request.URL != nil {
		baseURL = response.Request.URL
	}
	if href := faviconHref(body); href != "" {
		discovered, resolveErr := baseURL.Parse(strings.TrimSpace(href))
		if resolveErr == nil {
			discovered.Fragment = ""
			if _, validateErr := parsePublicHTTPSURL(discovered.String()); validateErr == nil &&
				len(discovered.String()) <= 2048 {
				return discovered.String(), "html", nil
			}
		}
	}
	fallback := *baseURL
	fallback.Path = "/favicon.ico"
	fallback.RawPath = ""
	fallback.RawQuery = ""
	fallback.Fragment = ""
	if _, err := parsePublicHTTPSURL(fallback.String()); err != nil {
		return "", "", err
	}
	return fallback.String(), "fallback", nil
}

func faviconHref(document []byte) string {
	for _, tag := range linkTagPattern.FindAll(document, -1) {
		attributes := make(map[string]string)
		for _, match := range linkAttributePattern.FindAllSubmatch(tag, -1) {
			value := ""
			for index := 2; index < len(match); index++ {
				if len(match[index]) > 0 {
					value = string(match[index])
					break
				}
			}
			attributes[strings.ToLower(string(match[1]))] = value
		}
		rel := strings.Fields(strings.ToLower(attributes["rel"]))
		if attributes["href"] != "" && slicesContain(rel, "icon") {
			return attributes["href"]
		}
	}
	return ""
}

func slicesContain(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func parsePublicHTTPSURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.Fragment != "" {
		return nil, errInvalidFaviconSite
	}
	if address, err := netip.ParseAddr(parsed.Hostname()); err == nil && !publicFaviconAddress(address) {
		return nil, errInvalidFaviconSite
	}
	return parsed, nil
}

func newSafeFaviconHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve favicon host: %w", err)
		}
		if len(addresses) == 0 {
			return nil, errors.New("resolve favicon host: no addresses")
		}
		for _, resolved := range addresses {
			if !publicFaviconAddress(resolved) {
				return nil, errors.New("favicon host resolves to a non-public address")
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].String(), port))
	}
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many favicon redirects")
			}
			_, err := parsePublicHTTPSURL(request.URL.String())
			return err
		},
	}
}

func publicFaviconAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() ||
		!address.IsGlobalUnicast() ||
		address.IsPrivate() ||
		address.IsLoopback() ||
		address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() ||
		address.IsMulticast() ||
		address.IsUnspecified() {
		return false
	}
	for _, blocked := range nonPublicFaviconNets {
		if blocked.Contains(address) {
			return false
		}
	}
	return true
}
