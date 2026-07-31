package httpserver

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

type faviconRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip faviconRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestDiscoverFaviconUsesHTMLIcon(t *testing.T) {
	client := &http.Client{Transport: faviconRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://app.example.com/" {
			t.Fatalf("unexpected discovery URL: %s", request.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`<html><head><link href="/assets/app-icon.svg" rel="shortcut icon"></head></html>`,
			)),
			Request: request,
			Header:  make(http.Header),
		}, nil
	})}

	faviconURL, source, err := discoverFavicon(
		context.Background(),
		client,
		"https://app.example.com/oidc/callback",
	)
	if err != nil {
		t.Fatal(err)
	}
	if faviconURL != "https://app.example.com/assets/app-icon.svg" || source != "html" {
		t.Fatalf("unexpected favicon discovery: %q %q", faviconURL, source)
	}
}

func TestDiscoverFaviconFallsBackToConventionalPath(t *testing.T) {
	client := &http.Client{Transport: faviconRoundTripper(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`<html><head><title>App</title></head></html>`)),
			Request:    request,
			Header:     make(http.Header),
		}, nil
	})}
	faviconURL, source, err := discoverFavicon(context.Background(), client, "https://app.example.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if faviconURL != "https://app.example.com/favicon.ico" || source != "fallback" {
		t.Fatalf("unexpected favicon fallback: %q %q", faviconURL, source)
	}
}

func TestFaviconDiscoveryRejectsPrivateTargets(t *testing.T) {
	for _, raw := range []string{
		"http://app.example.com/",
		"https://127.0.0.1/",
		"https://[::1]/",
		"https://169.254.169.254/latest/meta-data/",
	} {
		if _, err := parsePublicHTTPSURL(raw); err == nil {
			t.Fatalf("unsafe favicon target was accepted: %s", raw)
		}
	}
	for _, address := range []string{"10.0.0.1", "127.0.0.1", "::1", "fe80::1"} {
		if publicFaviconAddress(netip.MustParseAddr(address)) {
			t.Fatalf("private address was accepted: %s", address)
		}
	}
	for _, address := range []string{"100.64.0.1", "192.0.2.10", "203.0.113.10", "2001:db8::1"} {
		if publicFaviconAddress(netip.MustParseAddr(address)) {
			t.Fatalf("reserved address was accepted: %s", address)
		}
	}
	if !publicFaviconAddress(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public address was rejected")
	}
}
