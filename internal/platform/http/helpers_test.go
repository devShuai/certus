package httpserver

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIPAddressIgnoresForwardingFromUntrustedPeer(t *testing.T) {
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "198.51.100.10:4321"
	request.Header.Set("X-Forwarded-For", "203.0.113.20")
	if actual := clientIPAddress(request, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	}); actual != "198.51.100.10" {
		t.Fatalf("spoofed forwarded address was trusted: %s", actual)
	}
}

func TestClientIPAddressWalksTrustedProxyChain(t *testing.T) {
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "10.0.0.2:4321"
	request.Header.Set("X-Forwarded-For", "203.0.113.20, 10.0.0.1")
	if actual := clientIPAddress(request, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	}); actual != "203.0.113.20" {
		t.Fatalf("unexpected client address: %s", actual)
	}
}

func TestClientIPAddressFallsBackOnMalformedForwarding(t *testing.T) {
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "10.0.0.2:4321"
	request.Header.Set("X-Forwarded-For", "not-an-address")
	if actual := clientIPAddress(request, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	}); actual != "10.0.0.2" {
		t.Fatalf("malformed forwarding did not fall back to peer: %s", actual)
	}
}
