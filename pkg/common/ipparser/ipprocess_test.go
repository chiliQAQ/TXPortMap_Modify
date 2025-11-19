package ipparser

import "testing"

func TestIsIPRangeFull(t *testing.T) {
	if !IsIPRange("172.16.199.10-172.16.199.14") {
		t.Fatal("expected full range to be valid")
	}
}

func TestIsIPRangeShorthandValid(t *testing.T) {
	if !IsIPRange("172.16.199.10-14") {
		t.Fatal("expected shorthand range to be valid")
	}
}

func TestIsIPRangeShorthandInvalid(t *testing.T) {
	if IsIPRange("172.16.199.10-9") {
		t.Fatal("expected descending shorthand to be invalid")
	}
}

func TestPrimaryHostMapping(t *testing.T) {
	resetDomainHostCache()
	rememberDomainHost("web.example.com", []string{"192.0.2.10"})
	host, ok := PrimaryHost("192.0.2.10")
	if !ok || host != "web.example.com" {
		t.Fatalf("expected primary host web.example.com, got %s (ok=%v)", host, ok)
	}

	rememberDomainHost("api.example.com", []string{"192.0.2.10"})
	hosts := AllHosts("192.0.2.10")
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}
	if hosts[0] != "web.example.com" || hosts[1] != "api.example.com" {
		t.Fatalf("unexpected host order: %#v", hosts)
	}
}
