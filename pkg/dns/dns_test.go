package dns

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "default config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "custom timeout",
			config: &Config{
				Timeout: 3 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "custom resolver",
			config: &Config{
				CustomResolver: "8.8.8.8:53",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if client == nil {
				t.Error("NewClient() returned nil client")
			}
		})
	}
}

// TestNewClientDefaultResolverPrefersGo: without a custom resolver the client
// sends its own DNS queries through Go's resolver on every platform. On
// Windows the system path (GetAddrInfoW) answered "no data" for names that
// have AAAA records.
func TestNewClientDefaultResolverPrefersGo(t *testing.T) {
	for name, config := range map[string]*Config{"nil config": nil, "default config": DefaultConfig()} {
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("%s: NewClient: %v", name, err)
		}
		if client.resolver == nil || !client.resolver.PreferGo {
			t.Errorf("%s: resolver %+v does not prefer Go", name, client.resolver)
		}
		if client.resolver == net.DefaultResolver {
			t.Errorf("%s: the client must not set PreferGo on the process-wide net.DefaultResolver", name)
		}
		if client.resolver != nil && client.resolver.Dial != nil {
			t.Errorf("%s: the default resolver must ask the system's configured DNS servers, not a custom Dial", name)
		}
	}
}

// TestNewClientKeepsACustomResolver: a caller's Resolver is used as given,
// whatever else the config holds.
func TestNewClientKeepsACustomResolver(t *testing.T) {
	custom := &net.Resolver{PreferGo: true, StrictErrors: true}
	for name, config := range map[string]*Config{
		"resolver alone": {Resolver: custom},
		"resolver beside an address and a dialer": {
			Resolver:       custom,
			CustomResolver: "127.0.0.1:1",
			Dialer: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("not used")
			},
		},
	} {
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("%s: NewClient: %v", name, err)
		}
		if client.resolver != custom {
			t.Errorf("%s: resolver is %p, want the caller's %p", name, client.resolver, custom)
		}
	}
}

// TestNewClientMapsANonPositiveTimeoutToTheDefault: a negative Timeout (the
// CLI's -timeout -1) would hand every lookup a context that has already
// expired.
func TestNewClientMapsANonPositiveTimeoutToTheDefault(t *testing.T) {
	for _, timeout := range []time.Duration{0, -1, -time.Second} {
		client, err := NewClient(&Config{Timeout: timeout})
		if err != nil {
			t.Fatalf("NewClient(Timeout %s): %v", timeout, err)
		}
		if client.timeout != 5*time.Second {
			t.Errorf("Timeout %s became %s, want the 5s default", timeout, client.timeout)
		}
	}
}

func TestLookupA(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	result, err := client.Lookup(ctx, "google.com", RecordTypeA)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	if result.Domain != "google.com" {
		t.Errorf("Expected domain google.com, got %s", result.Domain)
	}

	if result.RecordType != RecordTypeA {
		t.Errorf("Expected record type A, got %s", result.RecordType)
	}

	if len(result.Records) == 0 {
		t.Error("Expected at least one A record")
	}

	t.Logf("A records for google.com: %v", result.Records)
}

func TestLookupMX(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	result, err := client.Lookup(ctx, "google.com", RecordTypeMX)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	if len(result.MXRecords) == 0 {
		t.Error("Expected at least one MX record")
	}

	t.Logf("MX records for google.com: %v", result.MXRecords)
}

func TestLookupNS(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	result, err := client.Lookup(ctx, "google.com", RecordTypeNS)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	if len(result.NameServers) == 0 {
		t.Error("Expected at least one NS record")
	}

	t.Logf("NS records for google.com: %v", result.NameServers)
}

func TestLookupTXT(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	result, err := client.Lookup(ctx, "google.com", RecordTypeTXT)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	if len(result.Records) == 0 {
		t.Error("Expected at least one TXT record")
	}

	t.Logf("TXT records for google.com: %v", result.Records)
}

func TestLookupAll(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	results, err := client.LookupAll(ctx, "google.com")
	if err != nil {
		t.Fatalf("LookupAll failed: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected at least one result")
	}

	// Check that we got results for common record types
	recordTypes := []RecordType{RecordTypeA, RecordTypeMX, RecordTypeNS}
	for _, rt := range recordTypes {
		if result, ok := results[rt]; ok {
			t.Logf("%s records: %v", rt, result.Records)
		}
	}
}

func TestLookupWithTimeout(t *testing.T) {
	config := &Config{
		Timeout: 1 * time.Millisecond, // Very short timeout
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	_, err = client.Lookup(ctx, "google.com", RecordTypeA)
	// We expect this might timeout, but we're just testing it doesn't panic
	t.Logf("Lookup with short timeout result: %v", err)
}

func TestLookupInvalidDomain(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	result, err := client.Lookup(ctx, "this-domain-does-not-exist-12345.com", RecordTypeA)

	// We expect an error or empty records
	if err == nil && len(result.Records) == 0 {
		t.Log("Invalid domain returned no records as expected")
	} else if err != nil {
		t.Logf("Invalid domain returned error as expected: %v", err)
	}
}
