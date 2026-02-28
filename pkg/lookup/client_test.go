package lookup

import (
	"context"
	"testing"

	"github.com/hellenic-development/dns-lookup/pkg/dns"
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
			name: "custom config",
			config: &Config{
				DNS:   dns.DefaultConfig(),
				WHOIS: nil,
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
			if client != nil {
				if client.DNS() == nil {
					t.Error("DNS client is nil")
				}
				if client.WHOIS() == nil {
					t.Error("WHOIS client is nil")
				}
			}
		})
	}
}

func TestDNSLookup(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	result, err := client.DNSLookup(ctx, "google.com", dns.RecordTypeA)
	if err != nil {
		t.Fatalf("DNSLookup failed: %v", err)
	}

	if result.Domain != "google.com" {
		t.Errorf("Expected domain google.com, got %s", result.Domain)
	}

	if len(result.Records) == 0 {
		t.Error("Expected at least one A record")
	}

	t.Logf("A records for google.com: %v", result.Records)
}

func TestDNSLookupAll(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	results, err := client.DNSLookupAll(ctx, "google.com")
	if err != nil {
		t.Fatalf("DNSLookupAll failed: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected at least one result")
	}

	t.Logf("Found %d record types", len(results))
}

func TestWHOISLookup(t *testing.T) {
	// Skip in short mode as this makes real network calls
	if testing.Short() {
		t.Skip("Skipping WHOIS lookup test in short mode")
	}

	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	result, err := client.WHOISLookup(ctx, "google.com")
	if err != nil {
		t.Fatalf("WHOISLookup failed: %v", err)
	}

	if result.Domain != "google.com" {
		t.Errorf("Expected domain google.com, got %s", result.Domain)
	}

	if result.RawResponse == "" {
		t.Error("Expected non-empty raw response")
	}

	t.Logf("WHOIS server: %s", result.Server)
	t.Logf("Registrar: %s", result.Registrar)
}

func TestLookupAll(t *testing.T) {
	// Skip in short mode as this makes real network calls
	if testing.Short() {
		t.Skip("Skipping full lookup test in short mode")
	}

	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	info, err := client.LookupAll(ctx, "google.com")
	if err != nil {
		t.Logf("Some lookups failed (expected): %v", err)
	}

	if info == nil {
		t.Fatal("Expected non-nil domain info")
	}

	if info.Domain != "google.com" {
		t.Errorf("Expected domain google.com, got %s", info.Domain)
	}

	if info.DNS == nil {
		t.Error("Expected DNS results")
	}

	if info.WHOIS == nil {
		t.Error("Expected WHOIS results")
	}

	t.Logf("Domain info collected successfully")
	t.Logf("DNS record types: %d", len(info.DNS))
	t.Logf("WHOIS server: %s", info.WHOIS.Server)
}
