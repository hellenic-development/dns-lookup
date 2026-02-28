package lookup

import (
	"context"
	"fmt"

	"github.com/hellenic-development/dns-lookup/pkg/dns"
	"github.com/hellenic-development/dns-lookup/pkg/whois"
)

// Client provides unified DNS and WHOIS lookup functionality by combining
// both DNS and WHOIS clients into a single convenient interface.
type Client struct {
	dnsClient   *dns.Client
	whoisClient *whois.Client
}

// Config contains configuration for both DNS and WHOIS clients.
type Config struct {
	DNS   *dns.Config
	WHOIS *whois.Config
}

// DefaultConfig returns a default configuration with default settings
// for both DNS and WHOIS clients.
func DefaultConfig() *Config {
	return &Config{
		DNS:   dns.DefaultConfig(),
		WHOIS: whois.DefaultConfig(),
	}
}

// NewClient creates a new unified lookup client that combines DNS and WHOIS
// functionality. If config is nil, DefaultConfig is used.
// Returns an error if either client creation fails.
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if config.DNS == nil {
		config.DNS = dns.DefaultConfig()
	}

	if config.WHOIS == nil {
		config.WHOIS = whois.DefaultConfig()
	}

	dnsClient, err := dns.NewClient(config.DNS)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS client: %w", err)
	}

	whoisClient, err := whois.NewClient(config.WHOIS)
	if err != nil {
		return nil, fmt.Errorf("failed to create WHOIS client: %w", err)
	}

	return &Client{
		dnsClient:   dnsClient,
		whoisClient: whoisClient,
	}, nil
}

// DNSLookup performs a DNS lookup for the specified domain and record type
// using the underlying DNS client.
func (c *Client) DNSLookup(ctx context.Context, domain string, recordType dns.RecordType) (*dns.LookupResult, error) {
	return c.dnsClient.Lookup(ctx, domain, recordType)
}

// DNSLookupAll performs DNS lookups for all common record types
// (A, AAAA, CNAME, MX, NS, TXT) using the underlying DNS client.
func (c *Client) DNSLookupAll(ctx context.Context, domain string) (map[dns.RecordType]*dns.LookupResult, error) {
	return c.dnsClient.LookupAll(ctx, domain)
}

// DNSLookupSRV performs a SRV record lookup for the specified service, protocol,
// and name using the underlying DNS client.
func (c *Client) DNSLookupSRV(ctx context.Context, service, proto, name string) (*dns.LookupResult, error) {
	return c.dnsClient.LookupSRV(ctx, service, proto, name)
}

// WHOISLookup performs a WHOIS lookup for the specified domain
// using the underlying WHOIS client.
func (c *Client) WHOISLookup(ctx context.Context, domain string) (*whois.WhoisResult, error) {
	return c.whoisClient.Lookup(ctx, domain)
}

// DomainInfo contains comprehensive information about a domain including
// both DNS records and WHOIS data.
type DomainInfo struct {
	Domain string                               `json:"domain"`
	DNS    map[dns.RecordType]*dns.LookupResult `json:"dns"`
	WHOIS  *whois.WhoisResult                   `json:"whois"`
	Error  string                               `json:"error,omitempty"`
}

// LookupAll performs both DNS and WHOIS lookups for a domain, combining
// all information into a single DomainInfo result. Continues even if individual
// lookups fail, recording errors in the Error field.
func (c *Client) LookupAll(ctx context.Context, domain string) (*DomainInfo, error) {
	info := &DomainInfo{
		Domain: domain,
	}

	// Perform DNS lookups
	dnsResults, err := c.dnsClient.LookupAll(ctx, domain)
	if err != nil {
		info.Error = fmt.Sprintf("DNS lookup failed: %v", err)
	}
	info.DNS = dnsResults

	// Perform WHOIS lookup
	whoisResult, err := c.whoisClient.Lookup(ctx, domain)
	if err != nil {
		if info.Error != "" {
			info.Error += "; "
		}
		info.Error += fmt.Sprintf("WHOIS lookup failed: %v", err)
	}
	info.WHOIS = whoisResult

	return info, nil
}

// DNS returns the underlying DNS client for direct access to DNS operations.
func (c *Client) DNS() *dns.Client {
	return c.dnsClient
}

// WHOIS returns the underlying WHOIS client for direct access to WHOIS operations.
func (c *Client) WHOIS() *whois.Client {
	return c.whoisClient
}
