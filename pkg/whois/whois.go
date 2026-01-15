package whois

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// WhoisServer represents a WHOIS server configuration with host and port.
type WhoisServer struct {
	Host string
	Port string
}

// DefaultWhoisServers maps TLDs to their corresponding WHOIS servers,
// supporting 50+ top-level domains including gTLDs and ccTLDs.
var DefaultWhoisServers = map[string]WhoisServer{
	"com":     {Host: "whois.verisign-grs.com", Port: "43"},
	"net":     {Host: "whois.verisign-grs.com", Port: "43"},
	"org":     {Host: "whois.pir.org", Port: "43"},
	"info":    {Host: "whois.afilias.net", Port: "43"},
	"biz":     {Host: "whois.biz", Port: "43"},
	"us":      {Host: "whois.nic.us", Port: "43"},
	"uk":      {Host: "whois.nic.uk", Port: "43"},
	"co.uk":   {Host: "whois.nic.uk", Port: "43"},
	"ca":      {Host: "whois.cira.ca", Port: "43"},
	"de":      {Host: "whois.denic.de", Port: "43"},
	"jp":      {Host: "whois.jprs.jp", Port: "43"},
	"fr":      {Host: "whois.nic.fr", Port: "43"},
	"au":      {Host: "whois.auda.org.au", Port: "43"},
	"ru":      {Host: "whois.tcinet.ru", Port: "43"},
	"ch":      {Host: "whois.nic.ch", Port: "43"},
	"it":      {Host: "whois.nic.it", Port: "43"},
	"nl":      {Host: "whois.domain-registry.nl", Port: "43"},
	"eu":      {Host: "whois.eu", Port: "43"},
	"nz":      {Host: "whois.irs.net.nz", Port: "43"},
	"io":      {Host: "whois.nic.io", Port: "43"},
	"me":      {Host: "whois.nic.me", Port: "43"},
	"tv":      {Host: "whois.nic.tv", Port: "43"},
	"cc":      {Host: "whois.nic.cc", Port: "43"},
	"app":     {Host: "whois.nic.google", Port: "43"},
	"dev":     {Host: "whois.nic.google", Port: "43"},
	"ai":      {Host: "whois.nic.ai", Port: "43"},
	"co":      {Host: "whois.nic.co", Port: "43"},
	"asia":    {Host: "whois.nic.asia", Port: "43"},
	"mobi":    {Host: "whois.nic.mobi", Port: "43"},
	"xxx":     {Host: "whois.nic.xxx", Port: "43"},
	"tel":     {Host: "whois.nic.tel", Port: "43"},
	"in":      {Host: "whois.registry.in", Port: "43"},
	"cn":      {Host: "whois.cnnic.cn", Port: "43"},
	"br":      {Host: "whois.registro.br", Port: "43"},
	"mx":      {Host: "whois.mx", Port: "43"},
	"se":      {Host: "whois.iis.se", Port: "43"},
	"be":      {Host: "whois.dns.be", Port: "43"},
	"at":      {Host: "whois.nic.at", Port: "43"},
	"dk":      {Host: "whois.dk-hostmaster.dk", Port: "43"},
	"fi":      {Host: "whois.fi", Port: "43"},
	"is":      {Host: "whois.isnic.is", Port: "43"},
	"cz":      {Host: "whois.nic.cz", Port: "43"},
	"pl":      {Host: "whois.dns.pl", Port: "43"},
	"default": {Host: "whois.iana.org", Port: "43"},
}

// WhoisResult contains the result of a WHOIS query, including both raw response
// and parsed structured data such as registrar, dates, name servers, and status.
type WhoisResult struct {
	Domain      string                 `json:"domain"`
	RawResponse string                 `json:"raw_response"`
	Server      string                 `json:"server"`
	Timestamp   time.Time              `json:"timestamp"`
	Error       string                 `json:"error,omitempty"`
	ParsedData  map[string]interface{} `json:"parsed_data,omitempty"`
	Registrar   string                 `json:"registrar,omitempty"`
	CreatedDate string                 `json:"created_date,omitempty"`
	ExpiryDate  string                 `json:"expiry_date,omitempty"`
	UpdatedDate string                 `json:"updated_date,omitempty"`
	NameServers []string               `json:"name_servers,omitempty"`
	Status      []string               `json:"status,omitempty"`
	Emails      []string               `json:"emails,omitempty"`
}

// ContextDialer is a function type for creating network connections with context support.
type ContextDialer func(ctx context.Context, network, address string) (net.Conn, error)

// Client is a WHOIS lookup client that performs WHOIS queries with support
// for automatic referral following and configurable timeouts.
type Client struct {
	timeout        time.Duration
	followReferral bool
	servers        map[string]WhoisServer
	dialer         ContextDialer
}

// Config contains configuration options for the WHOIS client.
type Config struct {
	// Timeout for WHOIS queries (default: 10 seconds).
	Timeout time.Duration
	// FollowReferral automatically follows referral WHOIS servers.
	FollowReferral bool
	// CustomServers allows overriding default WHOIS servers.
	CustomServers map[string]WhoisServer
	// Dialer allows providing a custom dialer for network connections.
	// This enables support for proxies (HTTP, SOCKS5) and other custom network configurations.
	// If set, this takes precedence over ProxyURL.
	Dialer ContextDialer
	// ProxyURL specifies a proxy server URL (e.g., "socks5://localhost:1080" or "http://proxy:8080").
	// This is used only if Dialer is not set.
	ProxyURL string
}

// DefaultConfig returns a default configuration with a 10-second timeout,
// automatic referral following enabled, and empty custom servers map.
func DefaultConfig() *Config {
	return &Config{
		Timeout:        10 * time.Second,
		FollowReferral: true,
		CustomServers:  make(map[string]WhoisServer),
	}
}

// NewClient creates a new WHOIS lookup client with the given configuration.
// If config is nil, DefaultConfig is used. Custom servers are merged with defaults.
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	// Merge custom servers with defaults
	servers := make(map[string]WhoisServer)
	for k, v := range DefaultWhoisServers {
		servers[k] = v
	}
	for k, v := range config.CustomServers {
		servers[k] = v
	}

	// Determine which dialer to use
	var dialFunc ContextDialer

	if config.Dialer != nil {
		// Use the custom dialer provided by the user
		dialFunc = config.Dialer
	} else if config.ProxyURL != "" {
		// Create a dialer from the proxy URL
		var err error
		dialFunc, err = createProxyDialer(config.ProxyURL, config.Timeout)
		if err != nil {
			return nil, fmt.Errorf("failed to create proxy dialer: %w", err)
		}
	} else {
		// Use default net.Dialer
		dialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{
				Timeout: config.Timeout,
			}
			return d.DialContext(ctx, network, address)
		}
	}

	return &Client{
		timeout:        config.Timeout,
		followReferral: config.FollowReferral,
		servers:        servers,
		dialer:         dialFunc,
	}, nil
}

// createProxyDialer creates a ContextDialer from a proxy URL string.
func createProxyDialer(proxyURL string, timeout time.Duration) (ContextDialer, error) {
	// Parse the proxy URL
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	// Create base dialer
	baseDialer := &net.Dialer{
		Timeout: timeout,
	}

	// Create proxy dialer based on scheme
	var proxyDialer proxy.Dialer
	switch parsedURL.Scheme {
	case "socks5", "socks5h":
		// SOCKS5 proxy
		proxyDialer, err = proxy.SOCKS5("tcp", parsedURL.Host, nil, baseDialer)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}
	case "http", "https":
		// HTTP proxy - use FromURL which supports HTTP CONNECT
		proxyDialer, err = proxy.FromURL(parsedURL, baseDialer)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP proxy dialer: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s (supported: socks5, http, https)", parsedURL.Scheme)
	}

	// Check if the dialer supports context
	if contextDialer, ok := proxyDialer.(proxy.ContextDialer); ok {
		return contextDialer.DialContext, nil
	}

	// Fallback for non-context dialers
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return proxyDialer.Dial(network, address)
	}, nil
}

// Lookup performs a WHOIS lookup for the specified domain, automatically
// determining the appropriate WHOIS server and following referrals if enabled.
// If ctx is nil, a new context with the client's timeout is created.
func (c *Client) Lookup(ctx context.Context, domain string) (*WhoisResult, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), c.timeout)
		defer cancel()
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")

	result := &WhoisResult{
		Domain:     domain,
		Timestamp:  time.Now(),
		ParsedData: make(map[string]interface{}),
	}

	// Get the appropriate WHOIS server
	server, err := c.getWhoisServer(domain)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Server = fmt.Sprintf("%s:%s", server.Host, server.Port)

	// Perform the WHOIS query
	response, err := c.query(ctx, domain, server)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.RawResponse = response

	// Check for referral server
	if c.followReferral {
		if referralServer := c.extractReferralServer(response); referralServer != "" {
			// Query the referral server
			referralResponse, err := c.query(ctx, domain, WhoisServer{Host: referralServer, Port: "43"})
			if err == nil && len(referralResponse) > len(response) {
				result.RawResponse = referralResponse
				result.Server = referralServer + ":43"
			}
		}
	}

	// Parse the response
	c.parseResponse(result)

	return result, nil
}

// query performs the actual WHOIS query by connecting to the WHOIS server
// via TCP and sending the domain query.
func (c *Client) query(ctx context.Context, domain string, server WhoisServer) (string, error) {
	address := net.JoinHostPort(server.Host, server.Port)

	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", fmt.Errorf("failed to connect to WHOIS server %s: %w", address, err)
	}
	defer conn.Close()

	// Set deadline for the entire operation
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(c.timeout))
	}

	// Send the query
	query := domain + "\r\n"
	_, err = conn.Write([]byte(query))
	if err != nil {
		return "", fmt.Errorf("failed to send query: %w", err)
	}

	// Read the response
	var response strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		response.WriteString(scanner.Text())
		response.WriteString("\n")
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading response: %w", err)
	}

	return response.String(), nil
}

// getWhoisServer determines the appropriate WHOIS server for a domain
// by extracting the TLD and looking it up in the server map.
func (c *Client) getWhoisServer(domain string) (WhoisServer, error) {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return WhoisServer{}, fmt.Errorf("invalid domain format: %s", domain)
	}

	// Try to find server for full TLD (e.g., co.uk)
	if len(parts) >= 3 {
		tld := strings.Join(parts[len(parts)-2:], ".")
		if server, ok := c.servers[tld]; ok {
			return server, nil
		}
	}

	// Try to find server for last part (e.g., uk)
	tld := parts[len(parts)-1]
	if server, ok := c.servers[tld]; ok {
		return server, nil
	}

	// Return default WHOIS server
	return c.servers["default"], nil
}

// extractReferralServer extracts referral WHOIS server information from the response,
// looking for "Whois Server:", "Referral URL:", or "Refer:" fields.
func (c *Client) extractReferralServer(response string) string {
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "whois server:") ||
			strings.HasPrefix(lower, "referral url:") ||
			strings.HasPrefix(lower, "refer:") {

			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				server := strings.TrimSpace(parts[1])
				server = strings.TrimPrefix(server, "whois://")
				server = strings.TrimPrefix(server, "http://")
				server = strings.TrimPrefix(server, "https://")
				if server != "" && server != "whois.iana.org" {
					return server
				}
			}
		}
	}
	return ""
}

// parseResponse parses the WHOIS response and extracts structured data
// including registrar, dates, name servers, status, and email addresses.
func (c *Client) parseResponse(result *WhoisResult) {
	lines := strings.Split(result.RawResponse, "\n")

	var nameServers []string
	var status []string
	var emails []string

	emailMap := make(map[string]bool)
	nsMap := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		lower := strings.ToLower(line)

		// Extract registrar
		if result.Registrar == "" && (strings.Contains(lower, "registrar:") || strings.Contains(lower, "registrar name:")) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.Registrar = strings.TrimSpace(parts[1])
			}
		}

		// Extract dates
		if result.CreatedDate == "" && (strings.Contains(lower, "creation date:") || strings.Contains(lower, "created:") || strings.Contains(lower, "registered:")) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.CreatedDate = strings.TrimSpace(parts[1])
			}
		}

		if result.ExpiryDate == "" && (strings.Contains(lower, "expiry date:") || strings.Contains(lower, "expiration date:") || strings.Contains(lower, "expires:")) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.ExpiryDate = strings.TrimSpace(parts[1])
			}
		}

		if result.UpdatedDate == "" && (strings.Contains(lower, "updated date:") || strings.Contains(lower, "last updated:") || strings.Contains(lower, "modified:")) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.UpdatedDate = strings.TrimSpace(parts[1])
			}
		}

		// Extract name servers
		if strings.Contains(lower, "name server:") || strings.Contains(lower, "nserver:") || strings.Contains(lower, "nameserver:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ns := strings.TrimSpace(parts[1])
				ns = strings.ToLower(ns)
				// Remove any additional info after whitespace
				if idx := strings.Index(ns, " "); idx > 0 {
					ns = ns[:idx]
				}
				if !nsMap[ns] {
					nameServers = append(nameServers, ns)
					nsMap[ns] = true
				}
			}
		}

		// Extract status
		if strings.Contains(lower, "status:") || strings.Contains(lower, "domain status:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				statusValue := strings.TrimSpace(parts[1])
				if statusValue != "" {
					status = append(status, statusValue)
				}
			}
		}

		// Extract emails
		if strings.Contains(line, "@") {
			// Simple email extraction
			words := strings.Fields(line)
			for _, word := range words {
				if strings.Contains(word, "@") && strings.Contains(word, ".") {
					email := strings.Trim(word, ",:;()<>[]")
					if !emailMap[email] && isValidEmail(email) {
						emails = append(emails, email)
						emailMap[email] = true
					}
				}
			}
		}
	}

	result.NameServers = nameServers
	result.Status = status
	result.Emails = emails

	// Store in parsed data as well
	result.ParsedData["registrar"] = result.Registrar
	result.ParsedData["created_date"] = result.CreatedDate
	result.ParsedData["expiry_date"] = result.ExpiryDate
	result.ParsedData["updated_date"] = result.UpdatedDate
	result.ParsedData["name_servers"] = result.NameServers
	result.ParsedData["status"] = result.Status
	result.ParsedData["emails"] = result.Emails
}

// isValidEmail performs basic email validation by checking length,
// the presence of @ and . characters, and basic structure.
func isValidEmail(email string) bool {
	if len(email) < 3 || len(email) > 254 {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	if len(parts[0]) == 0 || len(parts[1]) == 0 {
		return false
	}
	if !strings.Contains(parts[1], ".") {
		return false
	}
	return true
}
