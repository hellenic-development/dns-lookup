package whois

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/proxy"
)

// WhoisServer represents a WHOIS server configuration with host and port.
type WhoisServer struct {
	Host string
	Port string
	// QueryFormat is how the domain is written into the query line for this
	// server: the text with "%s" where the domain goes, for a registry that
	// needs flags. Empty sends the bare domain, as most servers expect, and
	// so does a format without "%s", so a query never goes out without the
	// domain. A referral to a host that a table row names gets that row's
	// format too, so DENIC reached through IANA is asked like DENIC reached
	// from the table.
	QueryFormat string
	// UnicodeQueryFormat is used in place of QueryFormat when the domain has
	// a character outside ASCII, for a registry whose flags differ by the
	// form the name is sent in. The same rule applies: a format without
	// "%s" is ignored. Empty means QueryFormat is used for every name. A
	// referral target gets this from a table row with its host, as it gets
	// QueryFormat.
	UnicodeQueryFormat string
}

// DefaultWhoisServers maps TLDs to their corresponding WHOIS servers,
// supporting 40+ top-level domains including gTLDs and ccTLDs. A TLD that is
// not listed goes to IANA, which names its registry's server; .app and .dev
// are left to that path on purpose, since whois.nic.google no longer resolves
// and IANA's record of .app names no WHOIS server.
//
// DENIC (.de) needs flags that depend on the form of the name. Sent live for
// bücher.de: a bare "bücher.de" gets only Domain, Domain-Ace and Status;
// "-T dn bücher.de" gets the full record (Domain, Domain-Ace, Nserver lines,
// Status, Changed); "-T dn,ace bücher.de" gets "% Error: 55000000010 Non
// bijective ace-idn convertible domain"; "-T dn xn--bcher-kva.de" gets
// "Status: invalid"; "-T dn,ace xn--bcher-kva.de" gets the full record. So
// "ace" means the name is sent in its xn-- form: an ASCII name is asked with
// "-T dn,ace" and a Unicode one with "-T dn".
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
	"de":      {Host: "whois.denic.de", Port: "43", QueryFormat: "-T dn,ace %s", UnicodeQueryFormat: "-T dn %s"},
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
	timeout                 time.Duration
	followReferral          bool
	followRegistrarReferral bool
	servers                 map[string]WhoisServer
	dialer                  ContextDialer
}

// Config contains configuration options for the WHOIS client.
type Config struct {
	// Timeout for WHOIS queries (default: 10 seconds). A value that is not
	// positive means the default.
	Timeout time.Duration
	// FollowReferral follows the registry server that IANA names for a TLD
	// the server table does not list.
	FollowReferral bool
	// FollowRegistrarReferral, together with FollowReferral, also follows
	// the registrar's WHOIS server that a registry's reply names, and keeps
	// the registrar's reply when it is longer. Off by default: that second
	// connection costs a round trip per name (a silent registrar costs up to
	// Timeout), and registrars mostly answer with less than the registry.
	// It applies only to a TLD the server table lists (after an IANA
	// referral the registry's answer is final, with this on or off), and it
	// does nothing when FollowReferral is false.
	FollowRegistrarReferral bool
	// CustomServers allows overriding default WHOIS servers. A caller who
	// replaces CustomServers["default"] (whois.iana.org) has that server's
	// referral followed only with FollowRegistrarReferral on, since only a
	// reply from whois.iana.org counts as IANA's.
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
// IANA referral following enabled, the registrar leg off, and an empty
// custom servers map.
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

	// A negative Timeout would leave a custom Dialer's read with no bound.
	if config.Timeout <= 0 {
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
		dialFunc = defaultDialer(config.Timeout)
	}

	return &Client{
		timeout:                 config.Timeout,
		followReferral:          config.FollowReferral,
		followRegistrarReferral: config.FollowRegistrarReferral,
		servers:                 servers,
		dialer:                  dialFunc,
	}, nil
}

// defaultDialer is the plain TCP dialer used when no Dialer or ProxyURL is
// configured. The timeout is captured by value, so a caller that edits its
// Config after NewClient does not change a live client's dial timeout.
func defaultDialer(timeout time.Duration) ContextDialer {
	d := &net.Dialer{Timeout: timeout}
	return d.DialContext
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
// The domain is sent as given (lower-cased and trimmed), never converted
// between its Unicode and xn-- forms; the server table's formats say how
// each form is asked. A result whose Server is "whois.iana.org:43" describes
// the TLD's record, not the domain (its created: and changed: dates are the
// TLD's), except under a TLD IANA itself runs, such as .int.
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

	// Check for referral server. A referral in IANA's answer is how the
	// registry of an unlisted TLD is reached; a referral in any other
	// server's answer is a registry naming the registrar, followed only when
	// the registrar leg is on.
	fromIANA := server.Host == "whois.iana.org"
	if c.followReferral && (fromIANA || c.followRegistrarReferral) {
		if referralServer := c.extractReferralServer(response); referralServer != "" {
			referralResponse, err := c.query(ctx, domain, c.referralServer(referralServer))
			// IANA's answer describes the TLD's registry, never the domain, so
			// the registry it refers to wins even with a short "not found".
			// Between a registry and a registrar the longer answer still wins,
			// so a registrar's rate-limit notice cannot replace a full record.
			if err == nil && strings.TrimSpace(referralResponse) != "" && (fromIANA || len(referralResponse) > len(response)) {
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

	dial := c.dialer
	if dial == nil {
		// A Client not built by NewClient: dial as NewClient would by default,
		// as v1.0.3 always did, instead of panicking on the nil func.
		dial = defaultDialer(c.timeout)
	}
	conn, err := dial(ctx, "tcp", address)
	if err != nil {
		return "", fmt.Errorf("failed to connect to WHOIS server %s: %w", address, err)
	}
	defer conn.Close()

	// A cancelled context closes the connection, so the read below returns at
	// once and not at the deadline.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	// The connection's deadline bounds this leg's write and read, set once
	// the dial has returned: the dial is outside it and has its own bound
	// (the default and proxy dialers use Timeout, a custom Dialer its own),
	// so one leg can take a dial Timeout plus a read Timeout, and a lookup
	// that follows a referral runs two legs. contextBound records which
	// deadline is in force, so a timeout is reported as the context's only
	// when it was.
	ctxDeadline, hasCtxDeadline := ctx.Deadline()
	deadline, contextBound := queryDeadline(time.Now(), c.timeout, ctxDeadline, hasCtxDeadline)
	conn.SetDeadline(deadline)

	// Send the query
	_, err = conn.Write([]byte(server.queryLine(domain)))
	if err != nil {
		if err := stoppedByContext(ctx, contextBound, address, err); err != nil {
			return "", err
		}
		return "", fmt.Errorf("failed to send query: %w", err)
	}

	// Read the response
	var response strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		response.WriteString(scanner.Text())
		response.WriteString("\n")
	}

	// A read cut short by the context is the caller's cancellation or
	// deadline, not a half answer and not a network error.
	if err := stoppedByContext(ctx, contextBound, address, scanner.Err()); err != nil {
		return "", err
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading response: %w", err)
	}

	return response.String(), nil
}

// queryLine is the line sent to the server for domain: the domain written
// into QueryFormat (UnicodeQueryFormat for a name with a character outside
// ASCII, when it has "%s"), or the bare domain, ended with CRLF. A format
// without "%s" is ignored, so a query never goes out without the domain.
func (s WhoisServer) queryLine(domain string) string {
	format := s.QueryFormat
	if strings.Contains(s.UnicodeQueryFormat, "%s") && !isASCII(domain) {
		format = s.UnicodeQueryFormat
	}
	if !strings.Contains(format, "%s") {
		return domain + "\r\n"
	}
	return strings.Replace(format, "%s", domain, 1) + "\r\n"
}

// looksLikeHost reports whether token, the first word of a line under a
// "Name servers:" heading, is shaped like a host name: it holds a dot once
// one trailing dot is trimmed, has no colon, and is not an IP address.
func looksLikeHost(token string) bool {
	name := strings.TrimSuffix(token, ".")
	return strings.Contains(name, ".") && !strings.Contains(name, ":") && net.ParseIP(name) == nil
}

// isASCII reports whether s has no byte outside ASCII.
func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// referralServer is the server a referral names, on the WHOIS port, with
// the query format the table gives that host, so a registry reached through
// IANA is asked the way it would be asked directly.
func (c *Client) referralServer(host string) WhoisServer {
	server := WhoisServer{Host: host, Port: "43"}
	for _, tld := range slices.Sorted(maps.Keys(c.servers)) {
		if known := c.servers[tld]; strings.EqualFold(known.Host, host) && (known.QueryFormat != "" || known.UnicodeQueryFormat != "") {
			server.QueryFormat = known.QueryFormat
			server.UnicodeQueryFormat = known.UnicodeQueryFormat
			break
		}
	}
	return server
}

// queryDeadline picks the connection deadline of one query leg: the earlier
// of the context's deadline and now + timeout, so Timeout bounds the leg in
// every case and the context can only shorten it. On an exact tie the
// context's deadline wins, so a timeout at that instant is always reported as
// the context's. contextBound reports that the context's deadline is the one
// in force.
func queryDeadline(now time.Time, timeout time.Duration, ctxDeadline time.Time, hasCtxDeadline bool) (deadline time.Time, contextBound bool) {
	if timeout > 0 {
		deadline = now.Add(timeout)
	}
	if hasCtxDeadline && (deadline.IsZero() || !ctxDeadline.After(deadline)) {
		return ctxDeadline, true
	}
	return deadline, false
}

// stoppedByContext returns the context's error, wrapped with the server's
// address, when the context ended the query; otherwise nil. When the
// connection's deadline is the context's (contextBound), the connection's
// timer and the context's fire at the same instant and either may wake the
// read first, so a timeout error then also counts as context.DeadlineExceeded.
// Every shape returned satisfies errors.Is with the context's error.
func stoppedByContext(ctx context.Context, contextBound bool, address string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("WHOIS query to %s stopped: %w", address, ctxErr)
	}
	if ne, ok := errors.AsType[net.Error](err); contextBound && ok && ne.Timeout() {
		return fmt.Errorf("WHOIS query to %s stopped: %w", address, context.DeadlineExceeded)
	}
	return nil
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
// looking for "Whois Server:", "Registrar WHOIS Server:", "Referral URL:", or
// "Refer:" fields.
func (c *Client) extractReferralServer(response string) string {
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "whois server:") ||
			strings.HasPrefix(lower, "registrar whois server:") ||
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
	addNameServer := func(ns string) {
		ns = strings.ToLower(ns)
		if !nsMap[ns] {
			nameServers = append(nameServers, ns)
			nsMap[ns] = true
		}
	}

	// section is the heading of the block the line is in, for the formats
	// that put a value on the lines under a bare "Heading:" (Nominet, EURid)
	// instead of after the colon. A blank line ends the block.
	var section string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			section = ""
			continue
		}
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		lower := strings.ToLower(line)

		// A heading has one colon, at its end; an IPv6 address under
		// "Name servers:" can end in "::" but has more than one colon.
		if strings.HasSuffix(lower, ":") && strings.Count(lower, ":") == 1 {
			section = strings.TrimSuffix(lower, ":")
			continue
		}

		switch section {
		case "registrar":
			// Nominet writes the registrar's name on the first line under
			// the heading; EURid writes "Name: <registrar>". The other
			// lines there (URL, Website) are not the name.
			if result.Registrar == "" {
				key, value, hasColon := strings.Cut(line, ":")
				switch {
				case !hasColon:
					result.Registrar = line
				case strings.EqualFold(strings.TrimSpace(key), "name"):
					result.Registrar = strings.TrimSpace(value)
				}
			}
		case "name servers":
			// One server per line, its addresses after it. Only a line whose
			// first word looks like a host name is a server: a dot once one
			// trailing dot is set aside ("None." is not a host), no colon,
			// and not an IP address. The server is stored as written,
			// trailing dot included, as the "Name Server:" rule stores it. A
			// "key: value" line (nserver:, changed:, DNS:) falls through to
			// the rules below, which read it or not as they would anywhere
			// else; any other line ("No name servers listed.", an address
			// first) is read by nothing.
			fields := strings.Fields(line)
			if len(fields) > 0 && looksLikeHost(fields[0]) {
				addNameServer(fields[0])
				continue
			}
			if !strings.Contains(line, ":") {
				continue
			}
		}

		// Nominet's creation date and DENIC's change date.
		if result.CreatedDate == "" && strings.HasPrefix(lower, "registered on:") {
			result.CreatedDate = strings.TrimSpace(line[len("registered on:"):])
		}
		// A changed: line fills UpdatedDate only when no earlier line gave
		// an update date, so a contact's or a TLD record's changed: further
		// down never replaces the domain's; with no earlier date it is taken.
		if result.UpdatedDate == "" && strings.HasPrefix(lower, "changed:") {
			result.UpdatedDate = strings.TrimSpace(line[len("changed:"):])
		}

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
				// Remove any additional info after whitespace
				if idx := strings.Index(ns, " "); idx > 0 {
					ns = ns[:idx]
				}
				addNameServer(ns)
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
