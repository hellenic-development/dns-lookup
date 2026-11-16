package whois

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
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
				Timeout: 5 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "custom server",
			config: &Config{
				CustomServers: map[string]WhoisServer{
					"test": {Host: "whois.test.com", Port: "43"},
				},
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

func TestGetWhoisServer(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	tests := []struct {
		name     string
		domain   string
		wantHost string
		wantErr  bool
	}{
		{
			name:     "com domain",
			domain:   "example.com",
			wantHost: "whois.verisign-grs.com",
			wantErr:  false,
		},
		{
			name:     "org domain",
			domain:   "example.org",
			wantHost: "whois.pir.org",
			wantErr:  false,
		},
		{
			name:     "co.uk domain",
			domain:   "example.co.uk",
			wantHost: "whois.nic.uk",
			wantErr:  false,
		},
		{
			name:     "io domain",
			domain:   "example.io",
			wantHost: "whois.nic.io",
			wantErr:  false,
		},
		{
			name:    "invalid domain",
			domain:  "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := client.getWhoisServer(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("getWhoisServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && server.Host != tt.wantHost {
				t.Errorf("getWhoisServer() host = %v, want %v", server.Host, tt.wantHost)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	// Skip in short mode as this makes real network calls
	if testing.Short() {
		t.Skip("Skipping WHOIS lookup test in short mode")
	}

	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	result, err := client.Lookup(ctx, "google.com")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	if result.Domain != "google.com" {
		t.Errorf("Expected domain google.com, got %s", result.Domain)
	}

	if result.RawResponse == "" {
		t.Error("Expected non-empty raw response")
	}

	t.Logf("WHOIS server: %s", result.Server)
	t.Logf("Registrar: %s", result.Registrar)
	t.Logf("Created: %s", result.CreatedDate)
	t.Logf("Expires: %s", result.ExpiryDate)
	t.Logf("Name servers: %v", result.NameServers)
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
	_, err = client.Lookup(ctx, "google.com")
	// We expect this might timeout, but we're just testing it doesn't panic
	t.Logf("Lookup with short timeout result: %v", err)
}

func TestExtractReferralServer(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	tests := []struct {
		name     string
		response string
		want     string
	}{
		{
			name:     "whois server format",
			response: "Whois Server: whois.example.com",
			want:     "whois.example.com",
		},
		{
			name:     "referral url format",
			response: "Referral URL: whois://whois.example.com",
			want:     "whois.example.com",
		},
		{
			name:     "refer format",
			response: "Refer: whois.example.com",
			want:     "whois.example.com",
		},
		{
			name:     "no referral",
			response: "Some other content",
			want:     "",
		},
		{
			name:     "iana server ignored",
			response: "Whois Server: whois.iana.org",
			want:     "",
		},
		{
			name:     "registrar whois server format",
			response: "Registrar WHOIS Server: whois.markmonitor.com",
			want:     "whois.markmonitor.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.extractReferralServer(tt.response)
			if got != tt.want {
				t.Errorf("extractReferralServer() = %v, want %v", got, tt.want)
			}
		})
	}
}

// pipeDialer serves each WHOIS address from a table over net.Pipe, so a
// lookup and its referral run without the network. It records every address
// dialed.
func pipeDialer(answers map[string]string, mu *sync.Mutex, dialed *[]string) ContextDialer {
	return func(_ context.Context, _, address string) (net.Conn, error) {
		mu.Lock()
		*dialed = append(*dialed, address)
		mu.Unlock()
		answer, ok := answers[address]
		if !ok {
			return nil, fmt.Errorf("no fake WHOIS server at %s", address)
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			if _, err := bufio.NewReader(server).ReadString('\n'); err != nil {
				return
			}
			_, _ = server.Write([]byte(answer))
		}()
		return client, nil
	}
}

// loopbackCom points .com at a closed loopback port, so a query that ever
// dials by itself instead of through the configured Dialer is refused at once
// and never reaches a real WHOIS server.
var loopbackCom = map[string]WhoisServer{"com": {Host: "127.0.0.1", Port: "1"}}

// silentDialer hands out pipes whose far end says nothing until hold closes.
// With takeQuery the far end reads the query first; without it the far end
// never reads, so the query's write blocks until the connection is closed.
func silentDialer(hold <-chan struct{}, takeQuery bool) ContextDialer {
	return func(_ context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			if takeQuery {
				_, _ = bufio.NewReader(server).ReadString('\n')
			}
			<-hold
		}()
		return client, nil
	}
}

func TestLookupUsesConfiguredDialer(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	client, err := NewClient(&Config{
		Timeout:       2 * time.Second,
		CustomServers: loopbackCom,
		Dialer: pipeDialer(map[string]string{
			"127.0.0.1:1": "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\nCreation Date: 1995-08-14T04:00:00Z\n",
		}, &mu, &dialed),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	result, err := client.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) == 0 {
		t.Fatal("the configured Dialer was never called; query dialed the network itself")
	}
	if result.Registrar != "Example Registrar, Inc." {
		t.Errorf("Registrar = %q", result.Registrar)
	}
}

// ianaXYZ is IANA's record of the .xyz registry: it refers to whois.nic.xyz
// and carries the registry's own dates, never the domain's.
const ianaXYZ = "% IANA WHOIS server\n\nrefer:        whois.nic.xyz\n\ndomain:       XYZ\n\norganisation: XYZ.COM LLC\n" +
	"address:      2121 E. Tropicana Ave\n\ncontact:      administrative\nname:         Domain Administrator\n\n" +
	"status:       ACTIVE\nremarks:      Registration information: http://nic.xyz\n\ncreated:      2014-03-20\nsource:       IANA\n"

// TestLookupPrefersTheServerIANAReferredTo cannot be made loopback-safe by
// configuration the way the .com tests are: overriding the "default" server
// with a loopback address would also switch off the IANA rule, which keys on
// the host whois.iana.org. With the fixed query it is hermetic; it would dial
// whois.iana.org and whois.nic.xyz only if query stopped using the Dialer.
func TestLookupPrefersTheServerIANAReferredTo(t *testing.T) {
	iana := ianaXYZ
	var mu sync.Mutex
	var dialed []string
	client, err := NewClient(&Config{
		Timeout:        2 * time.Second,
		FollowReferral: true,
		Dialer: pipeDialer(map[string]string{
			"whois.iana.org:43": iana,
			"whois.nic.xyz:43":  "The queried object does not exist: DOMAIN NOT FOUND\n",
		}, &mu, &dialed),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	result, err := client.Lookup(context.Background(), "no-such-name-4821.xyz")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if result.Server != "whois.nic.xyz:43" {
		t.Errorf("Server = %q, want the registry IANA referred to", result.Server)
	}
	if result.CreatedDate != "" {
		t.Errorf("CreatedDate %q came from IANA's record of the .xyz registry, not from the domain", result.CreatedDate)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"whois.iana.org:43", "whois.nic.xyz:43"}; !slices.Equal(dialed, want) {
		t.Errorf("dialed %q, want %q: the lookup must go through IANA and then the registry it referred to", dialed, want)
	}
}

// TestLookupKeepsIANAWhenTheRegistryAnswersBlank: a registry that IANA refers
// to and that answers nothing leaves IANA's record in place, with IANA as the
// server and no error, so the caller can still say what it learned.
func TestLookupKeepsIANAWhenTheRegistryAnswersBlank(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	client, err := NewClient(&Config{
		Timeout:        2 * time.Second,
		FollowReferral: true,
		Dialer: pipeDialer(map[string]string{
			"whois.iana.org:43": ianaXYZ,
			"whois.nic.xyz:43":  " \n\n",
		}, &mu, &dialed),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	result, err := client.Lookup(context.Background(), "no-such-name-4821.xyz")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if result.Server != "whois.iana.org:43" {
		t.Errorf("Server = %q, want IANA's address when the registry answered blank", result.Server)
	}
	if result.RawResponse != ianaXYZ {
		t.Errorf("RawResponse = %q, want IANA's record unchanged", result.RawResponse)
	}
}

// registryWithRegistrar is a .com registry answer that points at a registrar
// on loopback port 43 (the referral port is fixed), so the registrar leg is
// served by the pipe table and never by a real server.
const registryWithRegistrar = "Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: 127.0.0.1\nRegistrar: Registry View Inc.\n"

func TestLookupPrefersALongerRegistrarAnswer(t *testing.T) {
	registrar := "Domain Name: example.com\nRegistrar WHOIS Server: 127.0.0.1\nRegistrar: Registrar View LLC\n" +
		"Creation Date: 1995-08-14T04:00:00Z\nRegistrant Organization: Example Org\n"
	var mu sync.Mutex
	var dialed []string
	client, err := NewClient(&Config{
		Timeout:        2 * time.Second,
		FollowReferral: true,
		CustomServers:  loopbackCom,
		Dialer: pipeDialer(map[string]string{
			"127.0.0.1:1":  registryWithRegistrar,
			"127.0.0.1:43": registrar,
		}, &mu, &dialed),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	result, err := client.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if result.Server != "127.0.0.1:43" {
		t.Errorf("Server = %q, want the registrar whose answer is longer", result.Server)
	}
	if result.Registrar != "Registrar View LLC" {
		t.Errorf("Registrar = %q, want the registrar's record", result.Registrar)
	}
}

func TestLookupKeepsTheRegistryWhenTheRegistrarIsShorterOrFails(t *testing.T) {
	tests := []struct {
		name    string
		answers map[string]string
	}{
		{
			name: "registrar answers shorter",
			answers: map[string]string{
				"127.0.0.1:1":  registryWithRegistrar,
				"127.0.0.1:43": "Rate limit exceeded\n",
			},
		},
		{
			name:    "registrar fails",
			answers: map[string]string{"127.0.0.1:1": registryWithRegistrar},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var dialed []string
			client, err := NewClient(&Config{
				Timeout:        2 * time.Second,
				FollowReferral: true,
				CustomServers:  loopbackCom,
				Dialer:         pipeDialer(tt.answers, &mu, &dialed),
			})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			result, err := client.Lookup(context.Background(), "example.com")
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if result.Server != "127.0.0.1:1" {
				t.Errorf("Server = %q, want the registry", result.Server)
			}
			if result.RawResponse != registryWithRegistrar {
				t.Errorf("RawResponse = %q, want the registry's record", result.RawResponse)
			}
		})
	}
}

// TestLookupEndsWhenTheContextDoes: a registry that takes the query and then
// says nothing must not hold the caller until the read deadline.
func TestLookupEndsWhenTheContextDoes(t *testing.T) {
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	client, err := NewClient(&Config{Timeout: 10 * time.Second, CustomServers: loopbackCom, Dialer: silentDialer(hold, true)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)

	start := time.Now()
	_, err = client.Lookup(ctx, "example.com")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Lookup error = %v, want one that is context.Canceled", err)
	}
	if waited := time.Since(start); waited > 3*time.Second {
		t.Fatalf("Lookup waited %s on a silent server after cancel; it must end with the context", waited)
	}
}

// TestLookupEndsAtTheContextDeadline: when the context's deadline ends the
// read, the error is the deadline whichever of the two timers set to that
// instant (the connection's and the context's) fired first.
func TestLookupEndsAtTheContextDeadline(t *testing.T) {
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	client, err := NewClient(&Config{Timeout: 10 * time.Second, CustomServers: loopbackCom, Dialer: silentDialer(hold, true)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = client.Lookup(ctx, "example.com")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Lookup error = %v, want one that is context.DeadlineExceeded", err)
	}
	if waited := time.Since(start); waited > 3*time.Second {
		t.Fatalf("Lookup waited %s on a silent server past its deadline", waited)
	}
}

// TestLookupTimeoutBoundsAReadUnderALongContextDeadline: Config.Timeout bounds
// one query even when the context's deadline is far later, and the error is
// the read timeout, not the context's.
func TestLookupTimeoutBoundsAReadUnderALongContextDeadline(t *testing.T) {
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	client, err := NewClient(&Config{Timeout: 100 * time.Millisecond, CustomServers: loopbackCom, Dialer: silentDialer(hold, true)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	_, err = client.Lookup(ctx, "example.com")
	if waited := time.Since(start); waited > 3*time.Second {
		t.Fatalf("Lookup waited %s on a silent server; Config.Timeout of 100ms must bound it under a 30s context", waited)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Lookup error = %v, want the read timeout", err)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Errorf("Lookup error = %v is a context error; the context had not ended", err)
	}
}

// TestLookupCancelledBeforeItStarts: a context already cancelled when Lookup
// is called, through a dialer that ignores the context, ends the query in its
// write with the context's error, not a send failure.
func TestLookupCancelledBeforeItStarts(t *testing.T) {
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	client, err := NewClient(&Config{Timeout: 10 * time.Second, CustomServers: loopbackCom, Dialer: silentDialer(hold, false)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = client.Lookup(ctx, "example.com")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Lookup error = %v, want one that is context.Canceled", err)
	}
}

// TestLookupZeroValueClientDoesNotPanic: a Client not built by NewClient has
// no dialer; query falls back to the default one NewClient would build, as
// v1.0.3 dialed with a plain net.Dialer. The .com server is a closed loopback
// port, so the dial is refused at once.
func TestLookupZeroValueClientDoesNotPanic(t *testing.T) {
	client := &Client{servers: loopbackCom}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.Lookup(ctx, "example.com")
	if err == nil || !strings.Contains(err.Error(), "failed to connect to WHOIS server 127.0.0.1:1") {
		t.Fatalf("Lookup error = %v, want a refused connection to 127.0.0.1:1", err)
	}
}

func TestParseResponse(t *testing.T) {
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	result := &WhoisResult{
		Domain: "example.com",
		RawResponse: `Registrar: Example Registrar Inc.
Creation Date: 2020-01-01T00:00:00Z
Expiry Date: 2025-01-01T00:00:00Z
Updated Date: 2024-01-01T00:00:00Z
Name Server: ns1.example.com
Name Server: ns2.example.com
Status: clientTransferProhibited
Status: clientUpdateProhibited
Admin Email: admin@example.com
`,
		ParsedData: make(map[string]interface{}),
	}

	client.parseResponse(result)

	if result.Registrar != "Example Registrar Inc." {
		t.Errorf("Expected registrar 'Example Registrar Inc.', got '%s'", result.Registrar)
	}

	if result.CreatedDate != "2020-01-01T00:00:00Z" {
		t.Errorf("Expected created date '2020-01-01T00:00:00Z', got '%s'", result.CreatedDate)
	}

	if result.ExpiryDate != "2025-01-01T00:00:00Z" {
		t.Errorf("Expected expiry date '2025-01-01T00:00:00Z', got '%s'", result.ExpiryDate)
	}

	if len(result.NameServers) != 2 {
		t.Errorf("Expected 2 name servers, got %d", len(result.NameServers))
	}

	if len(result.Status) != 2 {
		t.Errorf("Expected 2 status values, got %d", len(result.Status))
	}

	if len(result.Emails) == 0 {
		t.Error("Expected at least one email address")
	}
}

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  bool
	}{
		{
			name:  "valid email",
			email: "test@example.com",
			want:  true,
		},
		{
			name:  "valid email with subdomain",
			email: "test@mail.example.com",
			want:  true,
		},
		{
			name:  "invalid - no @",
			email: "testexample.com",
			want:  false,
		},
		{
			name:  "invalid - no domain",
			email: "test@",
			want:  false,
		},
		{
			name:  "invalid - no local part",
			email: "@example.com",
			want:  false,
		},
		{
			name:  "invalid - no TLD",
			email: "test@example",
			want:  false,
		},
		{
			name:  "invalid - too short",
			email: "a@",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidEmail(tt.email)
			if got != tt.want {
				t.Errorf("isValidEmail(%s) = %v, want %v", tt.email, got, tt.want)
			}
		})
	}
}
