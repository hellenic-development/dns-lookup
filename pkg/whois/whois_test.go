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
			// whois.nic.google no longer resolves and IANA's record of .app
			// has an empty whois line, so .app and .dev go to IANA.
			name:     "app domain takes the IANA path",
			domain:   "example.app",
			wantHost: "whois.iana.org",
		},
		{
			name:     "dev domain takes the IANA path",
			domain:   "example.dev",
			wantHost: "whois.iana.org",
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
	if want := []string{"127.0.0.1:1"}; !slices.Equal(dialed, want) {
		t.Fatalf("dialed %q, want %q through the configured Dialer", dialed, want)
	}
	if result.Registrar != "Example Registrar, Inc." {
		t.Errorf("Registrar = %q", result.Registrar)
	}
}

// requireQueryUsesDialer fails the test unless a lookup goes through the
// configured Dialer. It runs first in the tests whose servers are real host
// names (the IANA path keys on whois.iana.org), so a query that dials by
// itself is refused at loopback port 1 here and never reaches those hosts.
func requireQueryUsesDialer(t *testing.T) {
	t.Helper()
	var mu sync.Mutex
	var dialed []string
	client, err := NewClient(&Config{
		Timeout:       2 * time.Second,
		CustomServers: loopbackCom,
		Dialer:        pipeDialer(map[string]string{"127.0.0.1:1": "Domain Name: EXAMPLE.COM\n"}, &mu, &dialed),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatalf("probe lookup: %v; query no longer uses the configured Dialer, so this test would dial real servers", err)
	}
	mu.Lock()
	if want := []string{"127.0.0.1:1"}; !slices.Equal(dialed, want) {
		mu.Unlock()
		t.Fatalf("probe dialed %q, want %q; query no longer uses the configured Dialer", dialed, want)
	}
	mu.Unlock()

	// The referral leg is the one that would reach a real host named in a
	// reply, so it is probed too: a registry naming a registrar on loopback,
	// with the registrar leg on, must dial both through the Dialer.
	var referralDialed []string
	referral, err := NewClient(&Config{
		Timeout:                 2 * time.Second,
		FollowReferral:          true,
		FollowRegistrarReferral: true,
		CustomServers:           loopbackCom,
		Dialer: pipeDialer(map[string]string{
			"127.0.0.1:1":  registryWithRegistrar,
			"127.0.0.1:43": "Rate limit exceeded\n",
		}, &mu, &referralDialed),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := referral.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatalf("referral probe lookup: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"127.0.0.1:1", "127.0.0.1:43"}; !slices.Equal(referralDialed, want) {
		t.Fatalf("referral probe dialed %q, want %q; the referral leg no longer uses the configured Dialer", referralDialed, want)
	}
}

// sentQuery is one query line a fake WHOIS server received.
type sentQuery struct {
	address string
	line    string
}

// queryRecorder is pipeDialer that also records the query line each fake
// server received, with its line ending.
func queryRecorder(answers map[string]string, mu *sync.Mutex, sent *[]sentQuery) ContextDialer {
	return func(_ context.Context, _, address string) (net.Conn, error) {
		answer, ok := answers[address]
		if !ok {
			return nil, fmt.Errorf("no fake WHOIS server at %s", address)
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			line, err := bufio.NewReader(server).ReadString('\n')
			mu.Lock()
			*sent = append(*sent, sentQuery{address: address, line: line})
			mu.Unlock()
			if err != nil {
				return
			}
			_, _ = server.Write([]byte(answer))
		}()
		return client, nil
	}
}

// TestQueryWritesTheServersQueryFormat: DENIC is asked with its flags, as
// the default table says, and a server without a format gets the bare name.
func TestQueryWritesTheServersQueryFormat(t *testing.T) {
	denic := DefaultWhoisServers["de"]
	if denic.Host != "whois.denic.de" {
		t.Fatalf("the default .de server is %q, want whois.denic.de", denic.Host)
	}
	var mu sync.Mutex
	var sent []sentQuery
	client, err := NewClient(&Config{
		Timeout: 2 * time.Second,
		CustomServers: map[string]WhoisServer{
			"com": {Host: "127.0.0.1", Port: "1"},
			"de":  {Host: "127.0.0.1", Port: "2", QueryFormat: denic.QueryFormat},
		},
		Dialer: queryRecorder(map[string]string{
			"127.0.0.1:1": "Domain Name: EXAMPLE.COM\n",
			"127.0.0.1:2": "Domain: denic.de\nStatus: connect\n",
		}, &mu, &sent),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	for _, name := range []string{"denic.de", "example.com"} {
		if _, err := client.Lookup(context.Background(), name); err != nil {
			t.Fatalf("Lookup(%s): %v", name, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	want := []sentQuery{
		{address: "127.0.0.1:2", line: "-T dn,ace denic.de\r\n"},
		{address: "127.0.0.1:1", line: "example.com\r\n"},
	}
	if !slices.Equal(sent, want) {
		t.Errorf("sent %q, want %q", sent, want)
	}
}

// TestLookupReferralUsesTheTableQueryFormat: when IANA refers a TLD to a
// server the table knows by host, the referral query uses that server's
// format too.
func TestLookupReferralUsesTheTableQueryFormat(t *testing.T) {
	requireQueryUsesDialer(t)
	var mu sync.Mutex
	var sent []sentQuery
	client, err := NewClient(&Config{
		Timeout:        2 * time.Second,
		FollowReferral: true,
		Dialer: queryRecorder(map[string]string{
			"whois.iana.org:43": "refer:        whois.denic.de\n\ndomain:       ZZ\n",
			"whois.denic.de:43": "Domain: denic.zz\nStatus: connect\n",
		}, &mu, &sent),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Lookup(context.Background(), "denic.zz"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []sentQuery{
		{address: "whois.iana.org:43", line: "denic.zz\r\n"},
		{address: "whois.denic.de:43", line: "-T dn,ace denic.zz\r\n"},
	}
	if !slices.Equal(sent, want) {
		t.Errorf("sent %q, want %q", sent, want)
	}
}

// TestLookupReferralToAnUnlistedHostSendsTheBareName: a referral target the
// table does not know by host is asked with the bare name.
func TestLookupReferralToAnUnlistedHostSendsTheBareName(t *testing.T) {
	requireQueryUsesDialer(t)
	var mu sync.Mutex
	var sent []sentQuery
	client, err := NewClient(&Config{
		Timeout:        2 * time.Second,
		FollowReferral: true,
		Dialer: queryRecorder(map[string]string{
			"whois.iana.org:43": ianaXYZ,
			"whois.nic.xyz:43":  "Domain Name: EXAMPLE.XYZ\n",
		}, &mu, &sent),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Lookup(context.Background(), "example.xyz"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []sentQuery{
		{address: "whois.iana.org:43", line: "example.xyz\r\n"},
		{address: "whois.nic.xyz:43", line: "example.xyz\r\n"},
	}
	if !slices.Equal(sent, want) {
		t.Errorf("sent %q, want %q", sent, want)
	}
}

// TestLookupFollowsOneReferralAtMost: after IANA's referral the registry's
// answer is final, even when it names a registrar and the registrar leg is
// on: two connections, never three.
func TestLookupFollowsOneReferralAtMost(t *testing.T) {
	requireQueryUsesDialer(t)
	var mu sync.Mutex
	var dialed []string
	client, err := NewClient(&Config{
		Timeout:                 2 * time.Second,
		FollowReferral:          true,
		FollowRegistrarReferral: true,
		Dialer: pipeDialer(map[string]string{
			"whois.iana.org:43": ianaXYZ,
			"whois.nic.xyz:43":  "Domain Name: EXAMPLE.XYZ\nRegistrar WHOIS Server: 127.0.0.1\nRegistrar: Registry View Inc.\n",
			"127.0.0.1:43":      "Domain Name: example.xyz\nRegistrar: Registrar View LLC\nA much longer record than the registry's, which would win if it were asked.\n",
		}, &mu, &dialed),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	result, err := client.Lookup(context.Background(), "example.xyz")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if result.Server != "whois.nic.xyz:43" {
		t.Errorf("Server = %q, want the registry IANA referred to", result.Server)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"whois.iana.org:43", "whois.nic.xyz:43"}; !slices.Equal(dialed, want) {
		t.Errorf("dialed %q, want %q", dialed, want)
	}
}

// TestLookupRegistrarLegNeedsFollowReferral: FollowRegistrarReferral does
// nothing while FollowReferral is false.
func TestLookupRegistrarLegNeedsFollowReferral(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	client, err := NewClient(&Config{
		Timeout:                 2 * time.Second,
		FollowRegistrarReferral: true,
		CustomServers:           loopbackCom,
		Dialer: pipeDialer(map[string]string{
			"127.0.0.1:1":  registryWithRegistrar,
			"127.0.0.1:43": "Domain Name: example.com\nRegistrar: Registrar View LLC\nA much longer record than the registry's.\n",
		}, &mu, &dialed),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"127.0.0.1:1"}; !slices.Equal(dialed, want) {
		t.Errorf("dialed %q, want %q", dialed, want)
	}
}

// TestQueryLineNeverDropsTheDomain: a QueryFormat or UnicodeQueryFormat
// without "%s" is ignored, so a query never goes out without the domain.
func TestQueryLineNeverDropsTheDomain(t *testing.T) {
	tests := []struct {
		format  string
		unicode string
		domain  string
		want    string
	}{
		{format: "", domain: "example.de", want: "example.de\r\n"},
		{format: "-T dn,ace %s", domain: "example.de", want: "-T dn,ace example.de\r\n"},
		{format: "-T dn", domain: "example.de", want: "example.de\r\n"},
		{format: "-T dn,ace %s", unicode: "-T dn %s", domain: "bücher.de", want: "-T dn bücher.de\r\n"},
		{format: "-T dn,ace %s", unicode: "-T dn %s", domain: "xn--bcher-kva.de", want: "-T dn,ace xn--bcher-kva.de\r\n"},
		{format: "-T dn,ace %s", unicode: "-T dn", domain: "bücher.de", want: "-T dn,ace bücher.de\r\n"},
		{unicode: "-T dn", domain: "bücher.de", want: "bücher.de\r\n"},
	}
	for _, tt := range tests {
		server := WhoisServer{Host: "whois.example", Port: "43", QueryFormat: tt.format, UnicodeQueryFormat: tt.unicode}
		if got := server.queryLine(tt.domain); got != tt.want {
			t.Errorf("QueryFormat %q, UnicodeQueryFormat %q, domain %q: queryLine = %q, want %q", tt.format, tt.unicode, tt.domain, got, tt.want)
		}
	}
}

// TestQueryWritesTheFormatForTheNamesForm: DENIC refuses a Unicode name sent
// with the ace flag ("Non bijective ace-idn convertible domain") and answers
// an xn-- name sent without it "Status: invalid", so each form is asked with
// its own flags, as the default table says. A server with only QueryFormat
// uses it for a Unicode name too, and a server with neither sends the bare
// name.
func TestQueryWritesTheFormatForTheNamesForm(t *testing.T) {
	denic := DefaultWhoisServers["de"]
	var mu sync.Mutex
	var sent []sentQuery
	client, err := NewClient(&Config{
		Timeout: 2 * time.Second,
		CustomServers: map[string]WhoisServer{
			"com": {Host: "127.0.0.1", Port: "1"},
			"de":  {Host: "127.0.0.1", Port: "2", QueryFormat: denic.QueryFormat, UnicodeQueryFormat: denic.UnicodeQueryFormat},
			"zz":  {Host: "127.0.0.1", Port: "3", QueryFormat: "-x %s"},
		},
		Dialer: queryRecorder(map[string]string{
			"127.0.0.1:1": "Domain Name: EXAMPLE.COM\n",
			"127.0.0.1:2": "Domain: denic.de\nStatus: connect\n",
			"127.0.0.1:3": "Domain: example.zz\n",
		}, &mu, &sent),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	for _, name := range []string{"bücher.de", "xn--bcher-kva.de", "denic.de", "bücher.zz", "bücher.com"} {
		if _, err := client.Lookup(context.Background(), name); err != nil {
			t.Fatalf("Lookup(%s): %v", name, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	want := []sentQuery{
		{address: "127.0.0.1:2", line: "-T dn bücher.de\r\n"},
		{address: "127.0.0.1:2", line: "-T dn,ace xn--bcher-kva.de\r\n"},
		{address: "127.0.0.1:2", line: "-T dn,ace denic.de\r\n"},
		{address: "127.0.0.1:3", line: "-x bücher.zz\r\n"},
		{address: "127.0.0.1:1", line: "bücher.com\r\n"},
	}
	if !slices.Equal(sent, want) {
		t.Errorf("sent %q, want %q", sent, want)
	}
}

// TestLookupReferralUsesTheTableUnicodeFormat: a referral to DENIC's host
// for a Unicode name gets the table's Unicode format.
func TestLookupReferralUsesTheTableUnicodeFormat(t *testing.T) {
	requireQueryUsesDialer(t)
	var mu sync.Mutex
	var sent []sentQuery
	client, err := NewClient(&Config{
		Timeout:        2 * time.Second,
		FollowReferral: true,
		Dialer: queryRecorder(map[string]string{
			"whois.iana.org:43": "refer:        whois.denic.de\n\ndomain:       ZZ\n",
			"whois.denic.de:43": "Domain: bücher.zz\nStatus: connect\n",
		}, &mu, &sent),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Lookup(context.Background(), "bücher.zz"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []sentQuery{
		{address: "whois.iana.org:43", line: "bücher.zz\r\n"},
		{address: "whois.denic.de:43", line: "-T dn bücher.zz\r\n"},
	}
	if !slices.Equal(sent, want) {
		t.Errorf("sent %q, want %q", sent, want)
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
// the host whois.iana.org. requireQueryUsesDialer runs first, so a query that
// stopped using the Dialer fails at loopback before whois.iana.org is dialed.
func TestLookupPrefersTheServerIANAReferredTo(t *testing.T) {
	requireQueryUsesDialer(t)
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
	requireQueryUsesDialer(t)
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
		Timeout:                 2 * time.Second,
		FollowReferral:          true,
		FollowRegistrarReferral: true,
		CustomServers:           loopbackCom,
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
				Timeout:                 2 * time.Second,
				FollowReferral:          true,
				FollowRegistrarReferral: true,
				CustomServers:           loopbackCom,
				Dialer:                  pipeDialer(tt.answers, &mu, &dialed),
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
			// The registry must win after the registrar was asked, not
			// because the registrar leg never ran.
			mu.Lock()
			defer mu.Unlock()
			if want := []string{"127.0.0.1:1", "127.0.0.1:43"}; !slices.Equal(dialed, want) {
				t.Errorf("dialed %q, want %q: the registrar leg was on", dialed, want)
			}
		})
	}
}

// TestLookupRegistrarLegIsOptIn: a registry reply that names a registrar's
// WHOIS server costs one connection under the default config, and two only
// when FollowRegistrarReferral is set. The live probe measured that leg at
// 50 ms to 2.2 s per name, and up to the read timeout on a silent registrar.
func TestLookupRegistrarLegIsOptIn(t *testing.T) {
	registrar := "Domain Name: example.com\nRegistrar: Registrar View LLC\n" +
		"Creation Date: 1995-08-14T04:00:00Z\nRegistrant Organization: Example Org\nA longer record than the registry's.\n"
	tests := []struct {
		name       string
		follow     bool
		wantDialed []string
		wantServer string
	}{
		{name: "default config", follow: false, wantDialed: []string{"127.0.0.1:1"}, wantServer: "127.0.0.1:1"},
		{name: "registrar leg on", follow: true, wantDialed: []string{"127.0.0.1:1", "127.0.0.1:43"}, wantServer: "127.0.0.1:43"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var dialed []string
			config := DefaultConfig()
			config.FollowRegistrarReferral = tt.follow
			config.CustomServers = loopbackCom
			config.Dialer = pipeDialer(map[string]string{
				"127.0.0.1:1":  registryWithRegistrar,
				"127.0.0.1:43": registrar,
			}, &mu, &dialed)
			client, err := NewClient(config)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			result, err := client.Lookup(context.Background(), "example.com")
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if result.Server != tt.wantServer {
				t.Errorf("Server = %q, want %q", result.Server, tt.wantServer)
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(dialed, tt.wantDialed) {
				t.Errorf("dialed %q, want %q", dialed, tt.wantDialed)
			}
		})
	}
}

// TestNewClientMapsANonPositiveTimeoutToTheDefault: a negative Timeout with a
// custom Dialer would otherwise read with no bound at all.
func TestNewClientMapsANonPositiveTimeoutToTheDefault(t *testing.T) {
	for _, timeout := range []time.Duration{0, -1, -time.Second} {
		client, err := NewClient(&Config{Timeout: timeout, Dialer: silentDialer(nil, true)})
		if err != nil {
			t.Fatalf("NewClient(Timeout %s): %v", timeout, err)
		}
		if client.timeout != 10*time.Second {
			t.Errorf("Timeout %s became %s, want the 10s default", timeout, client.timeout)
		}
	}
}

// TestQueryDeadline: the earlier of the context's deadline and now + Timeout
// is the connection's deadline, and on an exact tie the context's wins, so
// the error at that instant is always the context's.
func TestQueryDeadline(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name             string
		timeout          time.Duration
		ctxDeadline      time.Time
		hasCtxDeadline   bool
		wantDeadline     time.Time
		wantContextBound bool
	}{
		{name: "no context deadline", timeout: time.Second, wantDeadline: now.Add(time.Second)},
		{name: "context earlier", timeout: time.Second, ctxDeadline: now.Add(time.Millisecond), hasCtxDeadline: true, wantDeadline: now.Add(time.Millisecond), wantContextBound: true},
		{name: "timeout earlier", timeout: time.Second, ctxDeadline: now.Add(time.Minute), hasCtxDeadline: true, wantDeadline: now.Add(time.Second)},
		{name: "exact tie", timeout: time.Second, ctxDeadline: now.Add(time.Second), hasCtxDeadline: true, wantDeadline: now.Add(time.Second), wantContextBound: true},
		{name: "no timeout", ctxDeadline: now.Add(time.Minute), hasCtxDeadline: true, wantDeadline: now.Add(time.Minute), wantContextBound: true},
		{name: "neither"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deadline, contextBound := queryDeadline(now, tt.timeout, tt.ctxDeadline, tt.hasCtxDeadline)
			if !deadline.Equal(tt.wantDeadline) || contextBound != tt.wantContextBound {
				t.Errorf("queryDeadline = (%s, %t), want (%s, %t)", deadline, contextBound, tt.wantDeadline, tt.wantContextBound)
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

// nominetBBC is Nominet's reply for bbc.co.uk, as the live probe of
// 2026-11-16 received it. The registrar is on the line after "Registrar:".
const nominetBBC = "\n" +
	"    Domain name:\n" +
	"        bbc.co.uk\n" +
	"\n" +
	"    Data validation:\n" +
	"        Nominet was able to match the registrant's name and address against a 3rd party data source on 12-Jun-2014\n" +
	"\n" +
	"    Registrar:\n" +
	"        British Broadcasting Corporation [Tag = BBC]\n" +
	"        URL: https://www.bbc.co.uk\n" +
	"\n" +
	"    Relevant dates:\n" +
	"        Registered on: before Aug-1996\n" +
	"        Expiry date:  13-Dec-2034\n" +
	"        Last updated:  29-Oct-2025\n" +
	"\n" +
	"    Registration status:\n" +
	"        Registered until expiry date.\n" +
	"\n" +
	"    Name servers:\n" +
	"        ddns0.bbc.co.uk           148.163.199.1  2607:f740:e04e::1\n" +
	"        ddns0.bbc.com\n" +
	"        ddns1.bbc.co.uk           148.163.199.65  2607:f740:e04e:4::1\n" +
	"        ddns1.bbc.com\n" +
	"        dns0.bbc.co.uk            198.51.44.9  2620:4d:4000:6259:7:9:0:1\n" +
	"        dns0.bbc.com\n" +
	"        dns1.bbc.co.uk            198.51.45.9  2a00:edc0:6259:7:9::2\n" +
	"        dns1.bbc.com\n" +
	"\n" +
	"    WHOIS lookup made at 14:34:28 16-Nov-2026\n" +
	"\n" +
	"    ********************************************************************************\n" +
	"    * WHOIS service for .UK will cease on 9th of February 2027                     *\n" +
	"    * For more information on the replacement RDAP services please see:            *\n" +
	"    * https://theukdomain.uk/rdap                                                  *\n" +
	"    ********************************************************************************\n" +
	"\n" +
	"-- \n" +
	"This WHOIS information is provided for free by Nominet UK the central registry\n" +
	"for .uk domain names. This information and the .uk WHOIS are:\n" +
	"\n" +
	"    Copyright Nominet UK 1996 - 2026.\n" +
	"\n" +
	"You may not access the .uk WHOIS or use any data from it except as permitted\n" +
	"by the terms of use available in full at https://www.nominet.uk/whoisterms,\n" +
	"which includes restrictions on: (A) use of the data for advertising, or its\n" +
	"repackaging, recompilation, redistribution or reuse (B) obscuring, removing\n" +
	"or hiding any or all of this notice and (C) exceeding query rate or volume\n" +
	"limits. The data is provided on an 'as-is' basis and may lag behind the\n" +
	"register. Access may be withdrawn or restricted at any time. \n"

// eurIDEuropa is EURid's reply for europa.eu, as the live probe of
// 2026-11-16 received it. EURid's port 43 reply carries no dates at all.
const eurIDEuropa = "% The WHOIS service offered by EURid and the access to the records\n" +
	"% in the EURid WHOIS database are provided for information purposes\n" +
	"% only. It allows persons to check whether a specific domain name\n" +
	"% is still available or not and to obtain information related to\n" +
	"% the registration records of existing domain names.\n" +
	"%\n" +
	"% EURid cannot, under any circumstances, be held liable in case the\n" +
	"% stored information would prove to be wrong, incomplete or not\n" +
	"% accurate in any sense.\n" +
	"%\n" +
	"% By submitting a query, you agree not to use the information made\n" +
	"% available to:\n" +
	"%\n" +
	"% - allow, enable or otherwise support the transmission of unsolicited,\n" +
	"%   commercial advertising or other solicitations whether via email or\n" +
	"%   otherwise;\n" +
	"% - target advertising in any possible way;\n" +
	"% - cause nuisance in any possible way by sending messages to registrants,\n" +
	"%   whether by automated, electronic processes capable of enabling\n" +
	"%   high volumes or by other possible means.\n" +
	"%\n" +
	"% Without prejudice to the above, it is explicitly forbidden to extract,\n" +
	"% copy and/or use or re-utilise in any form and by any means\n" +
	"% (electronically or not) the whole or a quantitatively or qualitatively\n" +
	"% substantial part of the contents of the WHOIS database without prior\n" +
	"% and explicit permission by EURid, nor in any attempt hereof, to apply\n" +
	"% automated, electronic processes to EURid (or its systems).\n" +
	"%\n" +
	"% You agree that any reproduction and/or transmission of data for\n" +
	"% commercial purposes will always be considered as the extraction of a\n" +
	"% substantial part of the content of the WHOIS database.\n" +
	"%\n" +
	"% By submitting the query, you agree to abide by this policy and accept\n" +
	"% that EURid can take measures to limit the use of its WHOIS services\n" +
	"% to protect the privacy of its registrants or the integrity\n" +
	"% of the database.\n" +
	"%\n" +
	"% The EURid WHOIS service on port 43 (textual WHOIS) never discloses\n" +
	"% any information concerning the registrant.\n" +
	"% Registrant and on-site contact information can be obtained through use of the\n" +
	"% web-based WHOIS service available from the EURid website www.eurid.eu\n" +
	"%\n" +
	"% WHOIS europa.eu\n" +
	"Domain: europa.eu\n" +
	"Script: LATIN\n" +
	"\n" +
	"Registrant:\n" +
	"        NOT DISCLOSED!\n" +
	"        Visit www.eurid.eu for the web-based WHOIS.\n" +
	"\n" +
	"Technical:\n" +
	"        Organisation: ClearMedia NV\n" +
	"        Language: nl\n" +
	"        Email: support@clearmedia.be\n" +
	"\n" +
	"Registrar:\n" +
	"        Name: ClearMedia NV\n" +
	"        Website: https://www.clearmedia.be\n" +
	"\n" +
	"Name servers:\n" +
	"        ns1bru.europa.eu (147.67.250.2)\n" +
	"        ns4az2.europa.eu (2a05:d018:c5f:3702:4df4:7b41:c0a1:34e4)\n" +
	"        ns4az2.europa.eu (34.255.155.194)\n" +
	"        ns4az1.europa.eu (2a05:d018:c5f:3701:cc8a:9177:b28:c034)\n" +
	"        ns4az1.europa.eu (54.154.94.36)\n" +
	"        ns3lux.europa.eu (2a01:7080:24:101::2)\n" +
	"        ns3lux.europa.eu (147.67.12.4)\n" +
	"        ns2lux.europa.eu (147.67.12.3)\n" +
	"        ns3bru.europa.eu (2a01:7080:14:101::2)\n" +
	"        ns3bru.europa.eu (147.67.250.4)\n" +
	"        ans2.cw.net\n" +
	"        ns1lux.europa.eu (147.67.12.2)\n" +
	"        ns2bru.europa.eu (147.67.250.3)\n" +
	"        ans1.cw.net\n" +
	"\n" +
	"Keys:\n" +
	"        flags:KSK protocol:3 algorithm:RSA_SHA256 pubKey:AwEAAfKX5A/wIWblwrXsFCDw8WSAZUaxRmB5tQSlhAiTVkPNwhgcCE5ockRYQey6kdPX6YyVw7fDIAZQjzg5efHoKXzvaRWMK1XC09NXrIrnIkLVE7c6twDnEJBAd61kGablPeKR8sVOOJ7yFiISioat+t5woQCozU9c9w8RNKKHFuhdlega9qsWxxqaRI36ok6cFmEEPpOtEatgL7JoG4hnHf5UqcNbVb08F3Em0W+7WfcpPKXpWs437Q2GydKRoxg6kwxI/pOtzNxQVS8DNEE4XMTqP3SwkUuVMeqKWUYzrIE9wzzmGRff/9xjAzhC76XfCr1KTmd3WnINMDE4rtDacJE=\n" +
	"        flags:KSK protocol:3 algorithm:RSA_SHA256 pubKey:AwEAAd6ILwCObzteZw4iDDFF5Ab0GGaEvtogmEvjNeZyjczgtq641zpu38BNDMmgRM6tDqoYtphAoqWjEUkI8XiTYW6go+VGtqY06VDdX5+Hl0l2YOAAxKUo6EYlB9nos5wzKD5FeEYaBP2UCmyzk1hZyfTIOcLXkZt1uUQF7l3MmQ1ETB38pOvbwxU0EQVKuG9YmKKogjW7Ujab4JFIVxqyN+Fxhh7isrceHce0ITryL8e64wVwX9GQNA3zLxK7XQvOJswv82ebYwsl8PmIRwi7hkpJMuz+oQe/i5E6xLpAXRfCDENrcHgXi9FbRmC9Vk9RVU82BpYfrsoNZSNSeRDrJl5iftwtacOpf+QvaI1je7O5cd0VwehjteT9Rfs0Gx27WlZ7KBw7ZurwLdosvNUjKzzvLpmUiKvEyicmgZ+5cGYSTAIdhcAri+mKVpN776qeF2v6fOSEtHFK/Bpu7HMO6FQ3e7KtFiQPMdYe6WSaXODA1EoVHX2IcSNhxnMuhvt7QUaPLVfs0kbzhd2XlZH56D07kLLNAsnwl6ZeBnoqbe/vlio8/HXzDFlPmWTTUqLbPNdx0kfqbQEmkc1IRHnB0upy6/Vve86K9cl4FBW2eYdWZprm2c+ZdEJXsVAGo3w4LutKFjHLweABS0y/BNQN0a0Ga8GVTzmKK9csklZRqj3d\n" +
	"\n" +
	"Please visit www.eurid.eu for more info.\n"

// denicBuecher is DENIC's reply to "-T dn bücher.de", as the live probe of
// 2026-11-16 received it (the saved copy mangled the ü through a console
// code page; it is written as UTF-8 here). A query without -T dn gets only
// the Domain and Status lines.
const denicBuecher = "% Restricted rights.\n" +
	"% \n" +
	"% Terms and Conditions of Use\n" +
	"% \n" +
	"% The above data may only be used within the scope of technical or\n" +
	"% administrative necessities of Internet operation or to remedy legal\n" +
	"% problems.\n" +
	"% The use for other purposes, in particular for advertising, is not permitted.\n" +
	"% \n" +
	"% The DENIC whois service on port 43 doesn't disclose any information concerning\n" +
	"% the domain holder, general request and abuse contact.\n" +
	"% This information can be obtained through use of our web-based whois service\n" +
	"% available at the DENIC website:\n" +
	"% https://webwhois.denic.de/?lang=en\n" +
	"% \n" +
	"% \n" +
	"\n" +
	"Domain: bücher.de\n" +
	"Domain-Ace: xn--bcher-kva.de\n" +
	"Nserver: ken.ns.cloudflare.com\n" +
	"Nserver: sasha.ns.cloudflare.com\n" +
	"Status: connect\n" +
	"Changed: 2026-01-22T11:29:42+01:00\n" +
	"\n"

// nominetNotFound is Nominet's reply for a .co.uk name that is not
// registered, as the live probe of 2026-11-16 received it.
const nominetNotFound = "\n" +
	"    No match for \"ygaltjzmoqsoeocapgfl.co.uk\".\n" +
	"\n" +
	"    This domain name has not been registered.\n" +
	"\n" +
	"    WHOIS lookup made at 14:34:28 16-Nov-2026\n" +
	"\n" +
	"    ********************************************************************************\n" +
	"    * WHOIS service for .UK will cease on 9th of February 2027                     *\n" +
	"    * For more information on the replacement RDAP services please see:            *\n" +
	"    * https://theukdomain.uk/rdap                                                  *\n" +
	"    ********************************************************************************\n" +
	"\n" +
	"-- \n" +
	"This WHOIS information is provided for free by Nominet UK the central registry\n" +
	"for .uk domain names. This information and the .uk WHOIS are:\n" +
	"\n" +
	"    Copyright Nominet UK 1996 - 2026.\n" +
	"\n" +
	"You may not access the .uk WHOIS or use any data from it except as permitted\n" +
	"by the terms of use available in full at https://www.nominet.uk/whoisterms,\n" +
	"which includes restrictions on: (A) use of the data for advertising, or its\n" +
	"repackaging, recompilation, redistribution or reuse (B) obscuring, removing\n" +
	"or hiding any or all of this notice and (C) exceeding query rate or volume\n" +
	"limits. The data is provided on an 'as-is' basis and may lag behind the\n" +
	"register. Access may be withdrawn or restricted at any time. \n"

// TestParseRegistryFormats reads the registry replies the live probe saved,
// plus reply shapes (written from the registries' formats, not saved
// replies) that test the "Name servers:" block rule. TestParseResponse keeps
// the Verisign-style format in check.
func TestParseRegistryFormats(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		registrar   string
		created     string
		expiry      string
		updated     string
		nameServers []string
		status      []string
		emails      []string
	}{
		{
			name: "Nominet .co.uk not found",
			raw:  nominetNotFound,
		},
		{
			// Shape: Nominet's block for a name with no delegation.
			name: "name servers block with a sentence line",
			raw:  "    Name servers:\n        No name servers listed.\n\n",
		},
		{
			// Shape: a "key: value" line under the heading falls through to
			// the older rules, which read nserver: and changed:.
			name:        "name servers block with lines an older rule reads",
			raw:         "Name servers:\n    nserver: ns1.example.ee\n    nserver: ns2.example.ee\n    changed: 2020-05-06T07:08:09Z\n",
			updated:     "2020-05-06T07:08:09Z",
			nameServers: []string{"ns1.example.ee", "ns2.example.ee"},
		},
		{
			// Shape: a sentence ending in a dot is not a host.
			name: "name servers block with a one-word sentence",
			raw:  "Name servers:\n    None.\n",
		},
		{
			// Shape: an address before the server's name is not a server.
			name: "name servers block with an address first",
			raw:  "Name servers:\n    192.0.2.1 ns1.example.com\n",
		},
		{
			// A server written with a trailing dot is stored as the older
			// "Name Server:" rule stores it (trailing dot kept, lower-cased),
			// so the two collapse into one entry.
			name:        "name servers block with a trailing-dot server",
			raw:         "Name servers:\n    NS1.Example.COM.\n\nName Server: ns1.example.com.\n",
			nameServers: []string{"ns1.example.com."},
		},
		{
			// Shape: whois.mx's "DNS:" lines, which no rule reads.
			name: "name servers block with lines no rule reads",
			raw:  "Name servers:\n    DNS: ns1.example.mx\n    DNS: ns2.example.mx\n",
		},
		{
			// A later changed: line (a contact's or a TLD record's) never
			// replaces the update date an earlier line gave.
			name:    "first update date wins over a later changed line",
			raw:     "Updated Date: 2024-01-01T00:00:00Z\n\ncontact: technical\nchanged: 2019-03-04\n",
			updated: "2024-01-01T00:00:00Z",
		},
		{
			name:      "Nominet .co.uk",
			raw:       nominetBBC,
			registrar: "British Broadcasting Corporation [Tag = BBC]",
			created:   "before Aug-1996",
			expiry:    "13-Dec-2034",
			updated:   "29-Oct-2025",
			nameServers: []string{
				"ddns0.bbc.co.uk", "ddns0.bbc.com", "ddns1.bbc.co.uk", "ddns1.bbc.com",
				"dns0.bbc.co.uk", "dns0.bbc.com", "dns1.bbc.co.uk", "dns1.bbc.com",
			},
		},
		{
			name:      "EURid .eu",
			raw:       eurIDEuropa,
			registrar: "ClearMedia NV",
			nameServers: []string{
				"ns1bru.europa.eu", "ns4az2.europa.eu", "ns4az1.europa.eu", "ns3lux.europa.eu", "ns2lux.europa.eu",
				"ns3bru.europa.eu", "ans2.cw.net", "ns1lux.europa.eu", "ns2bru.europa.eu", "ans1.cw.net",
			},
			emails: []string{"support@clearmedia.be"},
		},
		{
			name:        "DENIC .de with -T dn",
			raw:         denicBuecher,
			updated:     "2026-01-22T11:29:42+01:00",
			nameServers: []string{"ken.ns.cloudflare.com", "sasha.ns.cloudflare.com"},
			status:      []string{"connect"},
		},
	}
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &WhoisResult{RawResponse: tt.raw, ParsedData: make(map[string]interface{})}
			client.parseResponse(result)
			if result.Registrar != tt.registrar {
				t.Errorf("Registrar = %q, want %q", result.Registrar, tt.registrar)
			}
			if result.CreatedDate != tt.created {
				t.Errorf("CreatedDate = %q, want %q", result.CreatedDate, tt.created)
			}
			if result.ExpiryDate != tt.expiry {
				t.Errorf("ExpiryDate = %q, want %q", result.ExpiryDate, tt.expiry)
			}
			if result.UpdatedDate != tt.updated {
				t.Errorf("UpdatedDate = %q, want %q", result.UpdatedDate, tt.updated)
			}
			if !slices.Equal(result.NameServers, tt.nameServers) {
				t.Errorf("NameServers = %q, want %q", result.NameServers, tt.nameServers)
			}
			if !slices.Equal(result.Status, tt.status) {
				t.Errorf("Status = %q, want %q", result.Status, tt.status)
			}
			if !slices.Equal(result.Emails, tt.emails) {
				t.Errorf("Emails = %q, want %q", result.Emails, tt.emails)
			}
		})
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
