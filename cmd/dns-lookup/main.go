package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hellenic-development/dns-lookup/pkg/dns"
	"github.com/hellenic-development/dns-lookup/pkg/lookup"
	"github.com/hellenic-development/dns-lookup/pkg/whois"
)

const (
	version = "1.0.1"
	banner  = `
╔═══════════════════════════════════════╗
║   DNS Lookup & WHOIS Tool v%s    ║
╚═══════════════════════════════════════╝
`
)

type options struct {
	domain         string
	recordType     string
	whoisOnly      bool
	dnsOnly        bool
	all            bool
	jsonOutput     bool
	timeout        int
	customResolver string
	followReferral bool
	srv            string
	showVersion    bool
}

func main() {
	opts := parseFlags()

	if opts.showVersion {
		fmt.Printf("dns-lookup version %s\n", version)
		os.Exit(0)
	}

	if opts.domain == "" && opts.srv == "" {
		fmt.Println("Error: domain is required")
		flag.Usage()
		os.Exit(1)
	}

	// Print banner for non-JSON output
	if !opts.jsonOutput {
		fmt.Printf(banner, version)
		fmt.Println()
	}

	// Create client configuration
	config := &lookup.Config{
		DNS: &dns.Config{
			Timeout:        time.Duration(opts.timeout) * time.Second,
			CustomResolver: opts.customResolver,
		},
		WHOIS: &whois.Config{
			Timeout:        time.Duration(opts.timeout) * time.Second,
			FollowReferral: opts.followReferral,
		},
	}

	client, err := lookup.NewClient(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// Handle SRV lookup
	if opts.srv != "" {
		handleSRVLookup(ctx, client, opts)
		return
	}

	// Handle different lookup modes
	if opts.all {
		handleAllLookup(ctx, client, opts)
	} else if opts.whoisOnly {
		handleWhoisLookup(ctx, client, opts)
	} else {
		// Default: DNS lookup only for specified record type
		handleDNSLookup(ctx, client, opts)
	}
}

func parseFlags() *options {
	opts := &options{}

	flag.StringVar(&opts.domain, "domain", "", "Domain to lookup (required)")
	flag.StringVar(&opts.domain, "d", "", "Domain to lookup (shorthand)")
	flag.StringVar(&opts.recordType, "type", "A", "DNS record type (A, AAAA, CNAME, MX, NS, TXT, PTR)")
	flag.StringVar(&opts.recordType, "t", "A", "DNS record type (shorthand)")
	flag.BoolVar(&opts.whoisOnly, "whois", false, "Perform WHOIS lookup only")
	flag.BoolVar(&opts.whoisOnly, "w", false, "Perform WHOIS lookup only (shorthand)")
	flag.BoolVar(&opts.dnsOnly, "dns", false, "Perform DNS lookup only")
	flag.BoolVar(&opts.all, "all", false, "Perform all DNS record type lookups + WHOIS")
	flag.BoolVar(&opts.all, "a", false, "Perform all lookups (shorthand)")
	flag.BoolVar(&opts.jsonOutput, "json", false, "Output results in JSON format")
	flag.BoolVar(&opts.jsonOutput, "j", false, "Output in JSON format (shorthand)")
	flag.IntVar(&opts.timeout, "timeout", 10, "Timeout in seconds")
	flag.StringVar(&opts.customResolver, "resolver", "", "Custom DNS resolver (e.g., 8.8.8.8:53)")
	flag.BoolVar(&opts.followReferral, "follow", true, "Follow WHOIS referrals")
	flag.StringVar(&opts.srv, "srv", "", "SRV lookup in format: service,proto,name (e.g., xmpp,tcp,example.com)")
	flag.BoolVar(&opts.showVersion, "version", false, "Show version information")
	flag.BoolVar(&opts.showVersion, "v", false, "Show version (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -d example.com                    # DNS A record lookup\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -d example.com -t MX              # DNS MX record lookup\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -d example.com -w                 # WHOIS lookup only\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -d example.com -a                 # All DNS records + WHOIS\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -d example.com -j                 # Output as JSON\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -srv xmpp,tcp,example.com         # SRV record lookup\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -d example.com -resolver 8.8.8.8:53  # Use custom DNS server\n", os.Args[0])
	}

	flag.Parse()

	// Support domain as positional argument
	if opts.domain == "" && flag.NArg() > 0 {
		opts.domain = flag.Arg(0)
	}

	return opts
}

func handleSRVLookup(ctx context.Context, client *lookup.Client, opts *options) {
	parts := strings.Split(opts.srv, ",")
	if len(parts) != 3 {
		fmt.Fprintf(os.Stderr, "Error: SRV format must be: service,proto,name\n")
		os.Exit(1)
	}

	service, proto, name := parts[0], parts[1], parts[2]

	result, err := client.DNSLookupSRV(ctx, service, proto, name)
	if err != nil {
		errorMsg := err.Error()
		// Check if it's a "no such host" error and format it consistently
		if strings.Contains(strings.ToLower(errorMsg), "no such host") {
			errorMsg = fmt.Sprintf("domain not found: %s", name)
		}

		if opts.jsonOutput {
			printJSON(map[string]string{"error": errorMsg})
		} else {
			fmt.Fprintf(os.Stderr, "Error: %s\n", errorMsg)
		}
		os.Exit(1)
	}

	if opts.jsonOutput {
		printJSON(result)
	} else {
		printSRVResult(result)
	}
}

func handleDNSLookup(ctx context.Context, client *lookup.Client, opts *options) {
	recordType := dns.RecordType(strings.ToUpper(opts.recordType))

	result, err := client.DNSLookup(ctx, opts.domain, recordType)
	if err != nil {
		errorMsg := err.Error()
		// Check if it's a "no such host" error and format it consistently
		if strings.Contains(strings.ToLower(errorMsg), "no such host") {
			errorMsg = fmt.Sprintf("domain not found: %s", opts.domain)
		}

		if opts.jsonOutput {
			printJSON(map[string]string{"error": errorMsg})
		} else {
			fmt.Fprintf(os.Stderr, "Error: %s\n", errorMsg)
		}
		os.Exit(1)
	}

	if opts.jsonOutput {
		printJSON(result)
	} else {
		printDNSResult(result)
	}
}

func handleWhoisLookup(ctx context.Context, client *lookup.Client, opts *options) {
	result, err := client.WHOISLookup(ctx, opts.domain)
	if err != nil {
		if opts.jsonOutput {
			printJSON(map[string]string{"error": err.Error()})
		} else {
			fmt.Fprintf(os.Stderr, "Error performing WHOIS lookup: %v\n", err)
		}
		os.Exit(1)
	}

	// Check if domain was not found in WHOIS
	if strings.Contains(strings.ToLower(result.RawResponse), "no match for") {
		errorMsg := fmt.Sprintf("domain not found: %s", opts.domain)
		if opts.jsonOutput {
			printJSON(map[string]string{"error": errorMsg})
		} else {
			fmt.Fprintf(os.Stderr, "Error: %s\n", errorMsg)
		}
		os.Exit(1)
	}

	if opts.jsonOutput {
		printJSON(result)
	} else {
		printWhoisResult(result)
	}
}

func handleAllLookup(ctx context.Context, client *lookup.Client, opts *options) {
	info, err := client.LookupAll(ctx, opts.domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Some lookups failed: %v\n", err)
	}

	if opts.jsonOutput {
		printJSON(info)
	} else {
		printAllResults(info)
	}
}

func printDNSResult(result *dns.LookupResult) {
	fmt.Printf("DNS Lookup Results for: %s\n", result.Domain)
	fmt.Printf("Record Type: %s\n", result.RecordType)
	fmt.Printf("Timestamp: %s\n\n", result.Timestamp.Format(time.RFC3339))

	if result.Error != "" {
		fmt.Printf("Error: %s\n", result.Error)
		return
	}

	if len(result.Records) > 0 {
		fmt.Println("Records:")
		for i, record := range result.Records {
			fmt.Printf("  %d. %s\n", i+1, record)
		}
	}

	if len(result.MXRecords) > 0 {
		fmt.Println("\nMX Records:")
		for i, mx := range result.MXRecords {
			fmt.Printf("  %d. Priority: %d, Host: %s\n", i+1, mx.Pref, mx.Host)
		}
	}

	if len(result.SRVRecords) > 0 {
		fmt.Println("\nSRV Records:")
		for i, srv := range result.SRVRecords {
			fmt.Printf("  %d. Priority: %d, Weight: %d, Port: %d, Target: %s\n",
				i+1, srv.Priority, srv.Weight, srv.Port, srv.Target)
		}
	}
}

func printSRVResult(result *dns.LookupResult) {
	fmt.Printf("SRV Lookup Results for: %s\n", result.Domain)
	fmt.Printf("Timestamp: %s\n\n", result.Timestamp.Format(time.RFC3339))

	if result.Error != "" {
		fmt.Printf("Error: %s\n", result.Error)
		return
	}

	if len(result.SRVRecords) > 0 {
		fmt.Println("SRV Records:")
		for i, srv := range result.SRVRecords {
			fmt.Printf("  %d. Priority: %d, Weight: %d, Port: %d, Target: %s\n",
				i+1, srv.Priority, srv.Weight, srv.Port, srv.Target)
		}
	} else {
		fmt.Println("No SRV records found")
	}
}

func printWhoisResult(result *whois.WhoisResult) {
	fmt.Printf("WHOIS Lookup Results for: %s\n", result.Domain)
	fmt.Printf("Server: %s\n", result.Server)
	fmt.Printf("Timestamp: %s\n\n", result.Timestamp.Format(time.RFC3339))

	if result.Error != "" {
		fmt.Printf("Error: %s\n", result.Error)
		return
	}

	if result.Registrar != "" {
		fmt.Printf("Registrar: %s\n", result.Registrar)
	}

	if result.CreatedDate != "" {
		fmt.Printf("Created Date: %s\n", result.CreatedDate)
	}

	if result.ExpiryDate != "" {
		fmt.Printf("Expiry Date: %s\n", result.ExpiryDate)
	}

	if result.UpdatedDate != "" {
		fmt.Printf("Updated Date: %s\n", result.UpdatedDate)
	}

	if len(result.Status) > 0 {
		fmt.Println("\nStatus:")
		for i, status := range result.Status {
			fmt.Printf("  %d. %s\n", i+1, status)
		}
	}

	if len(result.NameServers) > 0 {
		fmt.Println("\nName Servers:")
		for i, ns := range result.NameServers {
			fmt.Printf("  %d. %s\n", i+1, ns)
		}
	}

	if len(result.Emails) > 0 {
		fmt.Println("\nEmails:")
		for i, email := range result.Emails {
			fmt.Printf("  %d. %s\n", i+1, email)
		}
	}

	fmt.Println("\n" + strings.Repeat("-", 70))
	fmt.Println("Raw WHOIS Response:")
	fmt.Println(strings.Repeat("-", 70))
	fmt.Println(result.RawResponse)
}

func printAllResults(info *lookup.DomainInfo) {
	fmt.Printf("Complete Domain Information for: %s\n", info.Domain)
	fmt.Println(strings.Repeat("=", 70))

	// Print DNS results
	if info.DNS != nil {
		fmt.Println("\n[DNS RECORDS]")
		fmt.Println(strings.Repeat("-", 70))

		for recordType, result := range info.DNS {
			if result.Error == "" && len(result.Records) > 0 {
				fmt.Printf("\n%s Records:\n", recordType)
				for i, record := range result.Records {
					fmt.Printf("  %d. %s\n", i+1, record)
				}
			}
		}
	}

	// Print WHOIS results
	if info.WHOIS != nil {
		fmt.Println("\n\n[WHOIS INFORMATION]")
		fmt.Println(strings.Repeat("-", 70))

		if info.WHOIS.Error != "" {
			fmt.Printf("Error: %s\n", info.WHOIS.Error)
		} else {
			if info.WHOIS.Registrar != "" {
				fmt.Printf("Registrar: %s\n", info.WHOIS.Registrar)
			}
			if info.WHOIS.CreatedDate != "" {
				fmt.Printf("Created: %s\n", info.WHOIS.CreatedDate)
			}
			if info.WHOIS.ExpiryDate != "" {
				fmt.Printf("Expires: %s\n", info.WHOIS.ExpiryDate)
			}
			if info.WHOIS.UpdatedDate != "" {
				fmt.Printf("Updated: %s\n", info.WHOIS.UpdatedDate)
			}

			if len(info.WHOIS.NameServers) > 0 {
				fmt.Println("\nName Servers:")
				for i, ns := range info.WHOIS.NameServers {
					fmt.Printf("  %d. %s\n", i+1, ns)
				}
			}

			if len(info.WHOIS.Status) > 0 {
				fmt.Println("\nStatus:")
				for i, status := range info.WHOIS.Status {
					fmt.Printf("  %d. %s\n", i+1, status)
				}
			}
		}
	}

	if info.Error != "" {
		fmt.Printf("\nWarnings/Errors: %s\n", info.Error)
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
}

func printJSON(v interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}
