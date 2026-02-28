//go:build ignore
// +build ignore

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/hellenic-development/dns-lookup/pkg/dns"
	"github.com/hellenic-development/dns-lookup/pkg/lookup"
)

func main() {
	// Create a unified client with custom configuration
	config := &lookup.Config{
		DNS: &dns.Config{
			Timeout: 5 * time.Second,
		},
	}

	client, err := lookup.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	domain := "google.com"

	// Example 1: Complete domain information
	fmt.Println("=== Complete Domain Information ===")
	info, err := client.LookupAll(ctx, domain)
	if err != nil {
		log.Printf("Some lookups failed: %v", err)
	}

	fmt.Printf("Domain: %s\n\n", info.Domain)

	// Display DNS records
	fmt.Println("DNS Records:")
	for recordType, result := range info.DNS {
		if result.Error == "" && len(result.Records) > 0 {
			fmt.Printf("  %s: %v\n", recordType, result.Records)
		}
	}

	// Display WHOIS information
	fmt.Println("\nWHOIS Information:")
	if info.WHOIS != nil && info.WHOIS.Error == "" {
		fmt.Printf("  Registrar: %s\n", info.WHOIS.Registrar)
		fmt.Printf("  Created: %s\n", info.WHOIS.CreatedDate)
		fmt.Printf("  Expires: %s\n", info.WHOIS.ExpiryDate)
		fmt.Printf("  Updated: %s\n", info.WHOIS.UpdatedDate)
		fmt.Printf("  Name Servers: %v\n", info.WHOIS.NameServers)
	}

	// Example 2: Separate DNS and WHOIS lookups
	fmt.Println("\n\n=== Separate Lookups ===")

	// DNS only
	dnsResult, err := client.DNSLookup(ctx, domain, dns.RecordTypeA)
	if err != nil {
		log.Printf("DNS lookup failed: %v", err)
	} else {
		fmt.Printf("A Records: %v\n", dnsResult.Records)
	}

	// WHOIS only
	whoisResult, err := client.WHOISLookup(ctx, domain)
	if err != nil {
		log.Printf("WHOIS lookup failed: %v", err)
	} else {
		fmt.Printf("Registrar: %s\n", whoisResult.Registrar)
	}

	// Example 3: JSON output
	fmt.Println("\n\n=== JSON Output ===")
	jsonData, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal JSON: %v", err)
	} else {
		fmt.Println(string(jsonData))
	}

	// Example 4: Using individual clients
	fmt.Println("\n\n=== Using Individual Clients ===")

	// Access DNS client directly
	dnsClient := client.DNS()
	allDNSResults, err := dnsClient.LookupAll(ctx, domain)
	if err != nil {
		log.Printf("DNS LookupAll failed: %v", err)
	} else {
		fmt.Printf("Found %d DNS record types\n", len(allDNSResults))
	}

	// Access WHOIS client directly
	whoisClient := client.WHOIS()
	whoisInfo, err := whoisClient.Lookup(ctx, domain)
	if err != nil {
		log.Printf("WHOIS lookup failed: %v", err)
	} else {
		fmt.Printf("WHOIS server used: %s\n", whoisInfo.Server)
	}
}
