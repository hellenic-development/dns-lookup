//go:build ignore
// +build ignore

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/hellenic-development/dns-lookup/pkg/dns"
)

func main() {
	// Create a DNS client with custom configuration
	config := &dns.Config{
		Timeout: 5 * time.Second,
		// Optionally use a custom DNS resolver
		// CustomResolver: "8.8.8.8:53",
	}

	client, err := dns.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create DNS client: %v", err)
	}

	ctx := context.Background()
	domain := "google.com"

	// Example 1: Single A record lookup
	fmt.Println("=== A Record Lookup ===")
	result, err := client.Lookup(ctx, domain, dns.RecordTypeA)
	if err != nil {
		log.Printf("A record lookup failed: %v", err)
	} else {
		fmt.Printf("Domain: %s\n", result.Domain)
		fmt.Printf("A Records: %v\n\n", result.Records)
	}

	// Example 2: MX record lookup
	fmt.Println("=== MX Record Lookup ===")
	mxResult, err := client.Lookup(ctx, domain, dns.RecordTypeMX)
	if err != nil {
		log.Printf("MX record lookup failed: %v", err)
	} else {
		fmt.Printf("Domain: %s\n", mxResult.Domain)
		for i, mx := range mxResult.MXRecords {
			fmt.Printf("MX %d: Priority=%d, Host=%s\n", i+1, mx.Pref, mx.Host)
		}
		fmt.Println()
	}

	// Example 3: NS record lookup
	fmt.Println("=== NS Record Lookup ===")
	nsResult, err := client.Lookup(ctx, domain, dns.RecordTypeNS)
	if err != nil {
		log.Printf("NS record lookup failed: %v", err)
	} else {
		fmt.Printf("Domain: %s\n", nsResult.Domain)
		fmt.Printf("Name Servers: %v\n\n", nsResult.NameServers)
	}

	// Example 4: TXT record lookup
	fmt.Println("=== TXT Record Lookup ===")
	txtResult, err := client.Lookup(ctx, domain, dns.RecordTypeTXT)
	if err != nil {
		log.Printf("TXT record lookup failed: %v", err)
	} else {
		fmt.Printf("Domain: %s\n", txtResult.Domain)
		fmt.Println("TXT Records:")
		for i, txt := range txtResult.Records {
			fmt.Printf("  %d. %s\n", i+1, txt)
		}
		fmt.Println()
	}

	// Example 5: Lookup all common record types
	fmt.Println("=== All Record Types ===")
	allResults, err := client.LookupAll(ctx, domain)
	if err != nil {
		log.Printf("LookupAll failed: %v", err)
	}

	for recordType, result := range allResults {
		if result.Error == "" && len(result.Records) > 0 {
			fmt.Printf("%s Records: %v\n", recordType, result.Records)
		}
	}

	// Example 6: SRV record lookup
	fmt.Println("\n=== SRV Record Lookup ===")
	srvResult, err := client.LookupSRV(ctx, "xmpp-client", "tcp", "google.com")
	if err != nil {
		log.Printf("SRV record lookup failed: %v", err)
	} else {
		fmt.Printf("Domain: %s\n", srvResult.Domain)
		if len(srvResult.SRVRecords) > 0 {
			for i, srv := range srvResult.SRVRecords {
				fmt.Printf("SRV %d: Priority=%d, Weight=%d, Port=%d, Target=%s\n",
					i+1, srv.Priority, srv.Weight, srv.Port, srv.Target)
			}
		} else {
			fmt.Println("No SRV records found")
		}
	}
}
