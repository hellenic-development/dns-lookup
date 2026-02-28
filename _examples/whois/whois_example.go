//go:build ignore
// +build ignore

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/hellenic-development/dns-lookup/pkg/whois"
)

func main() {
	// Create a WHOIS client with custom configuration
	config := &whois.Config{
		Timeout:        10 * time.Second,
		FollowReferral: true, // Automatically follow referral WHOIS servers
	}

	client, err := whois.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create WHOIS client: %v", err)
	}

	ctx := context.Background()

	// Example 1: Basic WHOIS lookup
	fmt.Println("=== WHOIS Lookup for google.com ===")
	result, err := client.Lookup(ctx, "google.com")
	if err != nil {
		log.Fatalf("WHOIS lookup failed: %v", err)
	}

	fmt.Printf("Domain: %s\n", result.Domain)
	fmt.Printf("WHOIS Server: %s\n", result.Server)
	fmt.Printf("Registrar: %s\n", result.Registrar)
	fmt.Printf("Created Date: %s\n", result.CreatedDate)
	fmt.Printf("Expiry Date: %s\n", result.ExpiryDate)
	fmt.Printf("Updated Date: %s\n", result.UpdatedDate)

	if len(result.NameServers) > 0 {
		fmt.Println("\nName Servers:")
		for i, ns := range result.NameServers {
			fmt.Printf("  %d. %s\n", i+1, ns)
		}
	}

	if len(result.Status) > 0 {
		fmt.Println("\nStatus:")
		for i, status := range result.Status {
			fmt.Printf("  %d. %s\n", i+1, status)
		}
	}

	if len(result.Emails) > 0 {
		fmt.Println("\nEmails:")
		for i, email := range result.Emails {
			fmt.Printf("  %d. %s\n", i+1, email)
		}
	}

	// Example 2: Multiple domain lookups
	fmt.Println("\n\n=== Multiple Domain Lookups ===")
	domains := []string{"github.com", "example.org", "wikipedia.org"}

	for _, domain := range domains {
		result, err := client.Lookup(ctx, domain)
		if err != nil {
			log.Printf("Failed to lookup %s: %v", domain, err)
			continue
		}

		fmt.Printf("\n%s:\n", domain)
		fmt.Printf("  Registrar: %s\n", result.Registrar)
		fmt.Printf("  Created: %s\n", result.CreatedDate)
		fmt.Printf("  Expires: %s\n", result.ExpiryDate)
		fmt.Printf("  Name Servers: %d\n", len(result.NameServers))
	}

	// Example 3: Access raw WHOIS response
	fmt.Println("\n\n=== Raw WHOIS Response ===")
	result, err = client.Lookup(ctx, "example.com")
	if err != nil {
		log.Printf("WHOIS lookup failed: %v", err)
	} else {
		fmt.Printf("Raw response length: %d bytes\n", len(result.RawResponse))
		fmt.Println("\nFirst 500 characters of raw response:")
		if len(result.RawResponse) > 500 {
			fmt.Println(result.RawResponse[:500])
		} else {
			fmt.Println(result.RawResponse)
		}
	}
}
