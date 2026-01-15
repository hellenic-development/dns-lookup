package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/kataras/dns-lookup/pkg/dns"
	"github.com/kataras/dns-lookup/pkg/whois"
)

func main() {
	fmt.Println("=== DNS Lookup and WHOIS with Proxy Support ===\n")

	// Example 1: Using SOCKS5 proxy with ProxyURL
	exampleSOCKS5Proxy()

	// Example 2: Using HTTP proxy with ProxyURL
	exampleHTTPProxy()

	// Example 3: Using custom dialer function
	exampleCustomDialer()

	// Example 4: No proxy (direct connection)
	exampleDirectConnection()
}

func exampleSOCKS5Proxy() {
	fmt.Println("--- Example 1: SOCKS5 Proxy via ProxyURL ---")

	// Configure DNS client with SOCKS5 proxy
	dnsConfig := &dns.Config{
		Timeout:  10 * time.Second,
		ProxyURL: "socks5://localhost:1080", // Replace with your SOCKS5 proxy
	}

	dnsClient, err := dns.NewClient(dnsConfig)
	if err != nil {
		log.Printf("Failed to create DNS client: %v\n", err)
		return
	}

	// Configure WHOIS client with SOCKS5 proxy
	whoisConfig := &whois.Config{
		Timeout:  15 * time.Second,
		ProxyURL: "socks5://localhost:1080", // Replace with your SOCKS5 proxy
	}

	whoisClient, err := whois.NewClient(whoisConfig)
	if err != nil {
		log.Printf("Failed to create WHOIS client: %v\n", err)
		return
	}

	// Perform DNS lookup
	ctx := context.Background()
	result, err := dnsClient.Lookup(ctx, "example.com", dns.RecordTypeA)
	if err != nil {
		log.Printf("DNS lookup failed: %v\n", err)
	} else {
		fmt.Printf("DNS Result: %v\n", result.Records)
	}

	// Perform WHOIS lookup
	whoisResult, err := whoisClient.Lookup(ctx, "example.com")
	if err != nil {
		log.Printf("WHOIS lookup failed: %v\n", err)
	} else {
		fmt.Printf("WHOIS Registrar: %s\n", whoisResult.Registrar)
	}

	fmt.Println()
}

func exampleHTTPProxy() {
	fmt.Println("--- Example 2: HTTP Proxy via ProxyURL ---")

	// Configure with HTTP proxy
	dnsConfig := &dns.Config{
		Timeout:  10 * time.Second,
		ProxyURL: "http://proxy.example.com:8080", // Replace with your HTTP proxy
	}

	dnsClient, err := dns.NewClient(dnsConfig)
	if err != nil {
		log.Printf("Failed to create DNS client: %v\n", err)
		return
	}

	ctx := context.Background()
	result, err := dnsClient.Lookup(ctx, "google.com", dns.RecordTypeA)
	if err != nil {
		log.Printf("DNS lookup failed: %v\n", err)
	} else {
		fmt.Printf("DNS Result: %v\n", result.Records)
	}

	fmt.Println()
}

func exampleCustomDialer() {
	fmt.Println("--- Example 3: Custom Dialer Function ---")

	// Create a custom dialer with specific configuration
	customDialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		// You can add custom logic here, such as:
		// - Custom DNS resolution
		// - Connection pooling
		// - Logging
		// - Custom timeout handling
		// - Routing through specific interfaces
		// - etc.

		fmt.Printf("Custom dialer connecting to %s via %s\n", address, network)

		dialer := &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
			// You can also bind to a specific local address:
			// LocalAddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.100")},
		}

		return dialer.DialContext(ctx, network, address)
	}

	// Configure DNS client with custom dialer
	dnsConfig := &dns.Config{
		Timeout: 10 * time.Second,
		Dialer:  customDialer,
	}

	dnsClient, err := dns.NewClient(dnsConfig)
	if err != nil {
		log.Printf("Failed to create DNS client: %v\n", err)
		return
	}

	// Configure WHOIS client with custom dialer
	whoisConfig := &whois.Config{
		Timeout: 15 * time.Second,
		Dialer:  customDialer,
	}

	whoisClient, err := whois.NewClient(whoisConfig)
	if err != nil {
		log.Printf("Failed to create WHOIS client: %v\n", err)
		return
	}

	ctx := context.Background()

	// Perform DNS lookup
	result, err := dnsClient.Lookup(ctx, "github.com", dns.RecordTypeA)
	if err != nil {
		log.Printf("DNS lookup failed: %v\n", err)
	} else {
		fmt.Printf("DNS Result: %v\n", result.Records)
	}

	// Perform WHOIS lookup
	whoisResult, err := whoisClient.Lookup(ctx, "github.com")
	if err != nil {
		log.Printf("WHOIS lookup failed: %v\n", err)
	} else {
		fmt.Printf("WHOIS Registrar: %s\n", whoisResult.Registrar)
	}

	fmt.Println()
}

func exampleDirectConnection() {
	fmt.Println("--- Example 4: Direct Connection (No Proxy) ---")

	// Default configuration uses direct connection
	dnsConfig := dns.DefaultConfig()
	dnsClient, err := dns.NewClient(dnsConfig)
	if err != nil {
		log.Printf("Failed to create DNS client: %v\n", err)
		return
	}

	whoisConfig := whois.DefaultConfig()
	whoisClient, err := whois.NewClient(whoisConfig)
	if err != nil {
		log.Printf("Failed to create WHOIS client: %v\n", err)
		return
	}

	ctx := context.Background()

	// Perform DNS lookup
	result, err := dnsClient.Lookup(ctx, "cloudflare.com", dns.RecordTypeA)
	if err != nil {
		log.Printf("DNS lookup failed: %v\n", err)
	} else {
		fmt.Printf("DNS Result: %v\n", result.Records)
	}

	// Perform WHOIS lookup
	whoisResult, err := whoisClient.Lookup(ctx, "cloudflare.com")
	if err != nil {
		log.Printf("WHOIS lookup failed: %v\n", err)
	} else {
		fmt.Printf("WHOIS Registrar: %s\n", whoisResult.Registrar)
		fmt.Printf("Name Servers: %v\n", whoisResult.NameServers)
	}

	fmt.Println()
}
