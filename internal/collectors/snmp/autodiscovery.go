package snmp

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// AutodiscoveryOptions controls automatic network expansion
type AutodiscoveryOptions struct {
	Enabled         bool     `json:"enabled"`
	MaxDepth        int      `json:"maxDepth"`        // max hops from seeds (default: 2)
	MaxDevices      int      `json:"maxDevices"`      // safety limit (default: 50)
	WhitelistCIDRs  []string `json:"whitelistCIDRs"`  // allowed networks
	BlacklistCIDRs  []string `json:"blacklistCIDRs"`  // forbidden networks
	EnableARP       bool     `json:"enableARP"`       // use ARP tables
	EnableRoutes    bool     `json:"enableRoutes"`    // use routing tables
	EnableLLDPMgmt  bool     `json:"enableLLDPMgmt"`  // use LLDP mgmt addresses
	Timeout         int      `json:"timeout"`         // per-device timeout in seconds
}

// DefaultAutodiscoveryOptions returns safe defaults
func DefaultAutodiscoveryOptions() AutodiscoveryOptions {
	return AutodiscoveryOptions{
		Enabled:        false, // disabled by default for safety
		MaxDepth:       2,
		MaxDevices:     50,
		WhitelistCIDRs: []string{}, // empty = allow all private networks
		BlacklistCIDRs: []string{"127.0.0.0/8", "169.254.0.0/16"}, // localhost, link-local
		EnableARP:      true,
		EnableRoutes:   true,
		EnableLLDPMgmt: true,
		Timeout:        5,
	}
}

// DiscoveredTarget represents a newly found device
type DiscoveredTarget struct {
	Address    string    `json:"address"`
	Source     string    `json:"source"`     // "arp", "route", "lldp"
	FoundBy    string    `json:"foundBy"`    // device that discovered this target
	Depth      int       `json:"depth"`      // hops from original seeds
	Timestamp  time.Time `json:"timestamp"`
	Reachable  bool      `json:"reachable"`  // SNMP connectivity test result
}

// AutodiscoveryResult contains expansion results
type AutodiscoveryResult struct {
	OriginalSeeds    []string           `json:"originalSeeds"`
	DiscoveredTargets []DiscoveredTarget `json:"discoveredTargets"`
	TotalDevices     int                `json:"totalDevices"`
	MaxDepthReached  int                `json:"maxDepthReached"`
	Errors           []string           `json:"errors"`
	Duration         time.Duration      `json:"duration"`
}

// Autodiscoverer handles network expansion logic
type Autodiscoverer struct {
	collector *GoSNMPCollector
	options   AutodiscoveryOptions
	
	// Internal state
	discovered   map[string]*DiscoveredTarget // IP -> target info
	processed    map[string]bool              // IP -> processed flag
	whitelistNets []*net.IPNet               // parsed CIDR whitelist
	blacklistNets []*net.IPNet               // parsed CIDR blacklist
}

// NewAutodiscoverer creates a new autodiscovery instance
func NewAutodiscoverer(collector *GoSNMPCollector, options AutodiscoveryOptions) (*Autodiscoverer, error) {
	if options.MaxDepth <= 0 {
		options.MaxDepth = 2
	}
	if options.MaxDevices <= 0 {
		options.MaxDevices = 50
	}
	
	ad := &Autodiscoverer{
		collector:  collector,
		options:    options,
		discovered: make(map[string]*DiscoveredTarget),
		processed:  make(map[string]bool),
	}
	
	// Parse CIDR lists
	if err := ad.parseCIDRLists(); err != nil {
		return nil, fmt.Errorf("invalid CIDR configuration: %w", err)
	}
	
	return ad, nil
}

// ExpandTargets performs autodiscovery starting from seed targets
func (ad *Autodiscoverer) ExpandTargets(ctx context.Context, seeds []Target) (AutodiscoveryResult, error) {
	start := time.Now()
	result := AutodiscoveryResult{
		OriginalSeeds: make([]string, len(seeds)),
		Errors:        []string{},
	}
	
	// Extract seed addresses
	for i, seed := range seeds {
		result.OriginalSeeds[i] = seed.Address
	}
	
	// Initialize with seeds at depth 0
	for _, seed := range seeds {
		ip := normalizeIP(seed.Address)
		if ip != "" && ad.isAllowedIP(ip) {
			ad.discovered[ip] = &DiscoveredTarget{
				Address:   ip,
				Source:    "seed",
				FoundBy:   "user",
				Depth:     0,
				Timestamp: time.Now(),
				Reachable: false, // will be tested
			}
		}
	}
	
	// Iterative expansion by depth
	for depth := 0; depth <= ad.options.MaxDepth; depth++ {
		if len(ad.discovered) >= ad.options.MaxDevices {
			result.Errors = append(result.Errors, fmt.Sprintf("reached max devices limit (%d)", ad.options.MaxDevices))
			break
		}
		
		// Find unprocessed targets at current depth
		var currentTargets []string
		for ip, target := range ad.discovered {
			if target.Depth == depth && !ad.processed[ip] {
				currentTargets = append(currentTargets, ip)
			}
		}
		
		if len(currentTargets) == 0 {
			break // no more targets to process
		}
		
		result.MaxDepthReached = depth
		
		// Process each target at current depth
		for _, ip := range currentTargets {
			select {
			case <-ctx.Done():
				result.Errors = append(result.Errors, "autodiscovery cancelled")
				goto finish
			default:
			}
			
			if err := ad.processTarget(ctx, ip, depth+1); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("error processing %s: %v", ip, err))
			}
			ad.processed[ip] = true
		}
	}
	
finish:
	// Collect results
	for _, target := range ad.discovered {
		result.DiscoveredTargets = append(result.DiscoveredTargets, *target)
	}
	
	// Sort by depth, then by IP
	sort.Slice(result.DiscoveredTargets, func(i, j int) bool {
		if result.DiscoveredTargets[i].Depth != result.DiscoveredTargets[j].Depth {
			return result.DiscoveredTargets[i].Depth < result.DiscoveredTargets[j].Depth
		}
		return result.DiscoveredTargets[i].Address < result.DiscoveredTargets[j].Address
	})
	
	result.TotalDevices = len(result.DiscoveredTargets)
	result.Duration = time.Since(start)
	
	return result, nil
}

// processTarget discovers new targets from a single device
func (ad *Autodiscoverer) processTarget(ctx context.Context, ip string, nextDepth int) error {
	// Test SNMP connectivity
	target := ad.discovered[ip]
	
	// Try to open SNMP session (use v2c/public as default probe)
	cred := Credentials{Version: "v2c", Community: "public"}
	addr := ip
	if !strings.Contains(addr, ":") {
		addr = addr + ":161"
	}
	
	sn, err := ad.collector.openSession(addr, cred)
	if err != nil {
		target.Reachable = false
		return fmt.Errorf("SNMP connection failed: %w", err)
	}
	defer sn.Conn.Close()
	
	target.Reachable = true
	
	var newIPs []string
	
	// Discover from ARP table
	if ad.options.EnableARP {
		arpIPs, err := ad.discoverFromARP(sn, ip)
		if err == nil {
			newIPs = append(newIPs, arpIPs...)
		}
	}
	
	// Discover from routing table
	if ad.options.EnableRoutes {
		routeIPs, err := ad.discoverFromRoutes(sn, ip)
		if err == nil {
			newIPs = append(newIPs, routeIPs...)
		}
	}
	
	// Discover from LLDP management addresses
	if ad.options.EnableLLDPMgmt {
		lldpIPs, err := ad.discoverFromLLDP(sn, ip)
		if err == nil {
			newIPs = append(newIPs, lldpIPs...)
		}
	}
	
	// Add new targets
	for _, newIP := range newIPs {
		if ad.addDiscoveredTarget(newIP, "autodiscovery", ip, nextDepth) {
			// Successfully added new target
		}
	}
	
	return nil
}

// discoverFromARP extracts IPs from ARP table
func (ad *Autodiscoverer) discoverFromARP(sn *gosnmp.GoSNMP, sourceIP string) ([]string, error) {
	var ips []string
	
	// ipNetToMediaNetAddress: 1.3.6.1.2.1.4.22.1.3 (IPv4 ARP table)
	err := sn.BulkWalk(".1.3.6.1.2.1.4.22.1.3", func(pdu gosnmp.SnmpPDU) error {
		if ipStr := valueToString(pdu.Value); ipStr != "" {
			if net.ParseIP(ipStr) != nil {
				ips = append(ips, ipStr)
			}
		}
		return nil
	})
	
	if err != nil {
		return nil, err
	}
	
	return ad.filterIPs(ips), nil
}

// discoverFromRoutes extracts IPs from routing table
func (ad *Autodiscoverer) discoverFromRoutes(sn *gosnmp.GoSNMP, sourceIP string) ([]string, error) {
	var ips []string
	
	// ipRouteNextHop: 1.3.6.1.2.1.4.21.1.7 (next hop IPs)
	err := sn.BulkWalk(".1.3.6.1.2.1.4.21.1.7", func(pdu gosnmp.SnmpPDU) error {
		if ipStr := valueToString(pdu.Value); ipStr != "" {
			if ip := net.ParseIP(ipStr); ip != nil && !ip.IsUnspecified() {
				ips = append(ips, ipStr)
			}
		}
		return nil
	})
	
	if err != nil {
		return nil, err
	}
	
	return ad.filterIPs(ips), nil
}

// discoverFromLLDP extracts management IPs from LLDP
func (ad *Autodiscoverer) discoverFromLLDP(sn *gosnmp.GoSNMP, sourceIP string) ([]string, error) {
	var ips []string
	
	// lldpRemManAddr: 1.0.8802.1.1.2.1.4.2.1.4
	err := sn.BulkWalk(".1.0.8802.1.1.2.1.4.2.1.4", func(pdu gosnmp.SnmpPDU) error {
		addr := valueToString(pdu.Value)
		
		// Try parsing as string IP
		if ip := net.ParseIP(addr); ip != nil && !ip.IsUnspecified() {
			ips = append(ips, ip.String())
			return nil
		}
		
		// Try parsing as binary (4 bytes IPv4, 16 bytes IPv6)
		if len(addr) == 4 {
			ip := net.IPv4(addr[0], addr[1], addr[2], addr[3])
			if !ip.IsUnspecified() {
				ips = append(ips, ip.String())
			}
		} else if len(addr) == 16 {
			ip := net.IP(addr)
			if !ip.IsUnspecified() {
				ips = append(ips, ip.String())
			}
		}
		
		return nil
	})
	
	if err != nil {
		return nil, err
	}
	
	return ad.filterIPs(ips), nil
}

// Helper functions

func (ad *Autodiscoverer) parseCIDRLists() error {
	// Parse whitelist
	for _, cidr := range ad.options.WhitelistCIDRs {
		_, net, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid whitelist CIDR %s: %w", cidr, err)
		}
		ad.whitelistNets = append(ad.whitelistNets, net)
	}
	
	// Parse blacklist
	for _, cidr := range ad.options.BlacklistCIDRs {
		_, net, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid blacklist CIDR %s: %w", cidr, err)
		}
		ad.blacklistNets = append(ad.blacklistNets, net)
	}
	
	return nil
}

func (ad *Autodiscoverer) isAllowedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	
	// Check blacklist first
	for _, blackNet := range ad.blacklistNets {
		if blackNet.Contains(ip) {
			return false
		}
	}
	
	// If whitelist is empty, allow all (except blacklisted)
	if len(ad.whitelistNets) == 0 {
		// Default: allow private networks only
		return isPrivateIP(ip)
	}
	
	// Check whitelist
	for _, whiteNet := range ad.whitelistNets {
		if whiteNet.Contains(ip) {
			return true
		}
	}
	
	return false
}

func (ad *Autodiscoverer) filterIPs(ips []string) []string {
	seen := make(map[string]bool)
	var filtered []string
	
	for _, ip := range ips {
		normalized := normalizeIP(ip)
		if normalized != "" && !seen[normalized] && ad.isAllowedIP(normalized) {
			seen[normalized] = true
			filtered = append(filtered, normalized)
		}
	}
	
	return filtered
}

func (ad *Autodiscoverer) addDiscoveredTarget(ip, source, foundBy string, depth int) bool {
	if _, exists := ad.discovered[ip]; exists {
		return false // already discovered
	}
	
	if len(ad.discovered) >= ad.options.MaxDevices {
		return false // reached limit
	}
	
	ad.discovered[ip] = &DiscoveredTarget{
		Address:   ip,
		Source:    source,
		FoundBy:   foundBy,
		Depth:     depth,
		Timestamp: time.Now(),
		Reachable: false, // will be tested later
	}
	
	return true
}

func normalizeIP(addr string) string {
	// Remove port if present
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	
	return ip.String()
}

func isPrivateIP(ip net.IP) bool {
	// RFC 1918 private networks
	private := []*net.IPNet{
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},       // 10.0.0.0/8
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},    // 172.16.0.0/12
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},   // 192.168.0.0/16
	}
	
	for _, priv := range private {
		if priv.Contains(ip) {
			return true
		}
	}
	
	return false
}