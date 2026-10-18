package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/internal/types"
)

var (
	knownIPs = make(map[string]bool)
	ipMutex  sync.Mutex
)

type StixBundle struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	Objects []StixIndicator `json:"objects"`
}
type StixIndicator struct {
	Type        string    `json:"type"`
	SpecVersion string    `json:"spec_version"`
	ID          string    `json:"id"`
	Created     time.Time `json:"created"`
	Modified    time.Time `json:"modified"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Pattern     string    `json:"pattern"`
	PatternType string    `json:"pattern_type"`
	ValidFrom   time.Time `json:"valid_from"`
}

func StartThreatIntelProcessor() {
	fmt.Println("Threat intelligence processor active (STIX 2.1 and firewall blocklists)")
	loadKnownIPs()
	sub := event.GlobalBus.Subscribe(256)
	go func() {
		for e := range sub {
			record(e)
		}
	}()
}

func record(e types.Event) {
	ip, err := parseIP(e.AttackerIP)
	if err != nil {
		return
	}
	key := ip.String()
	ipMutex.Lock()
	defer ipMutex.Unlock()
	if knownIPs[key] {
		return
	}
	if err := appendBlocklist(ip); err != nil {
		fmt.Printf("blocklist write failed: %v\n", err)
		return
	}
	if err := exportSTIX(ip, e.Service); err != nil {
		fmt.Printf("STIX write failed: %v\n", err)
		return
	}
	knownIPs[key] = true
}

func parseIP(raw string) (netip.Addr, error) {
	if host, err := netip.ParseAddrPort(raw); err == nil {
		return host.Addr().Unmap(), nil
	}
	if host, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil {
		return host.Unmap(), nil
	}
	return netip.Addr{}, fmt.Errorf("invalid attacker IP %q", raw)
}

func loadKnownIPs() {
	f, err := os.Open("iptables-blocklist.txt")
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		fields := strings.Fields(line)
		for i := range fields {
			if fields[i] == "-s" && i+1 < len(fields) {
				if ip, err := parseIP(fields[i+1]); err == nil {
					knownIPs[ip.String()] = true
				}
			}
		}
	}
}

func appendBlocklist(ip netip.Addr) error {
	tool := "iptables"
	if ip.Is6() {
		tool = "ip6tables"
	}
	file, err := os.OpenFile("iptables-blocklist.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.WriteString(fmt.Sprintf("%s -A INPUT -s %s -j DROP\n", tool, ip)); err != nil {
		return err
	}
	return file.Sync()
}

func exportSTIX(ip netip.Addr, service string) error {
	now := time.Now().UTC()
	indicator := StixIndicator{Type: "indicator", SpecVersion: "2.1", ID: "indicator--" + event.GenerateSimpleIDForStore(), Created: now, Modified: now,
		Name: "Source IP observed by Hive", Description: fmt.Sprintf("IP address %s interacted with the %s honeypot service", ip, service),
		Pattern: fmt.Sprintf("[%s:value = '%s']", map[bool]string{true: "ipv6-addr", false: "ipv4-addr"}[ip.Is6()], ip), PatternType: "stix", ValidFrom: now}
	bundle := StixBundle{Type: "bundle", ID: "bundle--" + event.GenerateSimpleIDForStore(), Objects: []StixIndicator{indicator}}
	if previous, err := os.ReadFile("threat-intel.stix.json"); err == nil {
		var existing StixBundle
		if json.Unmarshal(previous, &existing) == nil && existing.Type == "bundle" {
			bundle.Objects = append(existing.Objects, indicator)
		} else {
			bundle.Objects = append(migrateLegacyIndicators(previous), indicator)
		}
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(".", ".threat-intel.stix.json.tmp")
	if err = os.WriteFile(tmp, append(data, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, "threat-intel.stix.json")
}

var stixPattern = regexp.MustCompile(`\[(?:ipv4|ipv6)-addr:value\s*=\s*'([^']+)'\]`)

// migrateLegacyIndicators preserves prior newline-delimited indicators while
// repairing addresses that older versions recorded with the source port.
func migrateLegacyIndicators(data []byte) []StixIndicator {
	var result []StixIndicator
	for _, line := range strings.Split(string(data), "\n") {
		var old struct {
			Description string `json:"description"`
			Name        string `json:"name"`
			Pattern     string `json:"pattern"`
		}
		if json.Unmarshal([]byte(line), &old) != nil {
			continue
		}
		match := stixPattern.FindStringSubmatch(old.Pattern)
		if len(match) != 2 {
			continue
		}
		ip, err := parseIP(match[1])
		if err != nil {
			continue
		}
		now := time.Now().UTC()
		family := "ipv4-addr"
		if ip.Is6() {
			family = "ipv6-addr"
		}
		result = append(result, StixIndicator{Type: "indicator", SpecVersion: "2.1", ID: "indicator--" + event.GenerateSimpleIDForStore(), Created: now, Modified: now,
			Name: old.Name, Description: old.Description, Pattern: fmt.Sprintf("[%s:value = '%s']", family, ip), PatternType: "stix", ValidFrom: now})
	}
	return result
}
