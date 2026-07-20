package store

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/internal/types"
)

var (
	knownIPs = make(map[string]bool)
	ipMutex  sync.Mutex
)

// StartThreatIntelProcessor écoute le bus et génère les fichiers de Threat Intel
func StartThreatIntelProcessor() {
	fmt.Println("📁 Threat Intelligence Processor active (STIX & Blocklists)...")

	subChan := make(chan interface{}, 100)
	event.RegisterSubscriber(subChan)

	// Création du fichier blocklist initial
	_ = os.WriteFile("iptables-blocklist.txt", []byte("# Auto-generated Honeypot Blocklist\n"), 0644)

	go func() {
		for msg := range subChan {
			e, ok := msg.(types.Event)
			if !ok {
				continue
			}

			ipMutex.Lock()
			if !knownIPs[e.AttackerIP] {
				knownIPs[e.AttackerIP] = true
				
				// 1. Ajouter à la blocklist iptables
				appendBlocklist(e.AttackerIP)
				
				// 2. Exporter l'indicateur STIX 2.1
				exportSTIX(e.AttackerIP, e.Service)
			}
			ipMutex.Unlock()
		}
	}()
}

func appendBlocklist(ip string) {
	f, err := os.OpenFile("iptables-blocklist.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	rule := fmt.Sprintf("iptables -A INPUT -s %s -j DROP\n", ip)
	f.WriteString(rule)
}

// StixIndicator représente un objet Indicator basique en STIX 2.1
type StixIndicator struct {
	Type        string    `json:"type"`
	ID          string    `json:"id"`
	Created     time.Time `json:"created"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Pattern     string    `json:"pattern"`
	PatternType string    `json:"pattern_type"`
	ValidFrom   time.Time `json:"valid_from"`
}

func exportSTIX(ip string, service string) {
	indicator := StixIndicator{
		Type:        "indicator",
		ID:          fmt.Sprintf("indicator--%s", event.GenerateSimpleIDForStore()),
		Created:     time.Now(),
		Name:        "Malicious IP detected by Honeypot",
		Description: fmt.Sprintf("IP address %s attacked the %s service", ip, service),
		Pattern:     fmt.Sprintf("[ipv4-addr:value = '%s']", ip),
		PatternType: "stix",
		ValidFrom:   time.Now(),
	}

	b, _ := json.Marshal(indicator)
	
	f, err := os.OpenFile("threat-intel.stix.json", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err == nil {
		f.WriteString(string(b) + "\n")
		f.Close()
	}
}
