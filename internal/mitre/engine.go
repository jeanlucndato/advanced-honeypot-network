package mitre

import (
	"fmt"
	"strings"

	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/internal/types"
)

// StartEngine démarre le moteur de corrélation TTP
func StartEngine() {
	fmt.Println("🛡️  MITRE ATT&CK Correlation Engine active...")

	subChan := make(chan interface{}, 100)
	event.RegisterSubscriber(subChan)

	// Note: We create a separate processed channel to republish enriched events,
	// but to avoid infinite loops with the global bus, we'll just modify them before storage
	// or we can just log the correlation for now.
	// In a real advanced setup, we'd have a raw_bus and a processed_bus.
	// Here, we just log the correlation and append it in memory.

	go func() {
		for msg := range subChan {
			e, ok := msg.(types.Event)
			if !ok {
				continue
			}

			techniques := extractTechniques(e)
			if len(techniques) > 0 {
				fmt.Printf("🔍 [MITRE ENGINE] Techniques détectées pour %s : %v\n", e.AttackerIP, techniques)
			}
		}
	}()
}

func extractTechniques(e types.Event) []string {
	var t []string
	payload := strings.ToLower(e.Payload)

	// T1190 - Exploit Public-Facing Application
	if e.EventType == "exploit_attempt" || strings.Contains(payload, "wp-login") {
		t = append(t, "T1190")
	}

	// T1110 - Brute Force
	if e.EventType == "auth_attempt" {
		t = append(t, "T1110")
	}

	// T1105 - Ingress Tool Transfer
	if strings.Contains(payload, "wget") || strings.Contains(payload, "curl") || strings.Contains(payload, "ftp") {
		t = append(t, "T1105")
	}

	// T1059 - Command and Scripting Interpreter
	if strings.Contains(payload, "sh") || strings.Contains(payload, "bash") || strings.Contains(payload, "python") {
		t = append(t, "T1059")
	}

	// T1070 - Indicator Removal
	if strings.Contains(payload, "rm ") || strings.Contains(payload, "history -c") {
		t = append(t, "T1070")
	}

	// T1082 - System Information Discovery
	if strings.Contains(payload, "uname") || strings.Contains(payload, "whoami") || strings.Contains(payload, "cat /etc/passwd") {
		t = append(t, "T1082")
	}

	return t
}
