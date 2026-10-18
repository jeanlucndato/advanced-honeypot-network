package mitre

import (
	"fmt"
	"strings"

	"advance-honeypot-network/internal/types"
)

// StartEngine reports that the synchronous enrichment hook is ready. The
// hook is installed on the event bus by the application entry point.
func StartEngine() { fmt.Println("MITRE ATT&CK event enrichment active") }

func Enrich(e types.Event) types.Event {
	e.MitreTechniques = ExtractTechniques(e)
	return e
}

func ExtractTechniques(e types.Event) []string {
	payload := strings.ToLower(e.Payload)
	var techniques []string
	add := func(id string) { techniques = append(techniques, id) }
	if e.EventType == "exploit_attempt" || strings.Contains(payload, "wp-login") || strings.Contains(payload, "phpmyadmin") {
		add("T1190")
	}
	if e.EventType == "auth_attempt" {
		add("T1110")
	}
	if strings.Contains(payload, "wget ") || strings.Contains(payload, "curl ") || strings.Contains(payload, "ftp ") {
		add("T1105")
	}
	if strings.Contains(payload, "sh ") || strings.Contains(payload, "bash") || strings.Contains(payload, "python") || strings.Contains(payload, "perl ") {
		add("T1059")
	}
	if strings.Contains(payload, "rm ") || strings.Contains(payload, "history -c") {
		add("T1070")
	}
	if strings.Contains(payload, "uname") || strings.Contains(payload, "whoami") || strings.Contains(payload, "cat /etc/passwd") || strings.Contains(payload, " id") {
		add("T1082")
	}
	return techniques
}
