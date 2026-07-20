package types

import "time"

// Event représente n'importe quelle interaction suspecte capturée par un honeypot
type Event struct {
	ID              string    `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	AttackerIP      string    `json:"attacker_ip"`
	Service         string    `json:"service"`      // "ssh", "http", "mysql", etc.
	EventType       string    `json:"event_type"`   // "auth_attempt", "command_exec", "file_upload"
	Payload         string    `json:"payload"`      // La commande tapée ou le mot de passe testé
	Username        string    `json:"username,omitempty"`
	CountryCode     string    `json:"country_code"` // Rempli plus tard par le moteur GeoIP
	CountryName     string    `json:"country_name"`
	MitreTechniques []string  `json:"mitre_techniques,omitempty"`
}
