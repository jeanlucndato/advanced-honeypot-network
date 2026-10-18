package sanitize

import "regexp"

var (
	keyValueSecret = regexp.MustCompile(`(?i)(password|passwd|pwd|token|secret|authorization|api[_-]?key)(["']?\s*[=:]\s*["']?)([^&\s,}"']+)`)
	flagSecret     = regexp.MustCompile(`(?i)(--password|-p|--token|--api-key)(\s+)([^\s]+)`)
)

// Redact removes common credential values from captured text. It is best-effort;
// callers should still treat all captured data as sensitive.
func Redact(value string) string {
	value = keyValueSecret.ReplaceAllString(value, "$1$2[REDACTED]")
	return flagSecret.ReplaceAllString(value, "$1$2[REDACTED]")
}
