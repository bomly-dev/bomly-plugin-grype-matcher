package plugin

import "time"

// formatDuration returns a short human-readable duration string for logs.
func formatDuration(value time.Duration) string {
	switch {
	case value < time.Second:
		return value.Round(10 * time.Millisecond).String()
	case value < time.Minute:
		return value.Round(100 * time.Millisecond).String()
	default:
		return value.Round(time.Second).String()
	}
}
