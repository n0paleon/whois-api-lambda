package domain

import (
	"fmt"
	"strings"
	"time"
)

type FlexibleTime struct {
	time.Time
}

// Formats tried in order
var timeFormats = []string{
	time.RFC3339,               // 2006-01-02T15:04:05Z07:00  ← standard
	"2006-01-02T15:04:05Z0700", // 2006-01-02T15:04:05+0000   ← no colon
	"2006-01-02T15:04:05",      // 2006-01-02T15:04:05        ← no timezone
	"2006-01-02",               // 2006-01-02                  ← date only
	"02-Jan-2006",              // 28-Feb-2025
}

func (ft *FlexibleTime) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "null" || s == "" {
		return nil
	}

	s = normalizeTimezone(s)

	for _, format := range timeFormats {
		t, err := time.Parse(format, s)
		if err == nil {
			ft.Time = t
			return nil
		}
	}

	return fmt.Errorf("cannot parse time %q: no matching format", s)
}

func (ft FlexibleTime) MarshalJSON() ([]byte, error) {
	if ft.IsZero() {
		return []byte("null"), nil
	}
	return []byte(`"` + ft.UTC().Format(time.RFC3339) + `"`), nil
}

// normalizeTimezone converts "+0700" to "+07:00"
func normalizeTimezone(s string) string {
	if !strings.Contains(s, "T") {
		return s
	}
	n := len(s)
	if n >= 5 {
		sign := s[n-5]
		if sign == '+' || sign == '-' {
			maybeOffset := s[n-4:]
			allDigits := true
			for _, c := range maybeOffset {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				return s[:n-2] + ":" + s[n-2:]
			}
		}
	}
	return s
}

// Convert from time.Time to FlexibleTime
func NewFlexibleTime(t time.Time) FlexibleTime {
	return FlexibleTime{Time: t}
}

// Convert from *time.Time to *FlexibleTime
func NewFlexibleTimePtr(t *time.Time) *FlexibleTime {
	if t == nil {
		return nil
	}
	ft := FlexibleTime{Time: *t}
	return &ft
}

// Convert back from FlexibleTime to time.Time
func (ft FlexibleTime) ToTime() time.Time {
	return ft.Time
}
