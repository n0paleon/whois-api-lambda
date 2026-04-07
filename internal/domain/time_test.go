package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFlexibleTime_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		jsonStr  string
		wantErr  bool
		wantTime time.Time // expected parsed time if no error
	}{
		{
			name:     "RFC3339 with colon",
			jsonStr:  `"2025-02-28T16:09:49+00:00"`,
			wantErr:  false,
			wantTime: time.Date(2025, 2, 28, 16, 9, 49, 0, time.UTC),
		},
		{
			name:     "RFC3339 without colon (normalized)",
			jsonStr:  `"2025-02-28T16:09:49+0000"`,
			wantErr:  false,
			wantTime: time.Date(2025, 2, 28, 16, 9, 49, 0, time.UTC),
		},
		{
			name:    "Invalid format",
			jsonStr: `"invalid-time"`,
			wantErr: true,
		},
		{
			name:     "Date only",
			jsonStr:  `"2025-02-28"`,
			wantErr:  false,
			wantTime: time.Date(2025, 2, 28, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "DD-MMM-YYYY format",
			jsonStr:  `"28-Feb-2025"`,
			wantErr:  false,
			wantTime: time.Date(2025, 2, 28, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "Null value",
			jsonStr:  `null`,
			wantErr:  false,
			wantTime: time.Time{},
		},
		{
			name:     "Empty string",
			jsonStr:  `""`,
			wantErr:  false,
			wantTime: time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ft FlexibleTime
			err := json.Unmarshal([]byte(tt.jsonStr), &ft)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !ft.Time.Equal(tt.wantTime) {
				t.Errorf("UnmarshalJSON() got = %v, want %v", ft.Time, tt.wantTime)
			}
		})
	}
}

func TestFlexibleTime_MarshalJSON(t *testing.T) {
	ft := NewFlexibleTime(time.Date(2025, 2, 28, 16, 9, 49, 0, time.UTC))
	data, err := json.Marshal(ft)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	expected := `"2025-02-28T16:09:49Z"`
	if string(data) != expected {
		t.Errorf("MarshalJSON() got = %v, want %v", string(data), expected)
	}
}
