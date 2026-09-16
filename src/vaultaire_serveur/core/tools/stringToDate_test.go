package tools

import (
	"testing"
)

// Test de StringToDate
func TestStringToDate(t *testing.T) {
	tests := []struct {
		input       string
		want        string
		expectError bool
	}{
		{"31/12/1999", "1999-12-31", false},
		{"01/01/2000", "2000-01-01", false},
		{"29/02/2020", "2020-02-29", false}, // année bissextile
		{"31/04/2020", "", true},            // avril a 30 jours
		{"12-31-1999", "", true},            // mauvais format
		{"", "", true},                      // chaîne vide
	}

	for _, tt := range tests {
		got, err := StringToDate(tt.input)
		if (err != nil) != tt.expectError {
			t.Errorf("StringToDate(%q) error = %v; want error? %v", tt.input, err, tt.expectError)
			continue
		}
		if got != tt.want {
			t.Errorf("StringToDate(%q) = %q; want %q", tt.input, got, tt.want)
		}
	}
}
