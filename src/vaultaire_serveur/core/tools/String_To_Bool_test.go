package tools

import "testing"

func TestString_tobool_yesnot(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"yes", true},
		{"not", false},
		{"no", false},  // cas invalide
		{"YES", false}, // sensible à la casse
		{"", false},    // chaîne vide
		{"y", false},   // autre valeur
	}

	for _, tt := range tests {
		got := String_tobool_yesnot(tt.input)
		if got != tt.want {
			t.Errorf("String_tobool_yesnot(%q) = %v; want %v", tt.input, got, tt.want)
		}
	}
}
