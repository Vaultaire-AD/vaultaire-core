package tools

import (
	"testing"
)

// Test de DetectOSName
func TestDetectOSName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Debian 10", "debian"},
		{"ubuntu 20.04", "ubuntu"},
		{"ROCKY LINUX", "rocky"},
		{"CentOS Stream", "centos"},
		{"Red Hat Enterprise Linux", "rhel"},
		{"Alpine Linux", "alpine"},
		{"Windows 10", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		got := DetectOSName(tt.input)
		if got != tt.want {
			t.Errorf("DetectOSName(%q) = %q; want %q", tt.input, got, tt.want)
		}
	}
}
