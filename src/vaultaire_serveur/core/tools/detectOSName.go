package tools

import "strings"

// DetectOSName takes a string input and returns the corresponding OS name.
// It checks for various OS names in a case-insensitive manner.
func DetectOSName(input string) string {
	input = strings.ToLower(input)

	switch {
	case strings.Contains(input, "debian"):
		return "debian"
	case strings.Contains(input, "ubuntu"):
		return "ubuntu"
	case strings.Contains(input, "rocky"):
		return "rocky"
	case strings.Contains(input, "centos"):
		return "centos"
	case strings.Contains(input, "red hat"):
		return "rhel"
	case strings.Contains(input, "alpine"):
		return "alpine"
	default:
		return "unknown"
	}
}
