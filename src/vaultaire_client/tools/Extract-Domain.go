package tools

import "strings"

func ExctractDomainFromUsername(username string) (string, string) {
	domain := ""
	// Si présence de @ → split user@domain
	if strings.Contains(username, "@") {
		parts := strings.SplitN(username, "@", 2)
		username = parts[0]
		domain = parts[1]
	}
	return username, domain
}
