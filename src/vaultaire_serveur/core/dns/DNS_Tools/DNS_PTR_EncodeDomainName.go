package dnstools

import (
	"fmt"
	"strings"
)

func EncodeDomainName(domain string) ([]byte, error) {
	domain = strings.TrimSuffix(domain, ".")
	labels := strings.Split(domain, ".")
	var buf []byte
	for _, label := range labels {
		if len(label) > 63 {
			return nil, fmt.Errorf("❌ Label DNS trop long : %s", label)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0) // fin de nom
	return buf, nil
}
