package ducky_tools

import (
	"vaultaire/serveur/storage"
	"strings"
)

func ExtractPublicKeys(keys []storage.PublicKey) string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Key)
	}
	return strings.Join(out, ",")
}
