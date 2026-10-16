package files

import (
	"strings"

	"vaultaire_nexus/internal/catalog"
)

func catalogPackage(fn string) catalog.Package {
	return catalog.Package{Filename: fn, Digest: "sha256:" + strings.Repeat("0", 64)}
}

func contient(s, sous string) bool { return strings.Contains(s, sous) }
