package web

import (
	"encoding/json"

	"vaultaire_nexus/internal/catalog"
	"vaultaire_nexus/internal/debrepo"
	"vaultaire_nexus/internal/files"
)

// debPool rend le chemin pool/… d'un paquet Debian.
func (s *Server) debPool(repo catalog.Repo, p catalog.Package) string {
	var c debrepo.Control
	if err := json.Unmarshal(p.Detail, &c); err != nil {
		return "pool/" + p.Filename
	}
	return debrepo.PoolPath(repo.Component, c, p.Filename)
}

func parseAsset(fn string) (name, version, arch string, ok bool) {
	return files.ParseAssetName(fn)
}
