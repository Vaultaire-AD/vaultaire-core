// Package files sert les dépôts de fichiers versionnés (generic, vaultaire) et,
// pour les dépôts « vaultaire », une API compatible avec celle des releases
// GitHub.
//
// # Pourquoi imiter GitHub
//
// deployments/pre-prod/docker-update.sh sait déjà télécharger une release :
// il lit « <API>/releases/latest » et « <DL>/<tag>/<archive> ». Nexus sert les
// mêmes chemins, si bien qu'un parc sans accès Internet se met à jour avec le
// même script :
//
//	VAULTAIRE_API_URL=https://nexus:8843/repo/vaultaire/releases/api \
//	VAULTAIRE_DL_URL=https://nexus:8843/repo/vaultaire/releases/download \
//	./deployments/pre-prod/docker-update.sh
//
// Une « release » est l'ensemble des fichiers publiés sous une même version,
// tous composants confondus. SHA256SUMS est calculé à la volée.
package files

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"vaultaire_nexus/internal/catalog"
	"vaultaire_nexus/internal/vercmp"
)

// Release est une version et ses fichiers.
type Release struct {
	Tag       string
	Version   string
	Published time.Time
	Assets    []catalog.Package
}

// Releases regroupe les fichiers d'un dépôt par version, la plus haute en tête.
func Releases(pkgs []catalog.Package) []Release {
	idx := map[string]*Release{}
	for _, p := range pkgs {
		r, ok := idx[p.Version]
		if !ok {
			r = &Release{Tag: "v" + p.Version, Version: p.Version}
			idx[p.Version] = r
		}
		r.Assets = append(r.Assets, p)
		if p.UploadedAt.After(r.Published) {
			r.Published = p.UploadedAt
		}
	}
	out := make([]Release, 0, len(idx))
	for _, r := range idx {
		sort.Slice(r.Assets, func(i, j int) bool { return r.Assets[i].Filename < r.Assets[j].Filename })
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return vercmp.Compare(out[i].Version, out[j].Version) > 0 })
	return out
}

// FindRelease rend la release d'un tag (« v2.1.0 » ou « 2.1.0 »).
func FindRelease(pkgs []catalog.Package, tag string) (Release, bool) {
	v := strings.TrimPrefix(tag, "v")
	for _, r := range Releases(pkgs) {
		if r.Version == v {
			return r, true
		}
	}
	return Release{}, false
}

// SHA256SUMS rend le fichier de sommes d'une release, au format sha256sum.
func (r Release) SHA256SUMS() []byte {
	var b strings.Builder
	for _, a := range r.Assets {
		if a.Filename == "SHA256SUMS" {
			continue
		}
		fmt.Fprintf(&b, "%s  %s\n", strings.TrimPrefix(a.Digest, "sha256:"), a.Filename)
	}
	return []byte(b.String())
}

// GitHubJSON rend la représentation d'une release comme l'API GitHub.
func (r Release) GitHubJSON(downloadBase string) map[string]any {
	assets := []map[string]any{}
	for _, a := range r.Assets {
		assets = append(assets, map[string]any{
			"name":                 a.Filename,
			"size":                 a.Size,
			"browser_download_url": downloadBase + "/" + r.Tag + "/" + a.Filename,
			"content_type":         "application/octet-stream",
			"digest":               a.Digest,
			"updated_at":           a.UploadedAt.Format(time.RFC3339),
		})
	}
	assets = append(assets, map[string]any{
		"name":                 "SHA256SUMS",
		"size":                 len(r.SHA256SUMS()),
		"browser_download_url": downloadBase + "/" + r.Tag + "/SHA256SUMS",
		"content_type":         "text/plain",
	})
	return map[string]any{
		"tag_name":     r.Tag,
		"name":         "Vaultaire " + r.Tag,
		"published_at": r.Published.Format(time.RFC3339),
		"draft":        false,
		"prerelease":   strings.Contains(r.Version, "~") || strings.Contains(r.Version, "-rc"),
		"assets":       assets,
	}
}

// assetName : <composant>-v<version>-<os>-<arch>.<ext>
var assetName = regexp.MustCompile(`^([A-Za-z0-9_]+)-v?([0-9][A-Za-z0-9.+~]*)-([a-z0-9]+-[a-z0-9_]+)\.(tar\.gz|tgz|zip|tar\.xz)$`)

// ParseAssetName reconnaît le nom d'une archive de release Vaultaire.
func ParseAssetName(fn string) (name, version, arch string, ok bool) {
	m := assetName.FindStringSubmatch(fn)
	if m == nil {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}
