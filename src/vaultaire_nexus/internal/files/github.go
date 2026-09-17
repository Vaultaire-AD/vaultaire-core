package files

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"vaultaire_nexus/internal/catalog"
	"vaultaire_nexus/internal/repos"
)

// Importer recopie une release GitHub dans un dépôt « vaultaire ».
//
// C'est le geste de l'hôte Nexus qui, LUI, a accès à Internet, pour un parc qui
// n'en a pas. Chaque archive est vérifiée contre le SHA256SUMS de la release
// avant d'être publiée : une archive qui ne correspond pas n'entre pas.
type Importer struct {
	Mgr    *repos.Manager
	Client *http.Client
	APIURL string // https://api.github.com
	Token  string // facultatif (dépôt privé, limite de débit)
}

var ghRepo = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// ImportResult décrit un import.
type ImportResult struct {
	Tag      string   `json:"tag"`
	Imported []string `json:"imported"`
	Skipped  []string `json:"skipped"`
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

func (im *Importer) get(ctx context.Context, url string, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "vaultaire-nexus")
	if im.Token != "" {
		req.Header.Set("Authorization", "Bearer "+im.Token)
	}
	resp, err := im.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s : HTTP %d", url, resp.StatusCode)
	}
	return resp, nil
}

// Import recopie la release tag (« latest » accepté) du dépôt GitHub owner/name.
func (im *Importer) Import(ctx context.Context, repo, ghRepoName, tag, by string) (ImportResult, error) {
	if !ghRepo.MatchString(ghRepoName) {
		return ImportResult{}, errors.New("dépôt GitHub attendu sous la forme propriétaire/nom")
	}
	api := strings.TrimRight(im.APIURL, "/")
	url := api + "/repos/" + ghRepoName + "/releases/"
	if tag == "" || tag == "latest" {
		url += "latest"
	} else {
		url += "tags/" + tag
	}
	resp, err := im.get(ctx, url, "application/vnd.github+json")
	if err != nil {
		return ImportResult{}, err
	}
	var rel ghRelease
	err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel)
	resp.Body.Close()
	if err != nil {
		return ImportResult{}, fmt.Errorf("release illisible : %w", err)
	}
	res := ImportResult{Tag: rel.TagName}

	sums := map[string]string{}
	for _, a := range rel.Assets {
		if a.Name != "SHA256SUMS" {
			continue
		}
		r, err := im.get(ctx, a.URL, "application/octet-stream")
		if err != nil {
			return res, err
		}
		sc := bufio.NewScanner(io.LimitReader(r.Body, 1<<20))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) == 2 {
				sums[strings.TrimPrefix(f[1], "*")] = "sha256:" + f[0]
			}
		}
		r.Body.Close()
	}
	if len(sums) == 0 {
		return res, errors.New("la release n'a pas de SHA256SUMS : import refusé")
	}

	existing, _ := im.Mgr.Cat.Packages(repo, "")
	for _, a := range rel.Assets {
		if a.Name == "SHA256SUMS" {
			continue
		}
		name, version, arch, ok := ParseAssetName(a.Name)
		want, listed := sums[a.Name]
		if !ok || !listed {
			res.Skipped = append(res.Skipped, a.Name+" (nom non reconnu ou absent de SHA256SUMS)")
			continue
		}
		if already(existing, name, version, a.Name) {
			res.Skipped = append(res.Skipped, a.Name+" (déjà présent)")
			continue
		}
		r, err := im.get(ctx, a.URL, "application/octet-stream")
		if err != nil {
			return res, err
		}
		// Vérification AVANT publication : on lit dans le magasin, puis on
		// compare ; Ingest ne connaît pas la somme attendue.
		body, err := io.ReadAll(io.LimitReader(r.Body, a.Size+1))
		r.Body.Close()
		if err != nil {
			return res, err
		}
		got := sha256Digest(body)
		if got != want {
			return res, fmt.Errorf("%s : somme %s, SHA256SUMS annonce %s — import interrompu", a.Name, got, want)
		}
		_, _, err = im.Mgr.Ingest(repo, bytes.NewReader(body), repos.UploadMeta{
			Filename: a.Name, Name: name, Version: version, Arch: arch,
			Summary: "Importé de github.com/" + ghRepoName + " " + rel.TagName,
		}, by)
		if err != nil {
			return res, fmt.Errorf("%s : %w", a.Name, err)
		}
		res.Imported = append(res.Imported, a.Name)
	}
	return res, nil
}

func already(ps []catalog.Package, name, version, fn string) bool {
	for _, p := range ps {
		if p.Name == name && p.Version == version && p.Filename == fn {
			return true
		}
	}
	return false
}

// DefaultClient est le client HTTP de l'import.
func DefaultClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Minute}
}
