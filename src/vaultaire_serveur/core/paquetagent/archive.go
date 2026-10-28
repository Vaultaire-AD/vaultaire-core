package paquetagent

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// Lecture de l'archive de release d'un agent :
//
//	vaultaire_client/vaultaire_client
//	vaultaire_client/VERSION
//	vaultaire_client/rocky/<quatre modules>
//	vaultaire_client/debian/<quatre modules>
//
// C'est l'unité de remplacement qui existe déjà (release.yaml, job build) : on
// ne l'invente pas, on la décrit.

// tailleMax borne chaque fichier lu : une archive n'est pas une source de
// confiance tant qu'elle n'est pas signée, et c'est précisément ce qu'on
// s'apprête à faire.
const tailleMax = 512 << 20

// DepuisArchive rend un manifeste par famille présente dans l'archive, triés
// par plateforme.
//
// Une famille INCOMPLÈTE est une erreur, pas une famille absente : signer les
// trois modules présents laisserait des machines sans le quatrième. Des
// modules hors d'un répertoire de famille — une compilation de développement —
// sont refusés : on ne signe que ce qu'on sait attribuer.
func DepuisArchive(r io.Reader) ([]Manifeste, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("archive : gzip illisible : %w", err)
	}
	defer func() { _ = gz.Close() }()

	sommes := map[string]string{} // chemin relatif → empreinte
	version := ""
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("archive : tar illisible : %w", err)
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		nom := path.Clean(strings.TrimPrefix(h.Name, "./"))
		racine, rel, ok := strings.Cut(nom, "/")
		if !ok || racine != "vaultaire_client" {
			return nil, fmt.Errorf("archive : %q hors du répertoire vaultaire_client/", h.Name)
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("archive : %q n'est pas un fichier ordinaire", h.Name)
		}
		if h.Size > tailleMax {
			return nil, fmt.Errorf("archive : %q dépasse %d Mo", h.Name, tailleMax>>20)
		}
		if _, deja := sommes[rel]; deja || (rel == "VERSION" && version != "") {
			return nil, fmt.Errorf("archive : %q en double", h.Name)
		}
		if rel == "VERSION" {
			brut, err := io.ReadAll(io.LimitReader(tr, 64))
			if err != nil {
				return nil, fmt.Errorf("archive : VERSION illisible : %w", err)
			}
			version = strings.TrimPrefix(strings.TrimSpace(string(brut)), "v")
			continue
		}
		hacheur := sha256.New()
		if _, err := io.Copy(hacheur, io.LimitReader(tr, tailleMax)); err != nil {
			return nil, fmt.Errorf("archive : lecture de %q : %w", h.Name, err)
		}
		var somme [32]byte
		copy(somme[:], hacheur.Sum(nil))
		sommes[rel] = EmpreinteHex(somme)
	}

	if version == "" {
		return nil, fmt.Errorf("archive : vaultaire_client/VERSION absent")
	}
	binaire, ok := sommes[Fichiers[0]]
	if !ok {
		return nil, fmt.Errorf("archive : vaultaire_client/%s absent", Fichiers[0])
	}
	for rel := range sommes {
		if strings.HasSuffix(rel, ".so") || strings.Contains(rel, ".so.") {
			if !strings.Contains(rel, "/") {
				return nil, fmt.Errorf("archive : module %q hors d'un répertoire de famille "+
					"(compilation de développement ?)", rel)
			}
		}
	}

	var out []Manifeste
	for _, famille := range Familles {
		present, manquants := 0, []string{}
		m := Manifeste{Version: version, Plateforme: PrefixePlateforme + famille,
			Fichiers: []Fichier{{Nom: Fichiers[0], SHA256: binaire}}}
		for _, f := range Fichiers[1:] {
			s, ok := sommes[famille+"/"+f]
			if !ok {
				manquants = append(manquants, f)
				continue
			}
			present++
			m.Fichiers = append(m.Fichiers, Fichier{Nom: f, SHA256: s})
		}
		switch {
		case present == 0:
			continue
		case len(manquants) > 0:
			return nil, fmt.Errorf("archive : famille %s incomplète, manque %s",
				famille, strings.Join(manquants, ", "))
		}
		if err := m.Valider(); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("archive : aucune famille de modules (%s)", strings.Join(Familles, ", "))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Plateforme < out[j].Plateforme })
	return out, nil
}

// NomManifeste rend le nom du manifeste rangé à côté de l'archive :
// `vaultaire_client-v2.3.0-linux-amd64.tar.gz` → `….tar.gz.rocky.manifest`.
// La signature est le même nom suivi de `.sig`.
func NomManifeste(archive string, m Manifeste) string {
	return archive + "." + m.Famille() + ".manifest"
}
