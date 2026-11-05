package miseajour

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vaultaire_client/paquet"
)

// La préparation — tout ce qui précède la bascule, sans RIEN toucher au système.
//
//	télécharger → vérifier la signature → vérifier chaque SHA-256
//	→ éprouver les modules (ldd) → essayer le binaire (--check) → plan.json
//
// Un échec ici laisse la machine telle qu'elle était. Deux sortes d'échec :
//
//   - TRANSITOIRE (réseau, dépôt injoignable) : aucun compte rendu. Le core
//     redonnera l'ordre à la reconnexion ou dans l'heure ; retenir l'ordre
//     pour une coupure réseau obligerait à relancer chaque machine à la main ;
//   - DÉFINITIF (signature, empreinte, module qui ne se charge pas) : compte
//     rendu « refuse ». Retenter donnerait le même refus.

// ErrTransitoire marque un échec qui se retentera.
var ErrTransitoire = errors.New("transitoire")

// FichierPlan : un des cinq fichiers, d'où il vient et où il va.
type FichierPlan struct {
	Nom         string      `json:"nom"`
	Source      string      `json:"source"`
	Destination string      `json:"destination"`
	Mode        os.FileMode `json:"mode"`
	SHA256      string      `json:"sha256"`
}

// Plan : ce que l'updater exécutera, écrit par l'agent qui a tout vérifié.
type Plan struct {
	Version     string        `json:"version"`
	Famille     string        `json:"famille"`
	Retrograder bool          `json:"retrograder"`
	Repertoire  string        `json:"repertoire"`
	Binaire     string        `json:"binaire"`
	Unite       string        `json:"unite"`
	Fichiers    []FichierPlan `json:"fichiers"`
}

// NomPlan : à la racine du répertoire de la version.
const NomPlan = "plan.json"

// Telecharger : GET d'une URL, borné. Remplaçable par les tests.
type Telecharger func(url string, max int64) ([]byte, error)

// TailleMaxArchive : l'archive d'agent pèse quelques dizaines de Mo.
const TailleMaxArchive = 512 << 20

// ClientHTTP compose le client du téléchargement : TLS VÉRIFIÉ, par les AC
// du système et, s'il est réglé, le fichier update_tls_ca.
//
// # Pourquoi vérifier, alors que la signature juge les octets
//
// La signature suffit à l'intégrité : un intermédiaire ne peut faire installer
// que ce que la clé du cluster a signé. Mais il peut servir une version
// ANCIENNE authentiquement signée, ou rien du tout, et c'est le tunnel qui
// ferme la première (l'agent n'installe que la version de l'ordre). Vérifier
// TLS ne coûte qu'une AC à déposer, et retire à un intermédiaire jusqu'à la
// possibilité de voir quels paquets le parc demande. Tranché le 17/10 : pas de
// réglage pour s'en passer — http:// est refusé.
func ClientHTTP(fichierAC string) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if strings.TrimSpace(fichierAC) != "" {
		pem, err := os.ReadFile(fichierAC)
		if err != nil {
			return nil, fmt.Errorf("update_tls_ca : %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("update_tls_ca : aucun certificat lisible dans %s", fichierAC)
		}
	}
	return &http.Client{
		Timeout: 10 * time.Minute,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 15 * time.Second,
		},
	}, nil
}

// TelechargerAvec rend un Telecharger sur ce client.
func TelechargerAvec(c *http.Client) Telecharger {
	return func(url string, max int64) ([]byte, error) {
		if !strings.HasPrefix(url, "https://") {
			return nil, fmt.Errorf("%s : https:// exigé", url)
		}
		resp, err := c.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s : HTTP %d", url, resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > max {
			return nil, fmt.Errorf("%s : plus de %d octets", url, max)
		}
		return b, nil
	}
}

// Preparation : ce dont Preparer a besoin.
type Preparation struct {
	Chemins     Chemins
	Systeme     Systeme
	Telecharger Telecharger
	Bases       []Base
	Cles        func() ([]*rsa.PublicKey, error)
}

// Preparer télécharge, vérifie et écrit le plan. Rend le plan, ou une erreur
// marquée ErrTransitoire quand elle se retentera.
func Preparer(p Preparation, o Ordre) (Plan, error) {
	osRelease, err := os.ReadFile(p.Chemins.OSRelease)
	if err != nil {
		return Plan{}, fmt.Errorf("os-release illisible : %w", err)
	}
	famille, err := FamilleDe(string(osRelease))
	if err != nil {
		return Plan{}, err
	}
	repPAM, err := RepertoirePAM(p.Chemins)
	if err != nil {
		return Plan{}, err
	}
	repNSS := filepath.Dir(repPAM)

	cles, err := p.Cles()
	if err != nil {
		return Plan{}, err
	}

	// 1. Télécharger, dépôt après dépôt.
	var manifeste, signature, archive []byte
	var essais []string
	for _, b := range p.Bases {
		u := func(f string) string { return URLFichier(b.URL, o.Depot, o.Version, f) }
		if manifeste, err = p.Telecharger(u(NomManifeste(o.Version, famille)), 64<<10); err == nil {
			if signature, err = p.Telecharger(u(NomSignature(o.Version, famille)), 16<<10); err == nil {
				if archive, err = p.Telecharger(u(NomArchive(o.Version)), TailleMaxArchive); err == nil {
					break
				}
			}
		}
		essais = append(essais, b.URL+" : "+err.Error())
	}
	if archive == nil {
		if len(essais) == 0 {
			essais = append(essais, "aucun dépôt")
		}
		return Plan{}, fmt.Errorf("%w : téléchargement impossible — %s", ErrTransitoire, strings.Join(essais, " ; "))
	}

	// 2. La signature, PUIS les empreintes : on ne lit pas un manifeste dont on
	// ne sait pas qui l'a écrit.
	env, err := paquet.LireEnveloppe(string(signature))
	if err != nil {
		return Plan{}, err
	}
	m, err := paquet.Verifier(string(manifeste), env, cles)
	if err != nil {
		return Plan{}, err
	}
	if m.Famille() != famille || m.Version != o.Version {
		return Plan{}, fmt.Errorf("manifeste de %s %s, l'ordre demande %s %s",
			m.Version, m.Plateforme, o.Version, famille)
	}

	// 3. Extraire les cinq fichiers de la famille, et les confronter au
	// manifeste.
	rep := filepath.Join(p.Chemins.Etat, o.Version)
	nouveau := filepath.Join(rep, "nouveau")
	if err := os.RemoveAll(nouveau); err != nil {
		return Plan{}, err
	}
	if err := os.MkdirAll(nouveau, 0o700); err != nil {
		return Plan{}, err
	}
	if err := extraire(archive, famille, nouveau); err != nil {
		return Plan{}, err
	}
	plan := Plan{Version: o.Version, Famille: famille, Retrograder: o.Retrograder, Repertoire: rep,
		Binaire: p.Chemins.Binaire, Unite: p.Chemins.Unite}
	for _, f := range m.Fichiers {
		src := filepath.Join(nouveau, f.Nom)
		somme, err := sommeDe(src)
		if err != nil {
			return Plan{}, err
		}
		if somme != f.SHA256 {
			return Plan{}, fmt.Errorf("%s : empreinte %s, le manifeste signé annonce %s", f.Nom, somme, f.SHA256)
		}
		fp := FichierPlan{Nom: f.Nom, Source: src, SHA256: somme, Mode: 0o755}
		switch {
		case f.Nom == "vaultaire_client":
			fp.Destination, fp.Mode = p.Chemins.Binaire, 0o750
		case strings.HasPrefix(f.Nom, "libnss_"):
			fp.Destination = filepath.Join(repNSS, f.Nom)
		default:
			fp.Destination = filepath.Join(repPAM, f.Nom)
		}
		if err := os.Chmod(src, fp.Mode); err != nil {
			return Plan{}, err
		}
		plan.Fichiers = append(plan.Fichiers, fp)
	}

	// 4. Les modules se chargent-ils sur CETTE machine ? Le contrôle de
	// rocky.sh et debian.sh, repris tel quel : « not found » dans ldd couvre
	// une bibliothèque absente et une version de glibc que le poste n'a pas —
	// le mode de défaillance réel d'un module PAM, vu ici AVANT que sshd ait à
	// le charger. ldd plutôt que dlopen() : l'agent n'emploie pas cgo, et ce
	// contrôle est celui que la recette a validé à l'installation.
	for _, fp := range plan.Fichiers {
		if !strings.HasSuffix(fp.Nom, ".so") && !strings.Contains(fp.Nom, ".so.") {
			continue
		}
		sortie, err := p.Systeme("ldd", fp.Source)
		if manques := lignesNotFound(string(sortie)); manques != "" {
			return Plan{}, fmt.Errorf("%s ne se charge pas sur cette machine : %s", fp.Nom, manques)
		}
		if err != nil {
			return Plan{}, fmt.Errorf("ldd %s : %v", fp.Nom, err)
		}
	}

	// 5. Le nouveau binaire s'exécute-t-il, et lit-il cette configuration ?
	// Le contrôle que l'unité jouera avant chaque démarrage (ExecStartPre).
	if sortie, err := p.Systeme(filepath.Join(nouveau, "vaultaire_client"), "--check"); err != nil {
		return Plan{}, fmt.Errorf("le nouveau binaire refuse de démarrer : %s", premieresLignes(string(sortie), 3))
	}

	b, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return Plan{}, err
	}
	if err := ecrireAtomique(filepath.Join(rep, NomPlan), b, 0o600); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// extraire écrit les cinq fichiers de la famille, à plat, dans dest.
func extraire(archive []byte, famille, dest string) error {
	gz, err := gzip.NewReader(strings.NewReader(string(archive)))
	if err != nil {
		return fmt.Errorf("archive illisible : %w", err)
	}
	defer gz.Close()
	attendus := map[string]string{"vaultaire_client/vaultaire_client": "vaultaire_client"}
	for _, so := range []string{"pam_login_custom_module.so", "pam_logout_custom_module.so",
		"pam_ssh_auth_module.so", "libnss_vaultaire.so.2"} {
		attendus["vaultaire_client/"+famille+"/"+so] = so
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("archive illisible : %w", err)
		}
		nom, ok := attendus[strings.TrimPrefix(filepath.ToSlash(filepath.Clean(h.Name)), "./")]
		if !ok || h.Typeflag != tar.TypeReg {
			continue
		}
		f, err := os.OpenFile(filepath.Join(dest, nom), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		_, errC := io.Copy(f, io.LimitReader(tr, TailleMaxArchive))
		if errF := f.Close(); errC != nil || errF != nil {
			return fmt.Errorf("extraction de %s : %v %v", nom, errC, errF)
		}
		delete(attendus, h.Name)
		delete(attendus, strings.TrimPrefix(filepath.ToSlash(filepath.Clean(h.Name)), "./"))
	}
	if len(attendus) > 0 {
		var manquants []string
		for _, n := range attendus {
			manquants = append(manquants, n)
		}
		return fmt.Errorf("archive incomplète pour la famille %s : %s", famille, strings.Join(manquants, ", "))
	}
	return nil
}

func sommeDe(chemin string) (string, error) {
	f, err := os.Open(chemin)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func lignesNotFound(sortie string) string {
	var out []string
	for _, l := range strings.Split(sortie, "\n") {
		if strings.Contains(strings.ToLower(l), "not found") {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return strings.Join(out, " ; ")
}

func premieresLignes(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[:n]
	}
	return strings.Join(l, " / ")
}
