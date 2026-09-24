// Package dependances dresse l'inventaire de ce dont Vaultaire dépend, et
// refuse qu'il dérive.
//
// # Ce qu'il y avait avant
//
// Neuf `go.mod`, deux images de base et des listes de paquets dans les
// Dockerfiles. Rien qui dise, en un seul endroit, de quoi le produit dépend —
// et surtout rien qui dise À QUOI chaque dépendance sert. Savoir qu'on tire
// `github.com/pkg/sftp` ne dit pas si on peut s'en passer ; savoir qu'elle
// porte `create -c … -join` le dit.
//
// Trois divergences de version dormaient ainsi entre modules, dont
// `golang.org/x/crypto` en TROIS versions. Un correctif de sécurité appliqué
// dans un module et pas dans les deux autres n'aurait alerté personne.
//
// # Pourquoi c'est un paquet Go et pas un script
//
// Un script produit un rapport, qu'on finit par ne plus lire. Ici l'inventaire
// est un test : il échoue quand la page de documentation ne décrit plus la
// réalité, quand une dépendance arrive sans qu'on dise à quoi elle sert, ou
// quand deux modules divergent sans raison écrite. C'est le même arbitrage
// qu'au point 75 — un contrôle qui ne peut pas dire non ne contrôle rien.
//
// `automatisation/dependances.sh` régénère la page ; le test la garde à jour.
//
// # Pourquoi dans vaultaire_serveur
//
// Il faut un module Go pour que `go test` le ramasse, et l'intégration continue
// les parcourt tous depuis le point 75. `vaultaire_serveur` est celui qui porte
// déjà l'inspection du dépôt (voir core/testrunner/run_core_fingerprint.go),
// donc celui où l'on va déjà chercher ce genre de chose.
package dependances

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Emplacements, relatifs à la racine du dépôt.
const (
	// CheminRoles porte la seule partie ÉCRITE À LA MAIN : à quoi sert chaque
	// dépendance. C'est aussi la seule qui vaille — le reste se lit dans les
	// fichiers et n'a donc pas à être recopié.
	CheminRoles = "docs/Developement/dependances.roles"
	// CheminDoc est la page régénérée.
	CheminDoc = "docs/Developement/how it work/Dependances.md"

	// MarqueDebut et MarqueFin délimitent la partie produite par l'outil. Le
	// texte autour reste écrit à la main : une page entièrement générée n'aurait
	// aucun endroit où expliquer quoi que ce soit.
	MarqueDebut = "<!-- INVENTAIRE:DEBUT — produit par automatisation/dependances.sh, ne pas éditer à la main -->"
	MarqueFin   = "<!-- INVENTAIRE:FIN -->"
)

// Dependance est une bibliothèque tierce et l'état de ses versions dans le dépôt.
type Dependance struct {
	Chemin string
	// Versions associe chaque version aux modules qui la demandent. Plus d'une
	// entrée signifie une divergence.
	Versions map[string][]string
	// Direct dit si au moins un module la déclare en dépendance directe. Une
	// dépendance seulement indirecte n'est importée par aucun de nos fichiers.
	Direct bool
}

// VersionsTriees rend les versions dans un ordre stable.
func (d Dependance) VersionsTriees() []string {
	out := make([]string, 0, len(d.Versions))
	for v := range d.Versions {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Divergente dit si le dépôt en porte plusieurs versions.
func (d Dependance) Divergente() bool { return len(d.Versions) > 1 }

// Image est une image de base employée par un Dockerfile.
type Image struct {
	Reference   string
	Dockerfiles []string
}

// Inventaire est l'état complet à un instant donné.
type Inventaire struct {
	Go      []Dependance
	Images  []Image
	Paquets map[string][]string // Dockerfile -> paquets système installés
	// Internes sont nos propres modules, liés par `replace`. Ils ne sont pas
	// des dépendances tierces et ne se mettent pas à jour : ils sont là pour
	// que la page dise d'où vient ce qui n'est pas dans le tableau.
	Internes []string
}

// RacineDuDepot remonte depuis le répertoire courant jusqu'à la racine.
//
// Le test peut être lancé depuis son paquet comme depuis la racine ; on ne peut
// pas supposer l'un ou l'autre. Le repère est le même que celui de
// core/testrunner, pour qu'il n'y ait pas deux définitions de « la racine ».
func RacineDuDepot() (string, error) {
	depart, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := depart
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "automatisation", "auto_deployements")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("racine du dépôt introuvable depuis %s", depart)
}

// --- lecture des go.mod ------------------------------------------------------

var (
	// Une ligne de `require` : chemin, version, et éventuellement « // indirect ».
	ligneRequire = regexp.MustCompile(`^\s*([a-zA-Z0-9._~/-]+\.[a-zA-Z0-9._~/-]+/[^\s]*|[a-zA-Z0-9._~/-]+/[^\s]*)\s+(v[^\s]+)\s*(//.*)?$`)
	// Une ligne `replace X => ../Y` : nos modules internes.
	ligneReplace = regexp.MustCompile(`^\s*replace\s+([^\s]+)\s+=>\s+(\.\.?/[^\s]+)`)
)

// Scanner dresse l'inventaire depuis les fichiers du dépôt.
func Scanner(racine string) (*Inventaire, error) {
	inv := &Inventaire{Paquets: map[string][]string{}}

	modules, err := filepath.Glob(filepath.Join(racine, "src", "*", "go.mod"))
	if err != nil {
		return nil, err
	}
	if len(modules) == 0 {
		// Zéro module rendrait un inventaire vide, c'est-à-dire un tableau qui
		// dit « aucune dépendance » — le contraire de la vérité, et un test qui
		// passerait. On refuse.
		return nil, fmt.Errorf("aucun go.mod trouvé sous %s/src", racine)
	}
	sort.Strings(modules)

	parChemin := map[string]*Dependance{}
	internes := map[string]bool{}

	for _, chemin := range modules {
		nomModule := filepath.Base(filepath.Dir(chemin))
		contenu, err := os.ReadFile(chemin)
		if err != nil {
			return nil, err
		}

		dansRequire := false
		for _, ligne := range strings.Split(string(contenu), "\n") {
			nue := strings.TrimSpace(ligne)

			if m := ligneReplace.FindStringSubmatch(ligne); m != nil {
				internes[m[1]] = true
				continue
			}
			switch {
			case strings.HasPrefix(nue, "require ("):
				dansRequire = true
				continue
			case dansRequire && nue == ")":
				dansRequire = false
				continue
			case strings.HasPrefix(nue, "//") || nue == "":
				continue
			}

			cible := ligne
			if !dansRequire {
				if !strings.HasPrefix(nue, "require ") {
					continue
				}
				cible = strings.TrimPrefix(nue, "require ")
			}

			m := ligneRequire.FindStringSubmatch(cible)
			if m == nil {
				continue
			}
			chemin, version, suffixe := m[1], m[2], m[3]

			d := parChemin[chemin]
			if d == nil {
				d = &Dependance{Chemin: chemin, Versions: map[string][]string{}}
				parChemin[chemin] = d
			}
			if !strings.Contains(suffixe, "indirect") {
				d.Direct = true
			}
			d.Versions[version] = append(d.Versions[version], nomModule)
		}
	}

	for chemin, d := range parChemin {
		if internes[chemin] {
			// Nos propres modules : ils portent une version fantoche (v0.0.0)
			// remplacée par un chemin local. Les afficher parmi les
			// dépendances tierces ferait croire à une bibliothèque à suivre.
			continue
		}
		for v := range d.Versions {
			sort.Strings(d.Versions[v])
		}
		inv.Go = append(inv.Go, *d)
	}
	sort.Slice(inv.Go, func(i, j int) bool { return inv.Go[i].Chemin < inv.Go[j].Chemin })

	for m := range internes {
		inv.Internes = append(inv.Internes, m)
	}
	sort.Strings(inv.Internes)

	if err := scannerDockerfiles(racine, inv); err != nil {
		return nil, err
	}
	return inv, nil
}

// --- lecture des Dockerfiles -------------------------------------------------

var (
	ligneFrom = regexp.MustCompile(`(?i)^\s*FROM\s+([^\s]+)`)
	// `dnf install -y a b c`, `apt-get install --no-install-recommends a b`, etc.
	debutInstall = regexp.MustCompile(`(?i)\b(dnf|yum|apt-get|apk|microdnf)\s+(?:-[^\s]+\s+)*(?:install|add)\b`)
)

// scannerDockerfiles relève les images de base et les paquets système.
//
// # Ce que cette lecture vaut, et ce qu'elle ne vaut pas
//
// Un `go.mod` est une source de vérité : il est lu par l'outil qui construit.
// Une ligne `dnf install` est du SHELL — elle peut venir d'une variable, d'une
// boucle, d'un script appelé. Ce qui est relevé ici est donc ce qui est écrit
// en clair dans les Dockerfiles, et la page le dit. Mieux vaut un inventaire
// honnête sur ses limites qu'un inventaire qui se croit complet.
func scannerDockerfiles(racine string, inv *Inventaire) error {
	var fichiers []string
	err := filepath.Walk(filepath.Join(racine, "deployments"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		nom := strings.ToLower(info.Name())
		if nom == "dockerfile" || strings.HasPrefix(nom, "dockerfile.") {
			fichiers = append(fichiers, p)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	sort.Strings(fichiers)

	parImage := map[string][]string{}
	for _, f := range fichiers {
		relatif, _ := filepath.Rel(racine, f)
		relatif = filepath.ToSlash(relatif)

		contenu, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		lignes := strings.Split(string(contenu), "\n")

		for i := 0; i < len(lignes); i++ {
			// Les COMMENTAIRES ne sont pas des commandes.
			//
			// `deployments/dev/dockerfile` explique en commentaire que Go ne
			// vient pas de « dnf install golang » — et l'analyse relevait
			// « golang` » comme un paquet installé. Un inventaire qui invente
			// une dépendance est pire qu'un inventaire qui en oublie une :
			// on cherche longtemps ce qui n'existe pas.
			if strings.HasPrefix(strings.TrimSpace(lignes[i]), "#") {
				continue
			}

			if m := ligneFrom.FindStringSubmatch(lignes[i]); m != nil {
				ref := m[1]
				// « FROM x AS constructeur » puis « FROM constructeur » : le
				// second ne désigne pas une image tierce.
				if !strings.Contains(ref, ":") && !strings.Contains(ref, "/") {
					continue
				}
				parImage[ref] = append(parImage[ref], relatif)
				continue
			}

			if loc := debutInstall.FindStringIndex(lignes[i]); loc != nil {
				// Les continuations de ligne font partie de la commande.
				commande := lignes[i][loc[1]:]
				for strings.HasSuffix(strings.TrimRight(commande, " \t"), "\\") && i+1 < len(lignes) {
					commande = strings.TrimSuffix(strings.TrimRight(commande, " \t"), "\\")
					i++
					commande += " " + lignes[i]
				}
				inv.Paquets[relatif] = append(inv.Paquets[relatif], paquetsDe(commande)...)
			}
		}
	}

	for ref, fichiers := range parImage {
		sort.Strings(fichiers)
		inv.Images = append(inv.Images, Image{Reference: ref, Dockerfiles: uniques(fichiers)})
	}
	sort.Slice(inv.Images, func(i, j int) bool { return inv.Images[i].Reference < inv.Images[j].Reference })

	for f := range inv.Paquets {
		inv.Paquets[f] = uniques(inv.Paquets[f])
	}
	return nil
}

// paquetsDe extrait les noms de paquets d'une commande d'installation.
func paquetsDe(commande string) []string {
	// La commande s'arrête au premier enchaînement shell : ce qui suit `&&`
	// n'installe plus rien.
	for _, fin := range []string{"&&", "||", ";"} {
		if i := strings.Index(commande, fin); i >= 0 {
			commande = commande[:i]
		}
	}
	var out []string
	for _, mot := range strings.Fields(commande) {
		// Un nom de paquet ne porte ni accent grave, ni guillemet, ni variable.
		// Ce qui en contient vient d'une phrase, pas d'une commande.
		if strings.HasPrefix(mot, "-") || mot == "\\" ||
			strings.ContainsAny(mot, "$`\"'") {
			continue
		}
		out = append(out, mot)
	}
	sort.Strings(out)
	return uniques(out)
}

func uniques(in []string) []string {
	vus := map[string]bool{}
	var out []string
	for _, s := range in {
		if !vus[s] {
			vus[s] = true
			out = append(out, s)
		}
	}
	return out
}

// --- la partie écrite à la main ----------------------------------------------

// Roles porte ce que les fichiers ne peuvent pas dire.
type Roles struct {
	// Role associe un chemin de dépendance (ou une référence d'image) à ce
	// qu'elle sert.
	Role map[string]string
	// Divergence justifie une dépendance présente en plusieurs versions.
	Divergence map[string]string
}

// LireRoles lit le fichier écrit à la main.
//
// Format volontairement pauvre — « chemin = explication », « !chemin = raison »
// pour une divergence acceptée, « # » en commentaire. Pas de YAML ni de JSON :
// le fichier se relit dans un diff, s'édite sans échapper quoi que ce soit, et
// n'ajoute aucune dépendance à l'outil qui inventorie les dépendances.
func LireRoles(racine string) (*Roles, error) {
	contenu, err := os.ReadFile(filepath.Join(racine, CheminRoles))
	if err != nil {
		return nil, err
	}
	r := &Roles{Role: map[string]string{}, Divergence: map[string]string{}}
	for i, ligne := range strings.Split(string(contenu), "\n") {
		nue := strings.TrimSpace(ligne)
		if nue == "" || strings.HasPrefix(nue, "#") {
			continue
		}
		cle, valeur, ok := strings.Cut(nue, "=")
		if !ok {
			return nil, fmt.Errorf("%s ligne %d : « = » manquant", CheminRoles, i+1)
		}
		cle, valeur = strings.TrimSpace(cle), strings.TrimSpace(valeur)
		if valeur == "" {
			return nil, fmt.Errorf("%s ligne %d : explication vide pour %q", CheminRoles, i+1, cle)
		}
		if strings.HasPrefix(cle, "!") {
			r.Divergence[strings.TrimPrefix(cle, "!")] = valeur
			continue
		}
		r.Role[cle] = valeur
	}
	return r, nil
}

// --- rendu -------------------------------------------------------------------

// Rendre produit le bloc d'inventaire inséré dans la page.
func Rendre(inv *Inventaire, roles *Roles) string {
	var b strings.Builder
	b.WriteString(MarqueDebut + "\n\n")

	fmt.Fprintf(&b, "### Bibliothèques Go — %d\n\n", len(inv.Go))
	b.WriteString("| Dépendance | Version | Lien | À quoi elle sert |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, d := range inv.Go {
		versions := strings.Join(d.VersionsTriees(), "<br>**≠** ")
		if d.Divergente() {
			versions = "**≠** " + versions
		}
		lien := "directe"
		if !d.Direct {
			lien = "indirecte"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n",
			d.Chemin, versions, lien, roles.Role[d.Chemin])
	}

	if divergentes := divergences(inv); len(divergentes) > 0 {
		b.WriteString("\n### Versions divergentes\n\n")
		b.WriteString("Une dépendance tirée en plusieurs versions. Un correctif appliqué à l'une " +
			"ne protège pas les autres.\n\n")
		b.WriteString("| Dépendance | Versions et modules | Pourquoi c'est accepté |\n")
		b.WriteString("|---|---|---|\n")
		for _, d := range divergentes {
			var détails []string
			for _, v := range d.VersionsTriees() {
				détails = append(détails, fmt.Sprintf("`%s` — %s", v, strings.Join(d.Versions[v], ", ")))
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n",
				d.Chemin, strings.Join(détails, "<br>"), roles.Divergence[d.Chemin])
		}
	}

	b.WriteString("\n### Images de base\n\n")
	b.WriteString("| Image | Dockerfiles | À quoi elle sert |\n|---|---|---|\n")
	for _, img := range inv.Images {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n",
			img.Reference, "`"+strings.Join(img.Dockerfiles, "`, `")+"`", roles.Role[img.Reference])
	}

	b.WriteString("\n### Paquets système installés dans les images\n\n")
	b.WriteString("Relevé dans les commandes d'installation écrites en clair. Un `go.mod` est lu " +
		"par l'outil qui construit ; une ligne `dnf install` est du shell, et ce tableau ne " +
		"prétend donc pas à l'exhaustivité.\n\n")
	fichiers := make([]string, 0, len(inv.Paquets))
	for f := range inv.Paquets {
		fichiers = append(fichiers, f)
	}
	sort.Strings(fichiers)
	b.WriteString("| Dockerfile | Paquets |\n|---|---|\n")
	for _, f := range fichiers {
		fmt.Fprintf(&b, "| `%s` | %s |\n", f, "`"+strings.Join(inv.Paquets[f], "`, `")+"`")
	}

	if len(inv.Internes) > 0 {
		b.WriteString("\n### Modules internes\n\n")
		b.WriteString("Nos propres modules, liés par `replace` vers un chemin local. Ils ne se " +
			"mettent pas à jour et ne sont pas des dépendances à suivre.\n\n")
		for _, m := range inv.Internes {
			fmt.Fprintf(&b, "- `%s`\n", m)
		}
	}

	b.WriteString("\n" + MarqueFin + "\n")
	return b.String()
}

// divergences rend les dépendances présentes en plusieurs versions.
func divergences(inv *Inventaire) []Dependance {
	var out []Dependance
	for _, d := range inv.Go {
		if d.Divergente() {
			out = append(out, d)
		}
	}
	return out
}

// RemplacerBloc réécrit la section délimitée dans la page.
func RemplacerBloc(page, bloc string) (string, error) {
	i := strings.Index(page, MarqueDebut)
	j := strings.Index(page, MarqueFin)
	if i < 0 || j < 0 || j < i {
		return "", fmt.Errorf("marques d'inventaire absentes de %s", CheminDoc)
	}
	return page[:i] + bloc + page[j+len(MarqueFin)+1:], nil
}

// BlocActuel extrait la section délimitée d'une page.
func BlocActuel(page string) (string, error) {
	i := strings.Index(page, MarqueDebut)
	j := strings.Index(page, MarqueFin)
	if i < 0 || j < 0 || j < i {
		return "", fmt.Errorf("marques d'inventaire absentes de %s", CheminDoc)
	}
	return page[i : j+len(MarqueFin)+1], nil
}
