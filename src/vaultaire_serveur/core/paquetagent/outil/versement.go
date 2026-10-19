package outil

// Versement d'un paquet d'agent dans les Nexus du cluster — TO-DO 206.
//
//	vaultaire_serveur --publish-package <archive> [--key <pem>] [--repo <dépôt>]
//	                  [--nexus <https://hôte:port>]… [--ca <pem>]
//	                  [--token-file <fichier>] [--replace-signatures]
//
// Un geste au lieu de quatre : signer l'archive (comme --sign-package), puis
// déposer l'archive, ses manifestes et leurs signatures dans CHAQUE Nexus, et
// relire chaque fichier comme le fera un agent — sans jeton, par l'URL de
// téléchargement.
//
// # Le jeton : fourni au versement, jamais gardé
//
// Le core ne garde aucun identifiant Nexus. L'opérateur passe un jeton nxs_
// à droit de publication, par la variable VAULTAIRE_NEXUS_TOKEN ou par un
// fichier (--token-file) : jamais sur la ligne de commande, que ps et
// l'historique du shell montrent à qui regarde. Le jeton n'est écrit nulle
// part, ni affiché, ni journalisé.
//
// # Ce qui est déjà là
//
// Nexus tient une version publiée pour immuable. Avant de verser, la liste du
// dépôt est relue, et chaque fichier comparé par son empreinte :
//
//   - même empreinte : déjà en place, rien n'est versé ;
//   - absent : versé ;
//   - archive ou manifeste DIFFÉRENT : refus pour ce Nexus, rien n'y est
//     versé — deux octets différents sous le même nom de version, c'est une
//     release refaite, pas un versement à compléter ;
//   - signature différente : une signature PSS change à chaque signature, une
//     autre peut donc valoir la nôtre. Valide pour la clé qui signe : gardée.
//     Sinon (signée par l'ancienne clé, après une bascule 207) : refus, sauf
//     --replace-signatures, qui la supprime et verse la nôtre.
//
// # Quels Nexus
//
// Par défaut, TOUS les Nexus enrôlés — pas seulement ceux annoncés aux
// agents : un Nexus qu'on synchronise avant de l'exposer doit porter les
// paquets le jour où il entre en rotation. Un Nexus hors ligne ou au point
// d'accès inutilisable est un échec du versement, pas un oubli silencieux :
// le code de sortie n'est 0 que si tous sont à jour.

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vaultaire/core/miseajour"
	"vaultaire/core/paquetagent"
)

// VariableJeton : où l'opérateur passe le jeton Nexus.
const VariableJeton = "VAULTAIRE_NEXUS_TOKEN"

// NexusCible : un Nexus où verser. Les champs autres que l'URL ne viennent
// que du cluster (cluster_nodes) et servent au compte rendu.
type NexusCible struct {
	Nom          string
	URL          string // https://hôte:port ; vide si le point d'accès est inutilisable
	EnLigne      bool
	ExposeAgents bool
	Maintenance  bool
	Probleme     string
	// Nomme : donné par --nexus, hors de la liste du cluster.
	Nomme bool
}

// optionsVersement : la ligne de commande, lue.
type optionsVersement struct {
	archive, cle, depot, ca, fichierJeton string
	nexus                                 []string
	remplacerSignatures                   bool
}

func lireOptionsVersement(args []string) (optionsVersement, error) {
	var o optionsVersement
	valeur := func(i *int) (string, error) {
		if *i+1 >= len(args) || strings.HasPrefix(args[*i+1], "--") {
			return "", fmt.Errorf("%s attend une valeur", args[*i])
		}
		*i++
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		var err error
		switch a := args[i]; a {
		case "--key":
			o.cle, err = valeur(&i)
		case "--repo":
			o.depot, err = valeur(&i)
		case "--ca":
			o.ca, err = valeur(&i)
		case "--token-file":
			o.fichierJeton, err = valeur(&i)
		case "--nexus":
			var n string
			n, err = valeur(&i)
			o.nexus = append(o.nexus, n)
		case "--replace-signatures":
			o.remplacerSignatures = true
		case "--token", "--password":
			return o, fmt.Errorf("%s refusé : un jeton sur la ligne de commande se lit dans ps et "+
				"l'historique — passez-le par %s ou --token-file", a, VariableJeton)
		default:
			if strings.HasPrefix(a, "--") || o.archive != "" {
				return o, fmt.Errorf("argument inattendu : %s", a)
			}
			o.archive = a
		}
		if err != nil {
			return o, err
		}
	}
	if o.archive == "" {
		return o, fmt.Errorf("archive à verser absente")
	}
	return o, nil
}

// lireJeton : la variable, ou le fichier s'il est donné. Le fichier gagne :
// il a été nommé pour CETTE commande, la variable peut traîner dans le shell.
func lireJeton(fichier string) (string, error) {
	jeton := os.Getenv(VariableJeton)
	if fichier != "" {
		contenu, err := os.ReadFile(fichier)
		if err != nil {
			return "", fmt.Errorf("lecture du jeton : %w", err)
		}
		jeton = string(contenu)
	}
	jeton = strings.TrimSpace(jeton)
	switch {
	case jeton == "":
		return "", fmt.Errorf("aucun jeton Nexus : passez un jeton nxs_ à droit de publication par %s "+
			"ou --token-file", VariableJeton)
	case strings.ContainsAny(jeton, " \t\r\n"):
		return "", fmt.Errorf("jeton Nexus illisible : une seule ligne, sans espace")
	}
	return jeton, nil
}

// clientNexus : TLS vérifié, toujours. Une AC privée s'ajoute par --ca.
func clientNexus(fichierCA string) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if fichierCA != "" {
		contenu, err := os.ReadFile(fichierCA)
		if err != nil {
			return nil, fmt.Errorf("lecture de l'AC : %w", err)
		}
		if !pool.AppendCertsFromPEM(contenu) {
			return nil, fmt.Errorf("%s : aucun certificat PEM", fichierCA)
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Minute, // une archive de plusieurs dizaines de Mo
		// Une redirection emporterait l'en-tête Authorization ailleurs : on
		// n'en suit aucune.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// NormaliserURLNexus : https://hôte[:port], sans chemin ni identifiants.
func NormaliserURLNexus(saisie string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(saisie))
	switch {
	case err != nil:
		return "", fmt.Errorf("URL Nexus %q illisible : %v", saisie, err)
	case u.Scheme != "https":
		return "", fmt.Errorf("URL Nexus %q refusée : https:// seulement (le jeton passerait en clair)", saisie)
	case u.Host == "" || u.Hostname() == "":
		return "", fmt.Errorf("URL Nexus %q sans hôte", saisie)
	case u.User != nil:
		return "", fmt.Errorf("URL Nexus %q refusée : pas d'identifiants dans l'URL", saisie)
	case strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "":
		return "", fmt.Errorf("URL Nexus %q refusée : la racine du Nexus, sans chemin", saisie)
	}
	return "https://" + u.Host, nil
}

// fichierAVerser : un des fichiers de la release.
type fichierAVerser struct {
	nom       string
	chemin    string
	signature bool
	empreinte string // sha256:<hex>
}

// paquetNexus : une ligne de GET /api/v1/repos/{dépôt}/packages.
type paquetNexus struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Filename string `json:"filename"`
	Digest   string `json:"digest"`
}

func versement(args []string, sortie, erreurs io.Writer, ouvrir func() (Cles, error)) int {
	echec := func(format string, a ...any) int {
		fmt.Fprintf(erreurs, "erreur : "+format+"\n", a...)
		return 1
	}
	o, err := lireOptionsVersement(args)
	if err != nil {
		fmt.Fprintf(erreurs, "erreur : %v\n\n%s", err, Aide)
		return 2
	}

	// Une seule ouverture de la base, quel que soit le nombre de questions.
	var cles *Cles
	ouvrirUneFois := func() (Cles, error) {
		if cles == nil {
			c, err := ouvrir()
			if err != nil {
				return Cles{}, err
			}
			cles = &c
		}
		return *cles, nil
	}

	// Tout ce qui peut échouer sans toucher à rien vient AVANT la signature.
	jeton, err := lireJeton(o.fichierJeton)
	if err != nil {
		return echec("%v", err)
	}
	client, err := clientNexus(o.ca)
	if err != nil {
		return echec("%v", err)
	}
	depot, err := depotDuVersement(o.depot, ouvrirUneFois)
	if err != nil {
		return echec("%v", err)
	}
	cibles, err := ciblesDuVersement(o.nexus, ouvrirUneFois)
	if err != nil {
		return echec("%v", err)
	}

	signee, err := signerArchive(o.archive, o.cle, ouvrirUneFois, true, sortie)
	if err != nil {
		return echec("%v", err)
	}
	fichiers, err := fichiersDeLaRelease(o.archive, signee.Manifestes)
	if err != nil {
		return echec("%v", err)
	}
	version := signee.Manifestes[0].Version

	fmt.Fprintf(sortie, "\nVersement de %s (v%s) dans le dépôt « %s » de %d Nexus :\n",
		filepath.Base(o.archive), strings.TrimPrefix(version, "v"), depot, len(cibles))
	v := verseur{client: client, jeton: jeton, depot: depot, version: version,
		signataire: signee.Signataire, remplacer: o.remplacerSignatures, sortie: sortie}
	reussis := 0
	for _, c := range cibles {
		if v.verser(c, fichiers) {
			reussis++
		}
	}
	fmt.Fprintf(sortie, "\nBilan : %d/%d Nexus à jour.\n", reussis, len(cibles))
	if reussis != len(cibles) {
		return 1
	}
	return 0
}

func depotDuVersement(saisie string, ouvrir func() (Cles, error)) (string, error) {
	if saisie == "" {
		cles, err := ouvrir()
		if err != nil {
			return "", err
		}
		if cles.Depot != nil {
			if saisie, err = cles.Depot(); err != nil {
				return "", err
			}
		}
		if saisie == "" {
			return miseajour.DepotParDefaut, nil
		}
	}
	return miseajour.NormaliserDepot(saisie)
}

func ciblesDuVersement(saisies []string, ouvrir func() (Cles, error)) ([]NexusCible, error) {
	if len(saisies) > 0 {
		var cibles []NexusCible
		for _, s := range saisies {
			u, err := NormaliserURLNexus(s)
			if err != nil {
				return nil, err
			}
			cibles = append(cibles, NexusCible{Nom: strings.TrimPrefix(u, "https://"), URL: u,
				EnLigne: true, ExposeAgents: true, Nomme: true})
		}
		return cibles, nil
	}
	cles, err := ouvrir()
	if err != nil {
		return nil, err
	}
	if cles.Nexus == nil {
		return nil, fmt.Errorf("liste des Nexus du cluster indisponible : nommez-les par --nexus")
	}
	cibles, err := cles.Nexus()
	if err != nil {
		return nil, fmt.Errorf("Nexus du cluster illisibles : %w", err)
	}
	if len(cibles) == 0 {
		return nil, fmt.Errorf("aucun Nexus enrôlé dans le cluster : enrôlez-en un, ou nommez-le par --nexus")
	}
	return cibles, nil
}

// fichiersDeLaRelease : l'archive, puis chaque manifeste, puis les
// signatures. Cet ordre de versement fait qu'un agent qui passe pendant le
// versement trouve au pire une signature absente — un refus propre, jamais
// une signature sans son paquet.
func fichiersDeLaRelease(archive string, manifestes []paquetagent.Manifeste) ([]fichierAVerser, error) {
	liste := []fichierAVerser{{nom: filepath.Base(archive), chemin: archive}}
	for _, m := range manifestes {
		c := paquetagent.NomManifeste(archive, m)
		liste = append(liste, fichierAVerser{nom: filepath.Base(c), chemin: c})
	}
	for _, m := range manifestes {
		c := paquetagent.NomManifeste(archive, m) + ".sig"
		liste = append(liste, fichierAVerser{nom: filepath.Base(c), chemin: c, signature: true})
	}
	for i := range liste {
		e, err := empreinteFichier(liste[i].chemin)
		if err != nil {
			return nil, err
		}
		liste[i].empreinte = e
	}
	return liste, nil
}

func empreinteFichier(chemin string) (string, error) {
	f, err := os.Open(chemin)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("lecture de %s : %w", chemin, err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// verseur porte ce qui est commun à tous les Nexus d'un versement.
type verseur struct {
	client     *http.Client
	jeton      string
	depot      string
	version    string
	signataire *rsa.PublicKey
	remplacer  bool
	sortie     io.Writer
}

// geste : ce qu'on fera d'un fichier sur un Nexus.
type geste int

const (
	enPlace geste = iota
	aVerser
	aRemplacer
	signatureGardee
)

// verser traite un Nexus et dit s'il est à jour.
func (v verseur) verser(c NexusCible, fichiers []fichierAVerser) bool {
	titre := c.Nom
	if !c.Nomme && c.URL != "" {
		titre += " (" + c.URL + ")"
	}
	if c.Maintenance {
		titre += ", en maintenance"
	}
	if !c.ExposeAgents {
		titre += ", non annoncé aux agents"
	}
	fmt.Fprintf(v.sortie, "\n%s\n", titre)
	rate := func(format string, a ...any) bool {
		fmt.Fprintf(v.sortie, "  ÉCHEC : "+format+"\n", a...)
		return false
	}
	switch {
	case c.Probleme != "":
		return rate("%s", c.Probleme)
	case c.URL == "":
		return rate("point d'accès inconnu")
	case !c.EnLigne:
		return rate("hors ligne pour le cluster — à reverser quand il sera revenu")
	}

	presents, err := v.liste(c.URL)
	if err != nil {
		return rate("%v", err)
	}

	// Le plan d'abord, pour tout refuser avant d'avoir rien versé.
	gestes := make([]geste, len(fichiers))
	attendu := make([]string, len(fichiers))
	for i, f := range fichiers {
		attendu[i] = f.empreinte
		p, ok := presents[f.nom]
		switch {
		case !ok:
			gestes[i] = aVerser
		case strings.EqualFold(p.Digest, f.empreinte):
			gestes[i] = enPlace
		case !f.signature:
			return rate("%s est déjà publié avec d'autres octets (%s, le nôtre %s) : une version "+
				"publiée est immuable — rien n'est versé sur ce Nexus", f.nom, court(p.Digest), court(f.empreinte))
		default:
			if v.signatureValide(c.URL, f, p) && !v.remplacer {
				gestes[i] = signatureGardee
				attendu[i] = p.Digest
				continue
			}
			if !v.remplacer {
				return rate("%s est déjà publiée et ne se vérifie pas avec la clé qui signe (ancienne clé ?) : "+
					"relancez avec --replace-signatures pour la remplacer — rien n'est versé sur ce Nexus", f.nom)
			}
			gestes[i] = aRemplacer
		}
	}

	for i, f := range fichiers {
		switch gestes[i] {
		case enPlace:
			fmt.Fprintf(v.sortie, "  déjà en place      %s\n", f.nom)
		case signatureGardee:
			fmt.Fprintf(v.sortie, "  signature gardée   %s (autre signature valide de la même clé)\n", f.nom)
		case aRemplacer:
			if err := v.supprimer(c.URL, presents[f.nom].ID); err != nil {
				return rate("%s : suppression de l'ancienne signature : %v", f.nom, err)
			}
			if err := v.deposer(c.URL, f); err != nil {
				return rate("%s : %v — l'ancienne signature est SUPPRIMÉE, relancez le versement", f.nom, err)
			}
			fmt.Fprintf(v.sortie, "  remplacée          %s\n", f.nom)
		case aVerser:
			if err := v.deposer(c.URL, f); err != nil {
				return rate("%s : %v", f.nom, err)
			}
			fmt.Fprintf(v.sortie, "  versé              %s\n", f.nom)
		}
	}

	// La relecture, comme un agent : sans jeton, par l'URL de téléchargement.
	for i, f := range fichiers {
		lu, err := v.telecharger(c.URL, f.nom)
		if err != nil {
			return rate("relecture de %s : %v", f.nom, err)
		}
		if e := "sha256:" + hex.EncodeToString(sha256Somme(lu)); !strings.EqualFold(e, attendu[i]) {
			return rate("relecture de %s : %s servi, %s attendu", f.nom, court(e), court(attendu[i]))
		}
	}
	fmt.Fprintf(v.sortie, "  vérifié : %d fichier(s) téléchargeables sans jeton, empreintes conformes\n", len(fichiers))
	return true
}

func sha256Somme(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func court(empreinte string) string {
	e := strings.TrimPrefix(empreinte, "sha256:")
	if len(e) > 12 {
		e = e[:12]
	}
	return e
}

// signatureValide : la signature déjà déposée vérifie-t-elle NOTRE manifeste
// avec la clé qui signe ? Lue sans jeton, comme l'agent la lira.
func (v verseur) signatureValide(base string, f fichierAVerser, p paquetNexus) bool {
	texte, err := v.telecharger(base, f.nom)
	if err != nil {
		return false
	}
	env, err := paquetagent.LireEnveloppe(string(texte))
	if err != nil {
		return false
	}
	corps, err := os.ReadFile(strings.TrimSuffix(f.chemin, ".sig"))
	if err != nil {
		return false
	}
	_, err = paquetagent.Verifier(string(corps), env, []*rsa.PublicKey{v.signataire})
	return err == nil
}

func (v verseur) api(base string) string {
	return base + "/api/v1/repos/" + url.PathEscape(v.depot)
}

func (v verseur) requete(methode, adresse string, corps io.Reader, avecJeton bool) (*http.Response, error) {
	req, err := http.NewRequest(methode, adresse, corps)
	if err != nil {
		return nil, err
	}
	if avecJeton {
		req.Header.Set("Authorization", "Bearer "+v.jeton)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		// L'erreur de net/http cite l'URL, jamais l'en-tête : le jeton n'y est pas.
		return nil, err
	}
	return resp, nil
}

// erreurHTTP traduit les réponses que l'opérateur saura corriger.
func erreurHTTP(resp *http.Response, quoi string) error {
	corps, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	message := strings.TrimSpace(string(corps))
	var j struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(corps, &j) == nil && j.Error != "" {
		message = j.Error
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("%s : jeton refusé par ce Nexus (401)", quoi)
	case http.StatusForbidden:
		return fmt.Errorf("%s : refusé (403) — le jeton doit avoir le droit de publication sur le dépôt : %s", quoi, message)
	case http.StatusNotFound:
		return fmt.Errorf("%s : introuvable (404) — le dépôt existe-t-il sur ce Nexus, de type vaultaire ? %s", quoi, message)
	case http.StatusConflict:
		return fmt.Errorf("%s : conflit (409) — %s", quoi, message)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("%s : redirection (%d) vers %s non suivie — donnez l'adresse directe du Nexus",
			quoi, resp.StatusCode, resp.Header.Get("Location"))
	}
	return fmt.Errorf("%s : HTTP %d %s", quoi, resp.StatusCode, message)
}

func (v verseur) liste(base string) (map[string]paquetNexus, error) {
	resp, err := v.requete(http.MethodGet, v.api(base)+"/packages", nil, true)
	if err != nil {
		return nil, fmt.Errorf("liste du dépôt %s : %w", v.depot, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, erreurHTTP(resp, "liste du dépôt "+v.depot)
	}
	var paquets []paquetNexus
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&paquets); err != nil {
		return nil, fmt.Errorf("liste du dépôt %s illisible : %w", v.depot, err)
	}
	out := map[string]paquetNexus{}
	for _, p := range paquets {
		// Le nom de fichier porte la version : un même nom est une même version.
		out[p.Filename] = p
	}
	return out, nil
}

func (v verseur) deposer(base string, f fichierAVerser) error {
	contenu, err := os.Open(f.chemin)
	if err != nil {
		return err
	}
	defer contenu.Close()
	resp, err := v.requete(http.MethodPut, v.api(base)+"/upload/"+url.PathEscape(f.nom), contenu, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return erreurHTTP(resp, "versement")
	}
	return nil
}

func (v verseur) supprimer(base, id string) error {
	resp, err := v.requete(http.MethodDelete, v.api(base)+"/packages/"+url.PathEscape(id), nil, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return erreurHTTP(resp, "suppression")
	}
	return nil
}

// telecharger lit un fichier par l'URL des agents (miseajour/depot.go côté
// agent) : <base>/repo/vaultaire/<dépôt>/download/v<version>/<fichier>.
func (v verseur) telecharger(base, nom string) ([]byte, error) {
	adresse := base + "/repo/vaultaire/" + url.PathEscape(v.depot) + "/download/v" +
		url.PathEscape(strings.TrimPrefix(v.version, "v")) + "/" + url.PathEscape(nom)
	resp, err := v.requete(http.MethodGet, adresse, nil, false)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("HTTP %d sans jeton — le dépôt %s n'est pas public, les agents ne pourront "+
			"pas le lire", resp.StatusCode, v.depot)
	case resp.StatusCode != http.StatusOK:
		return nil, erreurHTTP(resp, "téléchargement")
	}
	var b bytes.Buffer
	if _, err := io.Copy(&b, io.LimitReader(resp.Body, 1<<30)); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
