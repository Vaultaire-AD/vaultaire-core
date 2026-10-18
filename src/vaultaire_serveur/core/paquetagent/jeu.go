package paquetagent

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Le jeu de clés de confiance — TO-DO 207, la rotation de pkg_signing.
//
// # Ce qui est signé
//
//	vaultaire-pkg-trust-v1
//	<numéro>                      entier > 0, croissant
//	cle <DER PKIX en base64>      une ligne par clé, au moins une
//
// Le jeu COMPLET, pas un « ajoute » ou un « retire » : un seul format couvre
// l'ajout et le retrait, et l'agent n'a jamais à composer un état à partir
// d'opérations. Le numéro ferme le rejeu : un agent n'accepte qu'un jeu plus
// haut que le sien, signé par une clé qu'il tient DÉJÀ. Les jeux successifs
// forment une chaîne — un agent en retard les reçoit un par un, chacun signé
// par une clé du précédent.
//
// En-tête distinct de celui du manifeste (Domaine) : une signature de jeu ne
// vaut pas pour un paquet, ni l'inverse — Lire refuse l'un, LireJeu l'autre.
//
// # Ce que ce jeu ne sait PAS faire
//
// Remplacer une clé COMPROMISE. Qui détient l'ancienne clé peut signer un jeu
// comme le core : le canal ne sert qu'aux rotations planifiées. Une
// compromission se traite hors bande — voir --pkg-key compromised.

// EnteteJeu ouvre le corps signé d'un jeu.
const EnteteJeu = "vaultaire-pkg-trust-v1"

// Jeu est un jeu de clés de confiance.
type Jeu struct {
	Numero int
	Cles   []*rsa.PublicKey
}

var formeNumeroJeu = regexp.MustCompile(`^[1-9][0-9]{0,8}$`)

// Corps rend le texte canonique, celui qui est signé.
func (j Jeu) Corps() (string, error) {
	if j.Numero < 1 {
		return "", fmt.Errorf("jeu : numéro %d, 1 au moins", j.Numero)
	}
	if len(j.Cles) == 0 {
		return "", fmt.Errorf("jeu : aucune clé")
	}
	var b strings.Builder
	b.WriteString(EnteteJeu + "\n" + strconv.Itoa(j.Numero) + "\n")
	vues := map[string]bool{}
	for _, c := range j.Cles {
		der, err := x509.MarshalPKIXPublicKey(c)
		if err != nil {
			return "", fmt.Errorf("jeu : clé illisible : %w", err)
		}
		ligne := base64.StdEncoding.EncodeToString(der)
		if vues[ligne] {
			return "", fmt.Errorf("jeu : une clé y figure deux fois")
		}
		vues[ligne] = true
		b.WriteString("cle " + ligne + "\n")
	}
	return b.String(), nil
}

// LireJeu analyse un corps et refuse toute écriture non canonique.
func LireJeu(corps string) (Jeu, error) {
	l := strings.Split(strings.TrimSuffix(corps, "\n"), "\n")
	if !strings.HasSuffix(corps, "\n") || len(l) < 3 || l[0] != EnteteJeu {
		return Jeu{}, fmt.Errorf("jeu : en-tête %q attendu, puis un numéro et au moins une clé", EnteteJeu)
	}
	if !formeNumeroJeu.MatchString(l[1]) {
		return Jeu{}, fmt.Errorf("jeu : numéro %q illisible", l[1])
	}
	n, _ := strconv.Atoi(l[1])
	j := Jeu{Numero: n}
	for _, ligne := range l[2:] {
		b64, ok := strings.CutPrefix(ligne, "cle ")
		if !ok {
			return Jeu{}, fmt.Errorf("jeu : ligne %q inattendue", ligne)
		}
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return Jeu{}, fmt.Errorf("jeu : clé en base64 illisible")
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return Jeu{}, fmt.Errorf("jeu : clé illisible : %w", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok || rsaPub.N.BitLen() < 3072 {
			return Jeu{}, fmt.Errorf("jeu : clé RSA de 3072 bits au moins attendue")
		}
		j.Cles = append(j.Cles, rsaPub)
	}
	if relu, err := j.Corps(); err != nil || relu != corps {
		return Jeu{}, fmt.Errorf("jeu : écriture non canonique")
	}
	return j, nil
}

// SignerJeu signe un jeu.
func SignerJeu(j Jeu, cle *rsa.PrivateKey) (string, Enveloppe, error) {
	corps, err := j.Corps()
	if err != nil {
		return "", Enveloppe{}, fmt.Errorf("refus de signer : %w", err)
	}
	if cle.N.BitLen() < 3072 {
		return "", Enveloppe{}, fmt.Errorf("refus de signer : clé de %d bits, 3072 au moins", cle.N.BitLen())
	}
	empreinte, err := EmpreinteCle(&cle.PublicKey)
	if err != nil {
		return "", Enveloppe{}, err
	}
	condense := sha256.Sum256([]byte(corps))
	sig, err := rsa.SignPSS(rand.Reader, cle, crypto.SHA256, condense[:], optionsPSS)
	if err != nil {
		return "", Enveloppe{}, fmt.Errorf("signature du jeu : %w", err)
	}
	return corps, Enveloppe{EmpreinteCle: empreinte, Signature: sig}, nil
}

// VerifierJeu contrôle un jeu contre des clés de confiance. Le core s'en sert
// pour relire ce qu'il vient de signer ; l'agent a la sienne, jumelle.
func VerifierJeu(corps string, e Enveloppe, cles []*rsa.PublicKey) (Jeu, error) {
	j, err := LireJeu(corps)
	if err != nil {
		return Jeu{}, err
	}
	for _, c := range cles {
		empreinte, err := EmpreinteCle(c)
		if err != nil || empreinte != e.EmpreinteCle {
			continue
		}
		condense := sha256.Sum256([]byte(corps))
		if err := rsa.VerifyPSS(c, crypto.SHA256, condense[:], e.Signature, optionsPSS); err != nil {
			return Jeu{}, fmt.Errorf("jeu n°%d : signature invalide pour la clé %s", j.Numero, empreinte)
		}
		return j, nil
	}
	return Jeu{}, fmt.Errorf("jeu n°%d : signé par %s, clé inconnue de ce côté", j.Numero, e.EmpreinteCle)
}

// --- le fichier de la machine --------------------------------------------------

// MarqueNumeroJeu : la ligne du fichier pkg_signing_key.pem qui dit le numéro
// du jeu qu'il porte. Absente : 0, le fichier de l'installation.
const MarqueNumeroJeu = "# vaultaire-pkg-trust n="

var reNumeroFichier = regexp.MustCompile(`(?m)^# vaultaire-pkg-trust n=([0-9]{1,9})$`)

// NumeroDuFichier rend le numéro porté par un fichier de clés, 0 sans ligne.
func NumeroDuFichier(contenu string) int {
	m := reNumeroFichier.FindStringSubmatch(contenu)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// FichierCles rend le fichier pkg_signing_key.pem d'un jeu — LE MÊME texte
// écrit par le core à l'installation et par l'agent qui applique un jeu
// (vaultaire_client/paquet.FichierCles, vecteur jumeau). Numéro 0 : pas de
// ligne de numéro.
func FichierCles(j Jeu) (string, error) {
	var b strings.Builder
	b.WriteString("# Clés publiques de signature des paquets d'agent du cluster Vaultaire.\n" +
		"# Déposées à l'installation, puis tenues à jour par l'agent (jeux signés, TO-DO 207).\n" +
		"# Un paquet dont le manifeste n'est pas signé par une clé de ce fichier est refusé.\n")
	if j.Numero > 0 {
		b.WriteString(MarqueNumeroJeu + strconv.Itoa(j.Numero) + "\n")
	}
	if len(j.Cles) == 0 {
		return "", fmt.Errorf("fichier de clés : aucune clé")
	}
	for _, c := range j.Cles {
		der, err := x509.MarshalPKIXPublicKey(c)
		if err != nil {
			return "", err
		}
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}))
	}
	return b.String(), nil
}
