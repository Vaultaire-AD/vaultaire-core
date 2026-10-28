package paquet

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// L'enveloppe de signature — le fichier `<manifeste>.sig`.
//
//	vaultaire-pkg-sig-v1
//	SHA256:<empreinte de la clé publique>
//	<signature RSA-PSS SHA-256, base64>
//
// # Pourquoi l'empreinte de la clé est dans l'enveloppe
//
// Pour la ROTATION, prévue dès le format : un agent doit pouvoir faire
// confiance à deux clés — l'ancienne et la suivante —, sinon remplacer la clé
// demanderait de repasser sur chaque machine. L'empreinte désigne celle qui a
// signé. Elle n'est PAS une preuve : l'agent ne vérifie qu'avec une clé qu'il
// tient déjà, et une empreinte qu'il ne connaît pas est un refus. Elle sert
// au message — « signé par SHA256:…, que cette machine ne connaît pas » dit
// tout de suite qu'il manque une clé, et laquelle.
//
// RSA-PSS SHA-256, comme les politiques GPO : même algorithme, bibliothèque
// standard, rien à ajouter à l'agent.

// EnteteEnveloppe est la première ligne du fichier de signature.
const EnteteEnveloppe = "vaultaire-pkg-sig-v1"

// Enveloppe est un fichier de signature analysé.
type Enveloppe struct {
	EmpreinteCle string
	Signature    []byte
}

// Texte rend le fichier de signature.
func (e Enveloppe) Texte() string {
	return EnteteEnveloppe + "\n" + e.EmpreinteCle + "\n" +
		base64.StdEncoding.EncodeToString(e.Signature) + "\n"
}

// LireEnveloppe analyse un fichier de signature.
func LireEnveloppe(texte string) (Enveloppe, error) {
	lignes := strings.Split(strings.TrimRight(texte, "\n"), "\n")
	if len(lignes) != 3 || lignes[0] != EnteteEnveloppe {
		return Enveloppe{}, fmt.Errorf("signature : en-tête %q attendu sur trois lignes", EnteteEnveloppe)
	}
	if !strings.HasPrefix(lignes[1], "SHA256:") {
		return Enveloppe{}, fmt.Errorf("signature : empreinte de clé illisible")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lignes[2]))
	if err != nil || len(sig) == 0 {
		return Enveloppe{}, fmt.Errorf("signature : base64 illisible")
	}
	return Enveloppe{EmpreinteCle: lignes[1], Signature: sig}, nil
}

// EmpreinteCle rend « SHA256:… » sur le DER d'une clé publique — la même forme
// que l'empreinte du core et celle de la clé des GPO.
func EmpreinteCle(cle *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(cle)
	if err != nil {
		return "", fmt.Errorf("empreinte de clé : %w", err)
	}
	somme := sha256.Sum256(der)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(somme[:]), nil
}

var optionsPSS = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}

// Verifier contrôle une enveloppe contre les clés de confiance, et rend le
// manifeste. Seule une clé que la machine TIENT déjà peut valider : l'empreinte
// de l'enveloppe ne fait que la désigner.
func Verifier(corps string, e Enveloppe, cles []*rsa.PublicKey) (Manifeste, error) {
	m, err := Lire(corps)
	if err != nil {
		return Manifeste{}, err
	}
	for _, cle := range cles {
		empreinte, err := EmpreinteCle(cle)
		if err != nil || empreinte != e.EmpreinteCle {
			continue
		}
		condense := sha256.Sum256([]byte(corps))
		if err := rsa.VerifyPSS(cle, crypto.SHA256, condense[:], e.Signature, optionsPSS); err != nil {
			return Manifeste{}, fmt.Errorf("signature invalide pour la clé %s", empreinte)
		}
		return m, nil
	}
	return Manifeste{}, fmt.Errorf("signé par %s, clé inconnue de ce côté", e.EmpreinteCle)
}

// LireClesPubliques lit tous les blocs PEM d'un fichier de clés de confiance.
// Le texte hors des blocs (les commentaires du fichier déposé) est ignoré.
func LireClesPubliques(contenu []byte) ([]*rsa.PublicKey, error) {
	var cles []*rsa.PublicKey
	reste := contenu
	for {
		var bloc *pem.Block
		bloc, reste = pem.Decode(reste)
		if bloc == nil {
			break
		}
		if brute, err := x509.ParsePKIXPublicKey(bloc.Bytes); err == nil {
			if cle, ok := brute.(*rsa.PublicKey); ok {
				cles = append(cles, cle)
				continue
			}
			return nil, fmt.Errorf("clé publique : RSA attendue")
		}
		cle, err := x509.ParsePKCS1PublicKey(bloc.Bytes)
		if err != nil {
			return nil, fmt.Errorf("clé publique illisible : %w", err)
		}
		cles = append(cles, cle)
	}
	if len(cles) == 0 {
		return nil, fmt.Errorf("aucune clé publique dans le fichier")
	}
	return cles, nil
}
