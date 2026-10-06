package api

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"sync"

	"vaultaire/core/logs"

	"golang.org/x/crypto/ssh"
)

// Clés-leurres : le même travail pour un compte inconnu que pour un compte réel
// (TO-DO 102).
//
// # Le défaut
//
// « Utilisateur introuvable » sortait AVANT la lecture des clés et la
// vérification de signature. Le temps de réponse disait donc, sans aucun droit,
// si un nom existait dans l'annuaire — et le message le disait aussi.
//
// # La correction
//
// Pour un compte inconnu, révoqué ou sans clé, la signature est quand même
// vérifiée, contre une clé tirée au hasard au démarrage et dont personne ne
// détient la partie privée. La vérification échoue toujours, mais elle coûte ce
// que coûte une vraie.
//
// Une clé DU MÊME TYPE que la signature reçue : vérifier une signature RSA
// contre une clé ed25519 échoue dès la comparaison des formats, sans calcul —
// le compte inconnu redeviendrait le plus rapide.
//
// Ce qui reste : un compte à dix clés coûte dix vérifications, un compte
// inconnu une seule. Le temps trahit le NOMBRE de clés, pas l'existence du
// compte — un compte à une clé et un nom inventé ne se distinguent plus.

var (
	leurresUneFois sync.Once
	leurres        map[string]ssh.PublicKey
)

// preparerLeurres tire les clés-leurres. Appelée au démarrage de l'API : la clé
// RSA prend une fraction de seconde à générer, et la première requête vers un
// compte inconnu ne doit pas être reconnaissable à ce délai-là.
func preparerLeurres() {
	leurresUneFois.Do(func() {
		leurres = map[string]ssh.PublicKey{}
		ajouter := func(nom string, cle interface{}, err error) {
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeAPISign, "api: cle-leurre "+nom+" : "+err.Error())
				return
			}
			pub, err := ssh.NewPublicKey(cle)
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeAPISign, "api: cle-leurre "+nom+" : "+err.Error())
				return
			}
			leurres[nom] = pub
		}

		r, err := rsa.GenerateKey(rand.Reader, 2048)
		if err == nil {
			ajouter("rsa", &r.PublicKey, nil)
		} else {
			ajouter("rsa", nil, err)
		}
		e, _, err := ed25519.GenerateKey(rand.Reader)
		ajouter("ed25519", e, err)
		for nom, courbe := range map[string]elliptic.Curve{
			"nistp256": elliptic.P256(), "nistp384": elliptic.P384(), "nistp521": elliptic.P521(),
		} {
			k, err := ecdsa.GenerateKey(courbe, rand.Reader)
			if err == nil {
				ajouter(nom, &k.PublicKey, nil)
			} else {
				ajouter(nom, nil, err)
			}
		}
	})
}

// leurrePour rend la clé-leurre du type d'une signature, nil si le type est
// inconnu — auquel cas aucune vraie clé ne la vérifierait non plus, et le refus
// ne coûte rien dans les deux cas.
func leurrePour(format string) ssh.PublicKey {
	preparerLeurres()
	switch {
	case format == ssh.KeyAlgoRSA || strings.HasPrefix(format, "rsa-sha2-"):
		return leurres["rsa"]
	case format == ssh.KeyAlgoED25519:
		return leurres["ed25519"]
	case strings.HasPrefix(format, "ecdsa-sha2-"):
		return leurres[strings.TrimPrefix(format, "ecdsa-sha2-")]
	}
	return nil
}
