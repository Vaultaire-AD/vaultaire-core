package testrunner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"vaultaire/core/global/security"
)

// Tests du hachage des mots de passe.
//
// # Ce que cette suite ajoute aux tests unitaires
//
// core/global/security/password_test.go couvre déjà l'encodage, la relecture et
// la règle de réencodage. Mais il tourne dans un harnais hors ligne où la
// fonction de dérivation argon2 est REMPLACÉE par une substitution : ce sont
// les décisions du code qui y sont éprouvées, pas la primitive.
//
// Ici, argon2id est le vrai. Deux propriétés ne peuvent être vérifiées que dans
// ces conditions :
//
//   - le COÛT. Une empreinte qui se calcule en une microseconde n'est pas de
//     l'argon2id, quelle que soit l'allure de la chaîne qui la porte. C'est le
//     seul contrôle qui distingue « les paramètres sont écrits dans le format »
//     de « les paramètres sont réellement appliqués » ;
//   - le refus des paramètres nuls AVANT l'appel. Le vrai argon2.IDKey panique
//     sur t=0 ou m=0 ; le contrôle en amont transforme donc une ligne corrompue
//     en base en un simple échec d'authentification, au lieu d'une goroutine
//     d'authentification qui tombe.
func testPassword() []Result {
	var out []Result

	// --- Aller-retour, et coût réel ---------------------------------------

	debut := time.Now()
	empreinte, sel, err := security.Hacher("un mot de passe correct")
	duree := time.Since(debut)

	if err != nil {
		out = append(out, Result{Name: "password: hachage", OK: false, Msg: err.Error()})
		return out
	}
	out = append(out, Result{Name: "password: hachage réussi", OK: true})

	valide, aReencoder := security.Verifier("un mot de passe correct", sel, empreinte)
	out = append(out, Result{
		Name: "password: le bon mot de passe est accepté",
		OK:   valide,
		Msg:  "argon2id refuse le mot de passe qu'il vient de hacher",
	})
	out = append(out, Result{
		Name: "password: une empreinte fraîche n'est pas à réencoder",
		OK:   !aReencoder,
		Msg:  "chaque connexion réécrirait l'empreinte sans raison",
	})

	faux, _ := security.Verifier("un mot de passe FAUX", sel, empreinte)
	out = append(out, Result{
		Name: "password: un mauvais mot de passe est refusé",
		OK:   !faux,
		Msg:  "n'importe quel mot de passe ouvre le compte",
	})

	// LE contrôle qui ne peut pas se faire sans le vrai argon2.
	//
	// Le seuil est délibérément BAS — un millième du budget attendu. Il ne
	// mesure pas la performance de la machine, il distingue un ordre de
	// grandeur : un SHA-256 sur ces entrées se calcule en quelques
	// microsecondes, argon2id à 19 Mio en quelques dizaines de MILLISECONDES.
	// Un seuil serré échouerait sur une machine de test chargée et ferait
	// désactiver la vérification, ce qui est pire que pas de vérification.
	const plancher = 3 * time.Millisecond
	out = append(out, Result{
		Name: "password: le hachage coûte réellement (argon2id appliqué)",
		OK:   duree >= plancher,
		Msg: fmt.Sprintf("hachage en %s, moins que le plancher de %s — "+
			"les paramètres sont peut-être écrits dans le format sans être appliqués",
			duree.Round(time.Microsecond), plancher),
	})

	// --- Deux hachages du même mot de passe diffèrent ----------------------

	a, _, _ := security.Hacher("identique")
	b, _, _ := security.Hacher("identique")
	out = append(out, Result{
		Name: "password: le sel est aléatoire",
		OK:   a != b,
		Msg:  "deux comptes au même mot de passe auraient la même empreinte",
	})

	// --- Le format se décrit lui-même --------------------------------------

	out = append(out, Result{
		Name: "password: l'empreinte porte ses paramètres",
		OK: strings.HasPrefix(empreinte, "$argon2id$v=19$") &&
			strings.Contains(empreinte, fmt.Sprintf("m=%d,t=%d,p=%d",
				security.ArgonMemoireKio, security.ArgonTours, security.ArgonFils)),
		Msg: fmt.Sprintf("empreinte %q : sans les paramètres, une empreinte "+
			"calculée avec d'anciens réglages deviendra illisible", empreinte),
	})

	// --- La migration depuis SHA-256 ---------------------------------------
	//
	// Un compte hérité doit CONTINUER à se connecter, et être signalé comme à
	// réencoder. Perdre la première moitié enferme dehors tout le parc ; perdre
	// la seconde arrête la migration en silence.

	const selHerite = "00112233445566778899aabbccddeeff"
	selBrut, _ := hex.DecodeString(selHerite)
	somme := sha256.Sum256(append(append([]byte{}, selBrut...), []byte("mot de passe historique")...))
	empreinteHeritee := hex.EncodeToString(somme[:])

	valide, aReencoder = security.Verifier("mot de passe historique", selHerite, empreinteHeritee)
	out = append(out, Result{
		Name: "password: un compte SHA-256 se connecte encore",
		OK:   valide,
		Msg:  "tout compte créé avant la bascule serait enfermé dehors",
	})
	out = append(out, Result{
		Name: "password: une empreinte SHA-256 est signalée à réencoder",
		OK:   aReencoder,
		Msg:  "la migration ne démarrerait jamais, sans que rien ne le signale",
	})

	fauxHerite, _ := security.Verifier("mauvais", selHerite, empreinteHeritee)
	out = append(out, Result{
		Name: "password: un mauvais mot de passe est refusé aussi sur SHA-256",
		OK:   !fauxHerite,
		Msg:  "le chemin de compatibilité accepte n'importe quoi",
	})

	// --- Fail-closed --------------------------------------------------------

	illisibles := map[string]string{
		"vide":                   "",
		"texte quelconque":       "pas une empreinte",
		"hexadécimal trop court": strings.Repeat("a", 63),
		"PHC tronquée":           "$argon2id$v=19$m=19456,t=2,p=1$c2VsY2Vs",
		"PHC version inconnue":   strings.Replace(empreinte, "$v=19$", "$v=99$", 1),
		"autre algorithme":       "$argon2i$v=19$m=19456,t=2,p=1$c2Vs$aGFzaA",
		"paramètres à zéro":      "$argon2id$v=19$m=0,t=0,p=0$c2Vsc2Vsc2Vsc2Vsc2Vs$aGFzaGhhc2g",
		"base64 de sel invalide": "$argon2id$v=19$m=19456,t=2,p=1$@@@@$aGFzaA",
	}
	for nom, mauvaise := range illisibles {
		// Le mot de passe passé est CELUI D'ORIGINE pour la version inconnue :
		// c'est le seul moyen que le refus vienne du contrôle de version et non
		// d'un condensat qui ne correspond de toute façon pas.
		accepte, _ := security.Verifier("un mot de passe correct", sel, mauvaise)
		out = append(out, Result{
			Name: "password: empreinte illisible refusée — " + nom,
			OK:   !accepte,
			Msg:  "une empreinte qu'on ne sait pas relire est devinée au lieu d'être refusée",
		})
	}

	// Les paramètres nuls, en particulier : le vrai argon2.IDKey PANIQUE
	// dessus. Sans le contrôle en amont, une ligne corrompue en base ferait
	// tomber la goroutine d'authentification au lieu de refuser la connexion.
	// Ce test ne peut donc pas se faire avec une dérivation substituée.
	out = append(out, Result{
		Name: "password: des paramètres nuls n'ont pas fait paniquer argon2",
		OK:   true,
	})

	return out
}
