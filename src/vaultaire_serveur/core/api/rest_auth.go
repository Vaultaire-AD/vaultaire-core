package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Authentification de l'API REST — TO-DO 270.
//
// # Le même mécanisme que /api/command, transporté dans les en-têtes
//
// Aucune gestion nouvelle : un appel REST est signé avec la clé SSH du compte,
// celle que `vlt` emploie déjà (`add -u <compte> -k`). Le core la vérifie contre
// les clés publiques du compte, par le même chemin que /api/command
// (verifierIdentite) — compte inconnu, révoqué, sans clé et signature fausse
// rendent la même réponse ; la fraîcheur et l'unicité du nonce passent par le
// même registre.
//
// Seul le TRANSPORT change. /api/command signe un corps JSON qui porte la
// commande ; une requête REST porte ses données dans la méthode, le chemin, la
// requête et le corps. La signature les couvre tous :
//
//	VAULTAIRE-REST-1
//	<MÉTHODE>
//	<chemin tel qu'envoyé, échappé>
//	<requête brute, sans « ? », vide s'il n'y en a pas>
//	<compte>
//	<horodatage, secondes Unix>
//	<nonce>
//	<SHA-256 du corps, en hexadécimal minuscule — celui de la chaîne vide sans corps>
//
// lignes séparées par « \n », sans saut final. La signature est la structure
// `ssh.Signature` sérialisée (ssh.Marshal), en base64 standard — exactement ce
// que produit `signer.Sign` côté client, comme pour /api/command.
//
// En-têtes :
//
//	Authorization: Vaultaire-SSH <signature base64>
//	X-Vaultaire-User: <compte>
//	X-Vaultaire-Timestamp: <secondes Unix>
//	X-Vaultaire-Nonce: <aléa, 16 caractères au moins>
//
// La première ligne fixe le PROTOCOLE : une signature produite pour
// /api/command (un JSON) ne peut jamais être acceptée ici, ni l'inverse.

const (
	schemaSignatureREST = "Vaultaire-SSH"
	enteteUtilisateur   = "X-Vaultaire-User"
	enteteHorodatage    = "X-Vaultaire-Timestamp"
	enteteNonce         = "X-Vaultaire-Nonce"
	prefixeCanonique    = "VAULTAIRE-REST-1"
)

// identiteREST est ce que l'authentification établit.
type identiteREST struct {
	Username string
	UserID   int
}

// ChaineCanoniqueREST rend la chaîne signée d'une requête.
//
// Exportée : le client (`vlt api`, api_client_package) doit produire EXACTEMENT
// la même, et un test des deux côtés vaut mieux qu'une description.
func ChaineCanoniqueREST(methode, chemin, requete, compte string, horodatage int64, nonce string, corps []byte) []byte {
	somme := sha256.Sum256(corps)
	return []byte(strings.Join([]string{
		prefixeCanonique,
		strings.ToUpper(methode),
		chemin,
		requete,
		compte,
		strconv.FormatInt(horodatage, 10),
		nonce,
		hex.EncodeToString(somme[:]),
	}, "\n"))
}

// authentifierREST vérifie la SIGNATURE d'une requête REST et rend l'identité,
// ainsi que le nonce et l'horodatage que l'appelant contrôlera ensuite
// (verifierFraicheur).
//
// Deux temps, comme /api/command : la signature d'abord, la fraîcheur ensuite —
// un nonce n'est consommé que par une requête authentique, sans quoi n'importe
// qui pourrait « brûler » les nonces d'un client en les devinant ; et seul un
// échec de SIGNATURE compte dans les échecs de la source.
func authentifierREST(r *http.Request, corps []byte) (identiteREST, string, int64, error) {
	compte := strings.TrimSpace(r.Header.Get(enteteUtilisateur))
	nonce := strings.TrimSpace(r.Header.Get(enteteNonce))
	horodatage, errH := strconv.ParseInt(strings.TrimSpace(r.Header.Get(enteteHorodatage)), 10, 64)

	signature := ""
	if a := strings.TrimSpace(r.Header.Get("Authorization")); a != "" {
		schema, valeur, ok := strings.Cut(a, " ")
		if ok && strings.EqualFold(schema, schemaSignatureREST) {
			signature = strings.TrimSpace(valeur)
		}
	}

	if compte == "" || signature == "" {
		return identiteREST{}, "", 0,
			fmt.Errorf("en-têtes d'authentification absents (%s, Authorization: %s …)", enteteUtilisateur, schemaSignatureREST)
	}
	if errH != nil {
		return identiteREST{Username: compte}, "", 0, fmt.Errorf("%s invalide", enteteHorodatage)
	}

	canonique := ChaineCanoniqueREST(r.Method, r.URL.EscapedPath(), r.URL.RawQuery, compte, horodatage, nonce, corps)
	userID, err := verifierIdentite(compte, canonique, signature)
	if err != nil {
		return identiteREST{Username: compte, UserID: userID}, "", 0, err
	}
	return identiteREST{Username: compte, UserID: userID}, nonce, horodatage, nil
}
