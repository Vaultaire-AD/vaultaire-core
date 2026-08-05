package ssh

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// computePasswordHash reproduit le condensé stocké par le core.
//
// L'ordre SEL PUIS MOT DE PASSE n'est pas indifférent : il doit être identique à
// celui de la création du compte, côté core. L'inverser produit une preuve
// toujours refusée, sans le moindre message qui désigne la cause.
func computePasswordHash(password, saltHex string) ([]byte, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("sel hexadécimal invalide : %w", err)
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))
	return h.Sum(nil), nil
}

// GenerateChallengeProof calcule la preuve à envoyer en 03_01.
//
// # Ce qui entre dans le HMAC, et pourquoi
//
//	clé      : le condensé du mot de passe — jamais transmis
//	message  : username | aléa du serveur | identifiant de session
//
// L'aléa empêche de rejouer une preuve capturée sur un autre échange.
// L'identifiant de session l'attache À CETTE connexion : une preuve interceptée
// ne vaut rien sur une autre session, même dans la même seconde.
//
// # username entier, domaine compris
//
// Le core recalcule avec le nom TEL QU'IL A ÉTÉ ENVOYÉ. Retirer le domaine ici
// pour « faire propre » donne deux HMAC différents des deux côtés, et un refus
// que rien n'explique.
//
// Ni le mot de passe ni son condensé ne sortent de cette fonction.
func GenerateChallengeProof(username, password, saltHex, serverNonce, sessionID string) (string, error) {
	if username == "" || password == "" || saltHex == "" || serverNonce == "" || sessionID == "" {
		return "", fmt.Errorf("paramètre manquant pour le calcul de la preuve")
	}

	passwordHash, err := computePasswordHash(password, saltHex)
	if err != nil {
		return "", err
	}
	// Effacement au mieux. Go ne garantit pas qu'une copie ne traîne pas
	// ailleurs en mémoire, mais ne rien faire garantirait l'inverse.
	defer func() {
		for i := range passwordHash {
			passwordHash[i] = 0
		}
	}()

	mac := hmac.New(sha256.New, passwordHash)
	mac.Write([]byte(fmt.Sprintf("%s|%s|%s", username, serverNonce, sessionID)))
	return hex.EncodeToString(mac.Sum(nil)), nil
}
