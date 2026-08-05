// Package serveurauth traite la catégorie 01 : obtention de la clé publique du
// core, poignée de main, et enrôlement d'un client service.
//
// C'est la seule catégorie qui commence AVANT tout chiffrement : « askkey »
// voyage en clair, puisque c'est justement la clé publique du serveur qu'on
// vient chercher.
package serveurauth

import (
	"fmt"
	"strings"

	"duckynetwork/duckynetwork/keymanagement"
	"duckynetwork/duckynetwork/logs"
	"duckynetwork/duckynetwork/sendmessage"
	"duckynetwork/duckynetwork/storage"
	tramesmanager "duckynetwork/duckynetwork/trames_manager"
)

// AskServerKey demande la clé publique du core et l'enregistre.
//
// # Pourquoi cet échange n'est pas authentifié
//
// Il ne peut pas l'être : c'est le tout premier contact, aucune clé n'est encore
// partagée. N'importe qui peut donc obtenir la clé publique du serveur — ce
// n'est pas un secret, c'est une clé PUBLIQUE.
//
// Ce que cela implique en revanche, c'est qu'un intermédiaire actif pourrait
// substituer la sienne. La parade n'est pas ici : elle est dans le fait de
// pré-déployer la clé du core avec la configuration quand le réseau n'est pas de
// confiance. AskServerKey est le chemin commode, pas le chemin sûr.
func AskServerKey(session *storage.DuckySession, store *keymanagement.Store) error {
	if err := sendmessage.SendRaw(session, []byte("askkey")); err != nil {
		return fmt.Errorf("envoi de askkey : %w", err)
	}

	payload, err := tramesmanager.ReadPayload(session)
	if err != nil {
		return fmt.Errorf("lecture de la réponse askkey : %w", err)
	}

	lines := strings.Split(string(payload), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != "getkey" {
		return fmt.Errorf("réponse askkey inattendue")
	}

	key := strings.Join(lines[1:], "\n")
	if !strings.Contains(key, "-----BEGIN") {
		return fmt.Errorf("la réponse askkey ne contient pas de clé PEM")
	}
	if err := store.WriteServeurPublicKey(key); err != nil {
		return fmt.Errorf("enregistrement de la clé serveur : %w", err)
	}
	logs.Write("INFO", "clé publique du core obtenue et enregistrée")
	return nil
}

// EnsureServerKey récupère la clé du core si elle manque.
func EnsureServerKey(session *storage.DuckySession, store *keymanagement.Store) (string, error) {
	if !store.HasServeurPublicKey() {
		if err := AskServerKey(session, store); err != nil {
			return "", err
		}
	}
	return store.GetServeurPublicKey()
}
