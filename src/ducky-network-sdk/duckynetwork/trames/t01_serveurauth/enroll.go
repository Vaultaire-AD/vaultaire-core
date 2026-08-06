package serveurauth

import (
	"fmt"
	"strings"
	"time"

	keyencodedecode "duckynetwork/duckynetwork/key_encode_decode"
	"duckynetwork/duckynetwork/keymanagement"
	"duckynetwork/duckynetwork/logs"
	"duckynetwork/duckynetwork/sendmessage"
	"duckynetwork/duckynetwork/storage"
	"duckynetwork/duckynetwork/tools"
	tramesmanager "duckynetwork/duckynetwork/trames_manager"
)

// EnrollError est un refus d'enrôlement renvoyé par le core.
type EnrollError struct{ Code string }

func (e EnrollError) Error() string { return "enrôlement refusé : " + e.Code }

// Enroll génère une paire et fait enregistrer la publique auprès du core.
//
// # Ce que le client ne choisit PAS
//
// Ni son identifiant machine, ni son type. Les deux viennent du core : le
// premier est attribué, le second est porté par la clé d'enrôlement. Un client
// qui pourrait annoncer son type n'aurait qu'à s'enrôler pour se donner les
// privilèges qu'il veut.
//
// # La clé privée ne quitte jamais cet hôte
//
// Elle est produite ici et n'est jamais transmise. C'est toute la différence
// avec l'enrôlement d'un agent, dont le core génère la paire et livre la privée
// avec sa configuration.
func Enroll(session *storage.DuckySession, store *keymanagement.Store, serverPublicKeyPEM, enrollmentKey, label string) (keymanagement.Identity, error) {
	if strings.TrimSpace(enrollmentKey) == "" {
		return keymanagement.Identity{}, fmt.Errorf("clé d'enrôlement absente")
	}

	privatePEM, publicPEM, err := keyencodedecode.GenerateKeyPair()
	if err != nil {
		return keymanagement.Identity{}, err
	}
	tmpKey := tools.GenerateKey()
	// La clé publique voyage en base64 : le format de trame est ligne à ligne,
	// et un PEM en contient plusieurs.
	request := sendmessage.BuildClientTrame(
		"01_05", "serveur_central", tmpKey, "vaultaire", "enrollement",
		enrollmentKey,
	)

	session.IsSafe = false
	if err := sendmessage.SendMessage(request, session, serverPublicKeyPEM); err != nil {
		return keymanagement.Identity{}, fmt.Errorf("envoi de 01_05 : %w", err)
	}

	payload, err := tramesmanager.ReadPayload(session)
	if err != nil {
		return keymanagement.Identity{}, fmt.Errorf("lecture de la réponse d'enrôlement : %w", err)
	}

	// Un refus arrive EN CLAIR : le core n'a pas forcément de clé publique
	// exploitable à ce stade, c'est précisément ce qui peut avoir échoué. On
	// tente donc de lire un refus avant de déchiffrer.
	if trames := tramesmanager.ParseTrames(string(payload)); trames.Code() == "01_06" {
		
	}

	// Une acceptation est chiffrée avec la clé publique qu'on vient de
	// soumettre : la déchiffrer PROUVE que nous détenons la privée
	// correspondante. Même mécanisme que 01_02, un défi explicite serait inutile.
	plain, err := keyencodedecode.DecryptMessageWithPrivate(privatePEM, payload)
	if err != nil {
		return keymanagement.Identity{}, fmt.Errorf("réponse d'enrôlement illisible : %w", err)
	}
	trames := tramesmanager.ParseTrames(plain)
	if trames.Code() != "01_04" {
		return keymanagement.Identity{}, fmt.Errorf("réponse inattendue à l'enrôlement : %s", trames.Code())
	}

	lines := strings.Split(strings.TrimRight(trames.Content, "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return keymanagement.Identity{}, fmt.Errorf("le core n'a attribué aucun identifiant")
	}
	identity := keymanagement.Identity{
		ComputeurID: strings.TrimSpace(lines[0]),
		EnrolledAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if len(lines) > 1 {
		identity.ClientType = strings.TrimSpace(lines[1])
	}

	// Les clés sont écrites AVANT l'identité : une identité sans clé privée
	// serait inexploitable et ne se distinguerait pas d'un enrôlement réussi.
	if err := store.WriteClientKeys(privatePEM, publicPEM); err != nil {
		return keymanagement.Identity{}, fmt.Errorf("identité obtenue mais clés non enregistrées : %w", err)
	}
	if err := store.SaveIdentity(identity); err != nil {
		return keymanagement.Identity{}, fmt.Errorf("identité obtenue mais non enregistrée : %w", err)
	}

	logs.Write("INFO", fmt.Sprintf("enrôlé comme %s (type %s)", identity.ComputeurID, identity.ClientType))
	return identity, nil
}

func firstLine(content string) string {
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[0])
}
