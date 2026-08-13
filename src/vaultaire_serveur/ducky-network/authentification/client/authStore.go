package client

import (
	"sync"
	"time"

	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// authStore garde les défis d'authentification en attente, indexés par AuthID
// et protégés par mutex.
//
// Ça remplace l'ancienne storage.StorageAuth : une slice globale mutée depuis
// n'importe quelle goroutine de connexion (une par client connecté) sans aucune
// synchronisation, via des patterns append(slice[:i], slice[i+1:]...). Deux
// logins concurrents pouvaient corrompre les index pendant une suppression,
// faire disparaître la mauvaise entrée, voire paniquer.
//
// # Ce qui n'était PAS nettoyé
//
// Une entrée n'était retirée qu'à la consommation du défi — la trame 02_03. Une
// authentification abandonnée entre 02_02 et 02_03 laissait donc la sienne pour
// toute la durée de vie du processus.
//
// Le nettoyage de fermeture de session ne rattrapait rien : il appelait
// `DeleteAuthByID(ClientSoftwareID)` alors que la carte est indexée par AuthID.
// Un commentaire le signalait — « ClientSoftwareID n'est normalement pas un
// AuthID valide ici (comportement préexistant, hors périmètre) » — puis le
// gardait tel quel. La suppression ne trouvait donc jamais rien.
//
// Le défi n'est pas un secret durable, mais son entrée portait aussi le mot de
// passe EN CLAIR (voir storage.Authentification). Un poste qui coupait sa
// connexion au bon moment laissait donc un mot de passe en mémoire, sans limite
// de nombre ni de durée.
//
// Deux corrections : le mot de passe ne rentre plus dans la carte, et une
// ÉCHÉANCE retire les défis non consommés.

// DureeDeVieDefi borne l'attente entre l'émission d'une 02_02 et la 02_03 qui
// la consomme.
//
// Deux minutes : le client répond en quelques centaines de millisecondes — il
// n'a qu'à déchiffrer le jeton avec sa clé privée. Une minute suffirait ; deux
// laissent la marge d'un réseau lent sans rendre l'attente utile à qui voudrait
// accumuler des défis.
var DureeDeVieDefi = 2 * time.Minute

type defiEnAttente struct {
	auth storage.Authentification
	pose time.Time
}

var authStore = struct {
	mu sync.Mutex
	m  map[string]defiEnAttente
}{m: make(map[string]defiEnAttente)}

// maintenant est remplaçable par les tests.
var maintenant = time.Now

// storeAuth enregistre un défi en attente.
func storeAuth(auth storage.Authentification) {
	authStore.mu.Lock()
	defer authStore.mu.Unlock()

	purgerExpires()
	authStore.m[auth.AuthID] = defiEnAttente{auth: auth, pose: maintenant()}
}

// GetRandomAuthByAuthID récupère le défi et le username associés à un AuthID,
// puis le retire du store (usage unique).
//
// Retourne (nil, "") si l'AuthID est inconnu — déjà consommé, expiré, ou jamais
// émis. L'appelant refuse alors la trame : voir le garde-fou de CheckAuth, qui
// distingue ce cas d'un défi vide.
func GetRandomAuthByAuthID(authIDToFind string) ([]byte, string) {
	authStore.mu.Lock()
	defer authStore.mu.Unlock()

	purgerExpires()

	e, ok := authStore.m[authIDToFind]
	if !ok {
		return nil, ""
	}
	delete(authStore.m, authIDToFind)
	return e.auth.RandomAuth, e.auth.Username
}

// DeleteAuthByID retire un défi en attente par AuthID, sans erreur si absent.
func DeleteAuthByID(authID string) {
	authStore.mu.Lock()
	defer authStore.mu.Unlock()
	delete(authStore.m, authID)
}

// SupprimerDefisDuClient retire les défis en attente d'une MACHINE.
//
// C'est ce que la fermeture de session voulait faire, et ne faisait pas : elle
// passait le ClientSoftwareID à DeleteAuthByID, qui attend un AuthID. La carte
// étant indexée par AuthID, la suppression ne trouvait jamais rien.
//
// Le parcours complet plutôt qu'un second index : la carte compte au plus
// quelques dizaines d'entrées — une par authentification en cours — et un index
// secondaire à tenir d'accord serait une occasion de plus de se tromper pour un
// gain nul.
func SupprimerDefisDuClient(clientSoftwareID string) {
	if clientSoftwareID == "" {
		return
	}
	authStore.mu.Lock()
	defer authStore.mu.Unlock()

	for id, e := range authStore.m {
		if e.auth.ClientSoftwareID == clientSoftwareID {
			delete(authStore.m, id)
		}
	}
}

// purgerExpires retire les défis dépassés. L'appelant DOIT détenir le mutex.
//
// Amortie sur les accès plutôt que périodique : la carte n'est touchée qu'à
// l'authentification, et porter une goroutine pour balayer quelques dizaines
// d'entrées coûterait plus que le balayage lui-même.
func purgerExpires() {
	n := maintenant()
	for id, e := range authStore.m {
		if n.Sub(e.pose) > DureeDeVieDefi {
			logs.Write_Log("DEBUG",
				"defi d'authentification expire pour "+e.auth.Username+
					" (machine "+e.auth.ClientSoftwareID+")")
			delete(authStore.m, id)
		}
	}
}

// DefisEnAttente rend le nombre de défis en attente, pour les tests et la
// supervision.
func DefisEnAttente() int {
	authStore.mu.Lock()
	defer authStore.mu.Unlock()
	return len(authStore.m)
}
