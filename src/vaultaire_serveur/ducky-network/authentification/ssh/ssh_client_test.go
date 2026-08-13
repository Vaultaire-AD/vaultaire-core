package sshclient

import (
	"testing"

	"vaultaire/core/reglages"
)

// TestLePrefixeDesGroupesEstFige.
//
// L'agent déclare la MÊME chaîne, dans un autre module Go (vaultaire_client,
// paquet sshauth). Aucune compilation ne peut lier les deux : le serveur ne
// dépend pas de l'agent, et l'agent ne dépend pas du serveur.
//
// Changer la valeur d'un seul côté n'échoue nulle part. Le serveur enverrait une
// ligne que l'agent ne reconnaîtrait pas, la prendrait pour une clé publique, et
// l'écrirait dans authorized_keys — où sshd l'ignorerait sans rien dire. Les
// appartenances ne seraient jamais posées, et aucun journal ne le signalerait.
//
// Ce test et son jumeau côté agent (sshauth/groupes_trame_test.go) figent donc
// la chaîne aux deux bouts : la modifier fait échouer les tests avant le
// déploiement, ce que le compilateur ne peut pas faire ici.
func TestLePrefixeDesGroupesEstFige(t *testing.T) {
	if PrefixeGroupes != "groups:" {
		t.Errorf("PrefixeGroupes = %q : la valeur doit rester identique à celle de "+
			"l'agent (vaultaire_client/sshauth)", PrefixeGroupes)
	}
	if PrefixeCadence != "sync:" {
		t.Errorf("PrefixeCadence = %q : la valeur doit rester identique à celle de "+
			"l'agent (vaultaire_client/sshauth)", PrefixeCadence)
	}
}

// TestLaCadenceEstDansLesBornesDuReglage.
//
// La cadence part dans 03_09 : c'est un réglage du core qui pilote une boucle du
// PARC. Un zéro ou un négatif y ferait tourner la boucle de l'agent sans attendre
// — chaque machine redemanderait sa liste en continu, et le core recevrait autant
// de 03_08 qu'il peut en traiter.
//
// `reglages.Valeur` applique déjà les bornes du catalogue ; ce test vérifie que
// la définition elle-même ne peut pas les rendre absurdes.
func TestLaCadenceEstDansLesBornesDuReglage(t *testing.T) {
	d, ok := reglages.DefinitionDe(reglages.CleSynchroGroupes)
	if !ok {
		t.Fatal("group_sync_minutes absent du catalogue des réglages")
	}
	if d.Min < 1 {
		t.Errorf("minimum = %d : une cadence nulle ferait boucler l'agent sans "+
			"attendre", d.Min)
	}
	if d.Defaut < d.Min || d.Defaut > d.Max {
		t.Errorf("défaut %d hors des bornes %d-%d", d.Defaut, d.Min, d.Max)
	}

	// La valeur courante n'est PAS lue ici : `reglages.Valeur` passe par la base,
	// et un test qui la traverserait ne dirait plus rien sur une machine sans
	// base. C'est la définition qu'on éprouve — le reste est déjà couvert par
	// les tests de core/reglages, qui substituent la lecture.
}

// TestLePrefixeNePeutPasEtreConfonduAvecUneCle.
//
// Une clé publique commence par son type d'algorithme. Si le préfixe devenait un
// de ces mots, l'agent lirait des clés comme des listes de groupes : elles
// disparaîtraient d'authorized_keys, et l'utilisateur perdrait son accès.
func TestLePrefixeNePeutPasEtreConfonduAvecUneCle(t *testing.T) {
	typesDeCle := []string{
		"ssh-rsa", "ssh-ed25519", "ssh-dss",
		"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
		"sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
	}
	for _, t2 := range typesDeCle {
		if len(t2) >= len(PrefixeGroupes) && t2[:len(PrefixeGroupes)] == PrefixeGroupes {
			t.Errorf("le préfixe %q ouvre aussi les clés de type %q : l'agent lirait "+
				"ces clés comme des groupes", PrefixeGroupes, t2)
		}
	}
}
