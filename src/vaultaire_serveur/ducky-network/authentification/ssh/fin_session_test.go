package sshclient

import (
	"testing"

	"vaultaire/core/clienttype"
	"vaultaire/core/storage"
)

// 03_11 efface une ligne de session en base. Les deux refus ci-dessous sont
// donc les seules protections du chemin — ils s'exécutent AVANT toute lecture
// de base, et ces tests tournent sans base pour cette raison.

// Le compte `vaultaire` est le TUNNEL de la machine. Effacer sa ligne ferait
// disparaître la machine de `status -c` alors qu'elle est bien là : c'est
// exactement le défaut du point 64, atteint par un autre chemin.
func TestUneFinDeSessionNeFermeJamaisLeTunnelMachine(t *testing.T) {
	for _, nom := range []string{"vaultaire", "vaultaire@test.fr", "  vaultaire  "} {
		trame := storage.Trames_struct_client{
			Message_Order:    []string{"03", "11"},
			ClientSoftwareID: "poste-42",
			Content:          nom,
		}
		if r := SSH_Fin_De_Session(trame); r != "" {
			t.Errorf("%q : réponse %q, la trame ne doit rien répondre", nom, r)
		}
	}
	// Aucune base n'est ouverte ici : si l'un de ces noms avait franchi le
	// refus, le test aurait atteint database.GetDatabase() et échoué.
}

// Une trame tronquée ou vide ne doit pas être interprétée comme une demande
// portant sur un utilisateur vide — la résolution en base retournerait alors
// n'importe quoi.
func TestUneFinDeSessionSansUtilisateurEstIgnoree(t *testing.T) {
	for _, contenu := range []string{"", "\n", "   ", "\n\nalice@test.fr"} {
		trame := storage.Trames_struct_client{
			Message_Order:    []string{"03", "11"},
			ClientSoftwareID: "poste-42",
			Content:          contenu,
		}
		if r := SSH_Fin_De_Session(trame); r != "" {
			t.Errorf("contenu %q : réponse %q attendue vide", contenu, r)
		}
	}
}

// L'utilisateur est nommé dans le CONTENU, la machine vient de l'en-tête
// authentifié. Ce test fige la lecture du contenu : prendre la deuxième ligne,
// ou tout le contenu, ferait porter la suppression sur un autre compte.
func TestSeuleLaPremiereLigneNommeLUtilisateur(t *testing.T) {
	cas := map[string]string{
		"alice@test.fr":            "alice@test.fr",
		"alice@test.fr\nbob@x.fr":  "alice@test.fr",
		"  alice@test.fr  \nbruit": "  alice@test.fr  ",
		"":                         "",
	}
	for contenu, attendu := range cas {
		if got := lignePremiere(contenu); got != attendu {
			t.Errorf("lignePremiere(%q) = %q, attendu %q", contenu, got, attendu)
		}
	}
}

// Sans cette entrée au catalogue, la connexion de l'agent est FERMÉE à la
// première fin de session : le Spliter traite une trame non déclarée comme une
// tentative d'un client qui sort de son rôle. Le symptôme serait une machine
// qui perd son tunnel chaque fois que quelqu'un se déconnecte.
func TestLAgentADroitDEmettreLaFinDeSession(t *testing.T) {
	if !clienttype.MayEmit(clienttype.Client, "03_11") {
		t.Error("03_11 absente des trames autorisées à vaultaire_client")
	}
	// Et personne d'autre : un proxy ou un Nexus n'ouvre aucune session PAM.
	for _, autre := range []string{clienttype.Proxy, clienttype.Nexus} {
		if clienttype.MayEmit(autre, "03_11") {
			t.Errorf("%s ne doit pas pouvoir émettre 03_11", autre)
		}
	}
}
