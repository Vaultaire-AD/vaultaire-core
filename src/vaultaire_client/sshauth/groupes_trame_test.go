package sshauth

import (
	"strings"
	"testing"
)

// La ligne des groupes dans la réponse 03_02.
//
// Ce que ces tests gardent : qu'une ligne de groupes ne soit jamais prise pour
// une clé publique, et qu'une clé publique ne soit jamais prise pour une ligne
// de groupes. Les deux confusions sont silencieuses — sshd ignore une entrée
// malformée sans rien dire, et une clé lue comme une liste de groupes disparaît
// simplement d'authorized_keys.

func TestLaLigneDesGroupesEstLueEtRetiree(t *testing.T) {
	groupes, reste := extraireGroupes([]string{
		"groups:devs,prod",
		"ssh-rsa AAAA premiere",
		"ssh-ed25519 BBBB seconde",
	})

	if len(groupes) != 2 || groupes[0] != "devs" || groupes[1] != "prod" {
		t.Errorf("groupes = %v, attendu [devs prod]", groupes)
	}
	if len(reste) != 2 {
		t.Fatalf("%d ligne(s) de clés, attendu 2 : %v", len(reste), reste)
	}
	for _, l := range reste {
		if strings.HasPrefix(l, PrefixeGroupes) {
			t.Errorf("la ligne des groupes est restée dans les clés : %q — elle "+
				"serait écrite dans authorized_keys", l)
		}
	}
}

// TestUnServeurSansGroupesResteCompatible.
//
// L'agent doit fonctionner en face d'un serveur qui n'envoie pas la ligne : ses
// clés ne doivent pas être amputées de la première.
func TestUnServeurSansGroupesResteCompatible(t *testing.T) {
	cles := []string{"ssh-rsa AAAA premiere", "ssh-ed25519 BBBB seconde"}

	groupes, reste := extraireGroupes(cles)

	if len(groupes) != 0 {
		t.Errorf("groupes = %v, attendu aucun", groupes)
	}
	if len(reste) != 2 || reste[0] != cles[0] {
		t.Errorf("clés = %v, attendu %v : une clé a été lue comme une liste de "+
			"groupes", reste, cles)
	}
}

// TestUneListeVideNEstPasUnGroupe : « groups: » sans rien derrière veut dire
// « aucun groupe », pas « un groupe dont le nom est vide ».
func TestUneListeVideNEstPasUnGroupe(t *testing.T) {
	groupes, reste := extraireGroupes([]string{"groups:", "ssh-rsa AAAA"})

	if len(groupes) != 0 {
		t.Errorf("groupes = %v, attendu aucun", groupes)
	}
	if len(reste) != 1 {
		t.Errorf("clés = %v, attendu une seule", reste)
	}
}

// TestUnContenuSansCle : un compte sans clé publique reste lisible — la trame
// n'a alors que les groupes.
func TestUnContenuSansCle(t *testing.T) {
	groupes, reste := extraireGroupes([]string{"groups:devs"})

	if len(groupes) != 1 || groupes[0] != "devs" {
		t.Errorf("groupes = %v, attendu [devs]", groupes)
	}
	if len(reste) != 0 {
		t.Errorf("clés = %v, attendu aucune", reste)
	}
}

// TestLesEspacesAutourDesNomsSontOtes : une liste écrite « devs, prod » ne doit
// pas produire un groupe nommé « prod » avec une espace devant, qui n'existerait
// sur aucune machine.
func TestLesEspacesAutourDesNomsSontOtes(t *testing.T) {
	groupes, _ := extraireGroupes([]string{"groups: devs , prod ,"})

	if len(groupes) != 2 || groupes[0] != "devs" || groupes[1] != "prod" {
		t.Errorf("groupes = %v, attendu [devs prod]", groupes)
	}
}

// TestLePrefixeEstCeluiDuServeur.
//
// Le garde-fou de la valeur elle-même. La constante est déclarée des DEUX côtés
// — l'agent et le serveur sont des modules Go distincts, et rien ne peut les
// tenir liées à la compilation. Ce test fige la chaîne : la changer d'un côté
// fait échouer ici, au lieu de faire prendre la ligne pour une clé publique en
// production.
//
// Le pendant côté serveur est dans ssh_client_test.go.
func TestLePrefixeEstCeluiDuServeur(t *testing.T) {
	if PrefixeGroupes != "groups:" {
		t.Errorf("PrefixeGroupes = %q : la valeur doit rester identique à celle du "+
			"serveur (ducky-network/authentification/ssh)", PrefixeGroupes)
	}
	if PrefixeCadence != "sync:" {
		t.Errorf("PrefixeCadence = %q : la valeur doit rester identique à celle du "+
			"serveur (ducky-network/authentification/ssh)", PrefixeCadence)
	}
}

// TestLesDeuxPrefixesNeSeConfondentPas.
//
// Si l'un ouvrait l'autre, la ligne de cadence serait lue comme un groupe nommé
// « sync » — écarté par la validation, donc sans dégât visible, mais la cadence
// resterait celle du repli sans que rien ne le dise.
func TestLesDeuxPrefixesNeSeConfondentPas(t *testing.T) {
	if strings.HasPrefix(PrefixeCadence, PrefixeGroupes) ||
		strings.HasPrefix(PrefixeGroupes, PrefixeCadence) {
		t.Errorf("les préfixes %q et %q se recouvrent", PrefixeGroupes, PrefixeCadence)
	}
}
