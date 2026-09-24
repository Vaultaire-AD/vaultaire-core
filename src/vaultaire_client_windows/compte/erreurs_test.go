package compte

import (
	"strings"
	"testing"
)

// Le message d'un refus est la seule chose qui sépare une session de recette
// d'une lecture de journal. « NetUserAdd : code 2245 (paramètre 4294967295) »
// est exact et inutilisable : il faut connaître netapi32 pour le lire, et le
// second nombre ne veut rien dire.

func TestLeRefusDeMotDePasseDesigneLaPolitiqueDuPoste(t *testing.T) {
	err := ErreurNetapi("NetUserAdd", ErrMotDePasseRefuse, ParametreInconnu)
	if err == nil {
		t.Fatal("aucune erreur pour un code non nul")
	}
	msg := err.Error()

	// Qui refuse : le POSTE, pas Vaultaire. C'est la première chose à
	// comprendre, et celle que le code nu ne disait pas.
	for _, attendu := range []string{"politique de mot de passe", "POSTE"} {
		if !strings.Contains(msg, attendu) {
			t.Errorf("le message ne dit pas %q : %s", attendu, msg)
		}
	}

	// Les trois causes possibles, parce que le nom du code (« TooShort ») en
	// désigne une seule et que ce n'est pas toujours la bonne.
	for _, cause := range []string{"longueur", "complexité", "historique"} {
		if !strings.Contains(msg, cause) {
			t.Errorf("le message ne mentionne pas la cause possible %q : %s", cause, msg)
		}
	}

	// Quoi faire.
	if !strings.Contains(msg, "net accounts") || !strings.Contains(msg, "install.ps1") {
		t.Errorf("le message n'indique pas quoi faire : %s", msg)
	}
}

// Le paramètre fautif ne doit apparaître QUE s'il veut dire quelque chose.
// 4294967295 est PARM_ERROR_UNKNOWN : un nombre qui ressemble à une
// information et n'en est pas.
func TestLeParametreInconnuNEstPasAffiche(t *testing.T) {
	msg := ErreurNetapi("NetUserAdd", 99999, ParametreInconnu).Error()
	if strings.Contains(msg, "4294967295") || strings.Contains(msg, "champ") {
		t.Errorf("le paramètre inconnu est affiché : %s", msg)
	}

	// Un vrai indice, lui, est conservé.
	msg = ErreurNetapi("NetUserAdd", ErrParametreInvalide, 3).Error()
	if !strings.Contains(msg, "champ 3") {
		t.Errorf("le champ fautif a disparu : %s", msg)
	}
}

// Un accès refusé n'est pas un problème de mot de passe : c'est l'agent qui ne
// tourne pas sous le bon compte. Confondre les deux ferait perdre du temps sur
// une politique qui n'y est pour rien.
func TestUnAccesRefuseOrienteVersLeCompteDuService(t *testing.T) {
	msg := ErreurNetapi("NetUserAdd", ErrAccesRefuse, ParametreInconnu).Error()
	if !strings.Contains(msg, "SYSTEM") {
		t.Errorf("le message n'oriente pas vers le compte du service : %s", msg)
	}
	if strings.Contains(msg, "politique de mot de passe") {
		t.Errorf("un accès refusé est présenté comme un refus de mot de passe : %s", msg)
	}
}

// Un code sans traduction dédiée doit quand même produire un message exploitable
// — et surtout ne pas rendre nil, qui ferait passer un échec pour un succès.
func TestUnCodeInconnuResteUneErreur(t *testing.T) {
	if err := ErreurNetapi("NetUserAdd", 1234, ParametreInconnu); err == nil {
		t.Fatal("un code inconnu ne rend aucune erreur")
	} else if !strings.Contains(err.Error(), "1234") {
		t.Errorf("le code brut a disparu : %s", err.Error())
	}
}

// Zéro vaut succès : c'est la convention de netapi32, et la traduire en erreur
// ferait échouer tous les provisionnements réussis.
func TestZeroNEstPasUneErreur(t *testing.T) {
	if err := ErreurNetapi("NetUserAdd", 0, 0); err != nil {
		t.Errorf("le succès est traduit en erreur : %v", err)
	}
}
