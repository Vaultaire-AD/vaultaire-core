package pamcommunication

import (
	"encoding/json"
	"strings"
	"testing"
)

// TO-DO 171 : deux motifs de refus sont présentés à la personne, et eux seuls.

func TestUnMotDePasseExpireEstDit(t *testing.T) {
	m := MessageDeRefus("password expired")
	if !strings.Contains(m, "expiré") || !strings.Contains(m, "portail") {
		t.Errorf("message = %q : doit dire « expiré » et où le changer", m)
	}
}

func TestUnSecondFacteurManquantEstDit(t *testing.T) {
	m := MessageDeRefus("mfa required")
	if !strings.Contains(m, "code") || !strings.Contains(m, "0000 ne suffit pas") {
		t.Errorf("message = %q : doit dire qu'un vrai code est demandé", m)
	}
}

// Le silence est la règle : un refus qui dirait quelque chose avant que le mot
// de passe soit prouvé renseignerait qui essaie des mots de passe.
func TestToutAutreRefusResteMuet(t *testing.T) {
	for _, motif := range []string{
		"permission denied",  // mot de passe faux, compte inconnu, machine interdite
		"mfa unavailable",    // panne du core : rien à faire pour la personne
		"verification error", // idem
		"invalid request",
		"",
		"Password Expired",           // la casse compte : comparaison EXACTE
		" password expired",          // les espaces aussi
		"password expired; rm -rf /", // jamais recopié du core
		"Password expired, change it on the web interface", // le motif 02_07, pas 03_03
	} {
		if m := MessageDeRefus(motif); m != "" {
			t.Errorf("motif %q : message %q, attendu le silence", motif, m)
		}
	}
}

// Le texte affiché est celui de l'agent, jamais celui du core.
func TestLeTexteNeReprendPasLeMotif(t *testing.T) {
	for motif, texte := range motifsAffichables {
		if strings.Contains(texte, motif) {
			t.Errorf("le texte de %q reprend le motif brut : %q", motif, texte)
		}
	}
	if len(motifsAffichables) != 2 {
		t.Errorf("%d motifs affichables, attendu 2 : la liste s'élargit-elle sans revue ?", len(motifsAffichables))
	}
}

func TestLeChampRefusEstOmisQuandIlEstVide(t *testing.T) {
	ordinaire, _ := json.Marshal(Response{Status: "failed", SSHKeys: []string{}})
	if strings.Contains(string(ordinaire), "refus") {
		t.Errorf("un refus muet porte le champ : %s", ordinaire)
	}
	dit, _ := json.Marshal(Response{Status: "failed", Refus: MessageDeRefus("password expired"), SSHKeys: []string{}})
	s := string(dit)
	if i, j := strings.Index(s, `"refus"`), strings.Index(s, `"ssh_keys"`); i < 0 || i > j {
		t.Errorf("« refus » absent ou après les clés (tampon de 4 Kio du module) : %s", s)
	}
}
