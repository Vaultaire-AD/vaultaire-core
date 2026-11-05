package pamcommunication

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TO-DO 199 : la ligne du journal de debug des connexions, et ce que le module
// PAM lit de la réponse.

func TestLaLigneChronoDitChaqueEtape(t *testing.T) {
	l := ligneChrono("AUTH", "alice@dom", "success",
		412*time.Millisecond, 38*time.Millisecond, 640*time.Millisecond, true, true, 1102*time.Millisecond)
	attendu := "ouverture alice@dom [AUTH] success : core 412 ms (dont provisionnement 38 ms), GPO 640 ms, total agent 1102 ms"
	if l != attendu {
		t.Errorf("ligne = %q\nattendu %q", l, attendu)
	}
	l = ligneChrono("AUTH", "alice@dom", "success", 0, 0, 5*time.Second, true, false, 5100*time.Millisecond)
	if !strings.Contains(l, "GPO 5000 ms (plafond atteint, cycle poursuivi)") {
		t.Errorf("le plafond n'est pas dit : %q", l)
	}
	l = ligneChrono("CHECK", "bob@dom", "failed", 30*time.Millisecond, 0, 0, false, true, 31*time.Millisecond)
	if !strings.Contains(l, "GPO non jouees") {
		t.Errorf("un refus ne joue pas les GPO : %q", l)
	}
}

// Le module lit la réponse dans un tampon de 4 Kio : ce qu'il lit doit passer
// AVANT les clés, qui peuvent le remplir.
func TestLeModuleLitCeQuIlFautAvantLesCles(t *testing.T) {
	brut, _ := json.Marshal(Response{Status: "success", Chrono: true, Notice: "bonjour",
		IsAdmin: true, SSHKeys: []string{strings.Repeat("A", 5000)}})
	s := string(brut)
	cles := strings.Index(s, `"ssh_keys"`)
	for _, champ := range []string{`"status"`, `"chrono":true`, `"notice"`} {
		if i := strings.Index(s, champ); i < 0 || i > cles {
			t.Errorf("%s après les clés (ou absent) : %.120s…", champ, s)
		}
	}
	if ordinaire, _ := json.Marshal(Response{Status: "success", SSHKeys: []string{}}); strings.Contains(string(ordinaire), "chrono") {
		t.Errorf("hors debug, la réponse porte « chrono » : %s", ordinaire)
	}
}
