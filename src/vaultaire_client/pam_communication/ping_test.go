package pamcommunication

import (
	"os"
	"testing"

	"vaultaire_client/miseajour"
	"vaultaire_client/version"
)

// La sonde de la porte de santé (TO-DO 116), de bout en bout : la sonde de
// l'updater contre le vrai serveur du socket — contrôle de l'appelant,
// décodage, routage.
func TestPingDeBoutEnBout(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("le socket ne répond qu'à root")
	}
	chemin := serveurDeTest(t)

	avant := tunnelEtabli
	t.Cleanup(func() { tunnelEtabli = avant })

	for _, tunnel := range []bool{true, false} {
		tunnelEtabli = func() bool { return tunnel }
		p, err := miseajour.SondeSocket(chemin)()
		if err != nil {
			t.Fatalf("sonde : %v", err)
		}
		if p.Tunnel != tunnel || p.Version != version.Version {
			t.Errorf("tunnel=%v : %+v", tunnel, p)
		}
	}
}
