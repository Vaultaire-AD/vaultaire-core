package miseajour

import "testing"

// Les chaînes de la 09_07, jumelles de vaultaire_client/confsys
// (TestEtatsJumeaux) : un état renommé d'un seul côté serait refusé ici.
func TestEtatsDeConfigurationJumeaux(t *testing.T) {
	for c, attendu := range map[string]string{
		ConfConforme: "conforme", ConfReconciliee: "reconciliee", ConfEcart: "ecart",
		ConfDesactivee: "desactivee", ConfNonPrisEnCharge: "non_pris_en_charge",
	} {
		if c != attendu || !ConfValide(c) {
			t.Errorf("%q", c)
		}
	}
}

func TestLireCompteRenduConf(t *testing.T) {
	c, err := LireCompteRenduConf("ecart\nrefusé : ssh/sshd_config : sshd -t refuse")
	if err != nil || c.Etat != ConfEcart || c.Motif != "refusé : ssh/sshd_config : sshd -t refuse" {
		t.Fatalf("%+v %v", c, err)
	}
	if c, err := LireCompteRenduConf("conforme"); err != nil || c.Motif != "" {
		t.Errorf("%+v %v", c, err)
	}
	for _, mauvais := range []string{"", "ok\nx", "installe\nx"} {
		if _, err := LireCompteRenduConf(mauvais); err == nil {
			t.Errorf("%q accepté", mauvais)
		}
	}
}
