package gpo

import (
	"strings"
	"testing"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// TO-DO 167 : l'agent Windows répond « non pris en charge » au lieu de se
// taire, pour que le core cesse de lui remettre ses ordres.
func TestLaRevocationRepondNonPriseEnCharge(t *testing.T) {
	storage.Computeur_ID = "poste-win-01"
	cas := []struct {
		sous, contenu string
		ordre         string
	}{
		{"01", "42\nsoft\nalice@acme.lan\ncompromission", "42"},
		{"05", "2\n17|soft|alice@acme.lan|depart\n18|unlock|alice@acme.lan|retour", "17"},
	}
	for _, c := range cas {
		rep := HandleTrameRevocation(storage.Trames_struct_client{
			Message_Order: []string{"06", c.sous}, SessionIntegritykey: "cle", Content: c.contenu,
		}, nil)
		lignes := strings.Split(rep, "\n")
		attendu := []string{"06_03", "serveur_central", "cle", "vaultaire", "poste-win-01", c.ordre, "unsupported"}
		if len(lignes) != 8 || strings.Join(lignes[:7], "|") != strings.Join(attendu, "|") || lignes[7] == "" {
			t.Errorf("06_%s : réponse %q, attendu %v + motif", c.sous, lignes, attendu)
		}
		// Jamais un acquittement : un ordre acquitté se lit comme un compte coupé.
		if strings.HasPrefix(rep, "06_02") {
			t.Errorf("06_%s : l'agent ACQUITTE un ordre qu'il n'applique pas", c.sous)
		}
	}
	// Rien à répondre : liste vide, erreur du serveur, contenu illisible.
	for _, c := range [][2]string{{"05", "0"}, {"06", "lecture impossible\nbase"}, {"01", "x"}} {
		if rep := HandleTrameRevocation(storage.Trames_struct_client{
			Message_Order: []string{"06", c[0]}, Content: c[1]}, nil); rep != "" {
			t.Errorf("06_%s %q : réponse inattendue %q", c[0], c[1], rep)
		}
	}
}

func TestUnOrdreDeMiseAJourEstDitNonPrisEnCharge(t *testing.T) {
	storage.Computeur_ID = "poste-w"
	rep := HandleTrameMiseAJour(storage.Trames_struct_client{Message_Order: []string{"09", "06"},
		SessionIntegritykey: "CLE", Content: "2.4.0\nreleases\nnon"}, nil)
	if rep != "09_04\nserveur_central\nCLE\nvaultaire\nposte-w\n2.4.0\nnon_pris_en_charge\n"+
		"agent Windows : mise à jour non écrite (TO-DO 118)" {
		t.Errorf("%q", rep)
	}
	for _, s := range []string{"03", "05"} {
		if rep := HandleTrameMiseAJour(storage.Trames_struct_client{Message_Order: []string{"09", s}}, nil); rep != "" {
			t.Errorf("09_%s : %q", s, rep)
		}
	}
}
