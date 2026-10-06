package hosthandler

import (
	"strings"
	"testing"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// Ce que le core répond au compte rendu d'un proxy (TO-DO 141).
//
// C'est cette décision qui fait rouvrir ses ports à un proxy : elle doit être
// juste dans tous les cas, et surtout ne jamais boucler.
func TestLaDecisionPourLeProxy(t *testing.T) {
	cr := func(revision int, origine string, refusee int) clusterstorage.CompteRenduRelais {
		return clusterstorage.CompteRenduRelais{Revision: revision, Origine: origine, RevisionRefusee: refusee}
	}
	cas := []struct {
		nom      string
		revision int
		rapport  clusterstorage.CompteRenduRelais
		attendu  string
	}{
		{"non piloté, sur son fichier", 0, cr(0, clusterstorage.OrigineFichier, 0), ModeRelaisInchange},
		{"le core vient de rendre la main", 0, cr(3, clusterstorage.OrigineCore, 0), ModeRelaisFichier},
		{"première prise en main", 1, cr(0, clusterstorage.OrigineFichier, 0), ModeRelaisCore},
		{"révision appliquée", 4, cr(4, clusterstorage.OrigineCore, 0), ModeRelaisInchange},
		{"révision en retard", 5, cr(4, clusterstorage.OrigineCore, 0), ModeRelaisCore},
		// Le cas qui ne doit PAS boucler : la liste a été refusée en entier,
		// ou le proxy garde la main. La renvoyer chaque minute ne changerait
		// pas sa réponse.
		{"révision refusée en entier", 5, cr(4, clusterstorage.OrigineCore, 5), ModeRelaisInchange},
		{"proxy qui garde la main", 2, cr(0, clusterstorage.OrigineFichier, 2), ModeRelaisInchange},
		// Mais une révision NOUVELLE repart, même après un refus de l'ancienne.
		{"nouvelle révision après un refus", 6, cr(4, clusterstorage.OrigineCore, 5), ModeRelaisCore},
		// Même numéro, mais c'est son fichier qu'il applique : la base du core
		// a été restaurée, ou le proxy réinstallé.
		{"même numéro, origine fichier", 3, cr(3, clusterstorage.OrigineFichier, 0), ModeRelaisCore},
	}
	for _, c := range cas {
		if got := DecisionPourLeProxy(c.revision, c.rapport); got != c.attendu {
			t.Errorf("%s : %q, attendu %q", c.nom, got, c.attendu)
		}
	}
}

// La 04_19 telle que le proxy la lit : mode, révision, document — et rien
// d'autre que le mode quand il n'y a rien à appliquer.
func TestLa0419EstLisibleParLeProxy(t *testing.T) {
	demande := []clusterstorage.RelaisConfig{{Nom: "ducky", Type: "ducky", Ecoute: ":6666",
		Cibles: clusterstorage.CiblesRelais{Source: "cores"}}}

	lignes := strings.Split(composerLa0419("serveur_central", "CLE", ModeRelaisCore, 7, demande), "\n")
	if len(lignes) != 6 || lignes[0] != "04_19" || lignes[2] != "CLE" || lignes[3] != "core" || lignes[4] != "7" {
		t.Fatalf("04_19 en mode core : %q", lignes)
	}
	if !strings.HasPrefix(lignes[5], `{"relais":[{"nom":"ducky"`) {
		t.Fatalf("document de la 04_19 : %s", lignes[5])
	}

	for _, mode := range []string{ModeRelaisInchange, ModeRelaisFichier} {
		lignes := strings.Split(composerLa0419("", "CLE", mode, 7, demande), "\n")
		if len(lignes) != 5 || lignes[3] != mode {
			t.Errorf("04_19 en mode %s : %q — elle ne doit porter aucune liste", mode, lignes)
		}
	}
}
