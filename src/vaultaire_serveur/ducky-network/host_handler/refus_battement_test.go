package hosthandler

import (
	"strings"
	"testing"

	"vaultaire/core/storage"
)

// TestLeRefusDeBattementEstUneTrameLisible (TO-DO 109).
//
// Le nœud lit le 04_08 ligne par ligne : « refus » en première ligne de
// contenu, le motif en seconde. Un motif multiligne décalerait la lecture, et
// un refus sans motif laisserait le journal du nœud sans rien à corriger.
func TestLeRefusDeBattementEstUneTrameLisible(t *testing.T) {
	requete := storage.Trames_struct_client{Destination_Server: "serveur_central", SessionIntegritykey: "CLE"}

	lignes := strings.Split(RefusBattement(requete, "ligne un\nligne deux\r"), "\n")
	if len(lignes) != 5 {
		t.Fatalf("attendu cinq lignes (code, destination, clé, refus, motif), reçu %d : %q", len(lignes), lignes)
	}
	if lignes[0] != "04_08" || lignes[2] != "CLE" || lignes[3] != "refus" {
		t.Fatalf("en-tête ou statut inattendu : %q", lignes)
	}
	if strings.ContainsAny(lignes[4], "\r\n") || !strings.Contains(lignes[4], "ligne un") || !strings.Contains(lignes[4], "ligne deux") {
		t.Fatalf("motif mal ramené sur une ligne : %q", lignes[4])
	}

	if sansMotif := strings.Split(RefusBattement(requete, "  "), "\n"); sansMotif[4] != MotifBattementInconnu {
		t.Fatalf("un refus sans motif doit porter le motif par défaut, reçu %q", sansMotif[4])
	}
}
