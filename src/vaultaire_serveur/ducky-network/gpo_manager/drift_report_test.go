package gpomanager

import (
	"strings"
	"testing"
)

// buildDriftFrameLikeAgent reproduit EXACTEMENT ce que
// src/vaultaire_client/gpo.SendDriftReport écrit dans le contenu de 05_15.
//
// Le duplicat est délibéré : les deux modules ne se compilent pas ensemble, et
// une constante partagée n'existerait de toute façon pas au-dessus de la
// frontière réseau. Ce que ce test protège, c'est l'accord de format — si
// quelqu'un change l'ordre des champs d'un seul côté, le test tombe.
func buildDriftFrameLikeAgent(scope, username, checked string, items ...string) []string {
	return append([]string{scope, username, checked, itoa(len(items))}, items...)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestParseDriftLinesAccordAvecLAgent : l'ordre des champs est
// clé|type|chemin|détail, et pas un autre.
//
// L'inverser ne casserait rien à la compilation : les quatre champs sont des
// chaînes. On enregistrerait simplement des chemins dans la colonne « type » —
// une base pleine de données fausses, sans la moindre erreur nulle part.
func TestParseDriftLinesAccordAvecLAgent(t *testing.T) {
	lines := buildDriftFrameLikeAgent("machine", "", "12",
		"sshd_config|modified|/etc/ssh/sshd_config|empreinte differente",
		"sudoers_vaultaire|missing|/etc/sudoers.d/vaultaire|",
		"keyfile|permissions|/etc/vaultaire/key.pem|mode 0644 attendu 0600",
	)

	entries := parseDriftLines(lines, "PC-TEST")
	if len(entries) != 3 {
		t.Fatalf("%d écart(s) lu(s), attendu 3", len(entries))
	}

	if entries[0].StateKey != "sshd_config" || entries[0].Kind != "modified" ||
		entries[0].Path != "/etc/ssh/sshd_config" || entries[0].Detail != "empreinte differente" {
		t.Errorf("champs mal attribués : %+v", entries[0])
	}
	if entries[1].Detail != "" {
		t.Errorf("détail vide attendu, obtenu %q", entries[1].Detail)
	}
	if entries[2].Kind != "permissions" || entries[2].Path != "/etc/vaultaire/key.pem" {
		t.Errorf("écart de droits mal lu : %+v", entries[2])
	}
}

// TestParseDriftLinesIgnoreLInvalide : fail-closed sur la ligne, pas sur le
// rapport. Un type inconnu ne doit ni entrer en base ni faire perdre les autres.
func TestParseDriftLinesIgnoreLInvalide(t *testing.T) {
	lines := buildDriftFrameLikeAgent("machine", "", "9",
		"a|modified|/etc/a|",
		"b|corrompu_par_un_agent_futur|/etc/b|",
		"c|deux_champs_seulement",
		"",
		"   ",
		"d|missing|/etc/d|",
	)

	entries := parseDriftLines(lines, "PC-TEST")
	if len(entries) != 2 {
		t.Fatalf("%d écart(s) retenu(s), attendu 2 (a et d)", len(entries))
	}
	if entries[0].StateKey != "a" || entries[1].StateKey != "d" {
		t.Errorf("écarts retenus %q et %q, attendu a et d", entries[0].StateKey, entries[1].StateKey)
	}
}

// TestParseDriftLinesDetailAvecSeparateur : le détail est le DERNIER champ.
//
// SplitN à 4 et non Split : un séparateur résiduel dans le détail ne doit pas
// décaler les champs suivants, ce qui rangerait un fragment de message dans la
// colonne du chemin.
func TestParseDriftLinesDetailAvecSeparateur(t *testing.T) {
	lines := buildDriftFrameLikeAgent("user", "alice", "3",
		"x|modified|/home/alice/.bashrc|attendu a|b obtenu c",
	)
	entries := parseDriftLines(lines, "PC-TEST")
	if len(entries) != 1 {
		t.Fatalf("%d écart(s), attendu 1", len(entries))
	}
	if entries[0].Path != "/home/alice/.bashrc" {
		t.Errorf("chemin %q, le détail a décalé les champs", entries[0].Path)
	}
	if !strings.Contains(entries[0].Detail, "a|b") {
		t.Errorf("détail %q, le séparateur résiduel a été perdu", entries[0].Detail)
	}
}

// TestParseDriftLinesEnTeteNonLu épingle la frontière en-tête / contenu.
//
// Les quatre premières lignes sont l'en-tête ; le contenu commence à l'index 4.
// La quatrième ligne du montage ci-dessous n'est pas un compteur valide : c'est
// une SONDE, façonnée pour ressembler à un écart parfaitement formé. Si le
// parseur commençait à l'index 3, il la lirait, et le test tombe.
//
// Un compteur ordinaire ne suffirait pas à détecter ce décalage : « 12 » ne
// contient pas de séparateur, serait écarté comme ligne malformée, et le bogue
// passerait — en journalisant un avertissement que personne ne lit.
func TestParseDriftLinesEnTeteNonLu(t *testing.T) {
	sonde := []string{"machine", "", "12", "sonde|modified|/etc/sonde|"}
	if entries := parseDriftLines(sonde, "PC-TEST"); len(entries) != 0 {
		t.Errorf("l'en-tête a été lu comme contenu : %+v", entries)
	}

	// Et le cas réel : un rapport conforme, sans aucun écart.
	conforme := []string{"machine", "", "12", "0"}
	if entries := parseDriftLines(conforme, "PC-TEST"); len(entries) != 0 {
		t.Errorf("%d écart(s) lu(s) dans un rapport conforme : %+v", len(entries), entries)
	}
}
