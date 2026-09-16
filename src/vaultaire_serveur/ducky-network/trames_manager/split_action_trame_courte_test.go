package tramesmanager

import (
	"net"
	"runtime/debug"
	"testing"

	"vaultaire/core/storage"
)

// TestSplitActionTrameCourteNePaniquePas couvre un déni de service NON
// AUTHENTIFIÉ sur le port Ducky.
//
// # Le chemin
//
//  1. « askkey » rend la clé publique du core, SANS authentification
//  2. l'attaquant chiffre avec elle une trame de moins de 5 lignes
//  3. parseTrames refuse la trame et rend une structure VIDE
//  4. Split_Action lit Message_Order[0] sur une tranche nil
//
// Le refus de parseTrames est correct ; ce qui manquait, c'est que l'appelant
// n'en tenait pas compte. Comme la goroutine Ducky n'a pas de recover(), la
// panique arrête le processus entier — LDAP, DNS, web et API compris.
//
// C'est la même classe de défaut que celui trouvé côté LDAP : une donnée réseau
// refusée par une couche, puis utilisée telle quelle par la suivante.
func TestSplitActionTrameCourteNePaniquePas(t *testing.T) {
	client, serveur := net.Pipe()
	defer client.Close()
	defer serveur.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIQUE sur une trame malformée : %v\n%s", r, debug.Stack())
		}
	}()

	session := &storage.DuckySession{Conn: serveur, SessionID: "test"}

	// Ce que rend parseTrames sur une trame de moins de 5 lignes.
	Split_Action(storage.Trames_struct_client{}, session)

	// Un code sans séparateur : Message_Order n'a qu'un élément.
	Split_Action(storage.Trames_struct_client{Message_Order: []string{"01"}}, session)

	// Un code vide.
	Split_Action(storage.Trames_struct_client{Message_Order: []string{""}}, session)
}
