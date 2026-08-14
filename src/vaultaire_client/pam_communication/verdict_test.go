package pamcommunication

import (
	"strings"
	"testing"

	"vaultaire_client/pamstate"
)

// Le verdict d'authentification.
//
// # Ce que ces tests gardent
//
// Une seule chose, et elle vaut tout le reste du fichier : QU'AUCUNE ENTRÉE
// AUTRE QU'UNE ACCEPTATION EXPLICITE NE PRODUISE UNE ACCEPTATION.
//
// Le défaut qui a motivé ces tests laissait entrer n'importe quel mot de passe.
// Le serveur refusait, l'agent traduisait ce refus en « success », et sshd
// ouvrait la session — `/etc/shadow` étant au passage réécrit avec le mot de
// passe essayé.

// TestUnCanalFermeEstUnRefus.
//
// LE test. C'est le chemin exact qui a ouvert la porte.
//
// Le refus du serveur (03_03) fermait le canal. Le lecteur faisait
// `result := <-finalChan` sans le second retour, recevait le zéro du type, et
// son test « Type ni vide ni AUTH » laissait passer la chaîne vide dans la
// branche du succès.
func TestUnCanalFermeEstUnRefus(t *testing.T) {
	// Exactement ce que rend `<-ch` sur un canal fermé : le zéro, et recu=false.
	motif := VerdictRefuse(pamstate.AuthResult{}, false)

	if motif == "" {
		t.Fatal("un canal fermé a été traité comme une AUTHENTIFICATION RÉUSSIE — " +
			"c'est le défaut par lequel n'importe quel mot de passe ouvrait une session")
	}
	if !strings.Contains(motif, "fermé") {
		t.Errorf("motif %q : il doit nommer le canal fermé, sans quoi le journal "+
			"ne distingue pas ce cas d'un refus du serveur", motif)
	}
}

// TestLeZeroDuTypeEstUnRefus.
//
// Même chose, mais avec recu=true : un message VIDE effectivement reçu. Le zéro
// de la structure doit valoir « refusé », quelle que soit la façon dont il
// arrive.
func TestLeZeroDuTypeEstUnRefus(t *testing.T) {
	if VerdictRefuse(pamstate.AuthResult{}, true) == "" {
		t.Fatal("le zéro de AuthResult a été accepté : tout chemin qui oublierait " +
			"de remplir le résultat ouvrirait une session")
	}
}

// TestUnRefusExpliciteEstUnRefus : la trame 03_03 telle qu'elle est émise.
func TestUnRefusExpliciteEstUnRefus(t *testing.T) {
	refus := pamstate.AuthResult{Type: "AUTH", Accepte: false}

	motif := VerdictRefuse(refus, true)
	if motif == "" {
		t.Fatal("un refus explicite du serveur a été accepté")
	}
	if !strings.Contains(motif, "refusé") {
		t.Errorf("motif %q : il doit dire que le serveur a refusé", motif)
	}
}

// TestUneAcceptationExpliciteEstAcceptee.
//
// L'autre moitié, et elle compte autant : un verdict trop strict couperait le
// parc, et le réflexe devant un parc coupé est de désactiver le contrôle.
func TestUneAcceptationExpliciteEstAcceptee(t *testing.T) {
	ok := pamstate.AuthResult{Type: "AUTH", Accepte: true, IsAdmin: true, SSHKeys: "ssh-rsa AAAA"}

	if motif := VerdictRefuse(ok, true); motif != "" {
		t.Fatalf("une authentification légitime a été refusée : %s", motif)
	}
}

// TestUnAccepteSansTypeEstRefuse.
//
// `Accepte` seul ne suffit pas. Une réponse acceptée mais de type inattendu
// signale une confusion de canaux — une réponse FETCH arrivée sur le chemin
// d'authentification — et non une authentification réussie.
func TestUnAccepteSansTypeEstRefuse(t *testing.T) {
	cas := map[string]pamstate.AuthResult{
		"type vide":  {Accepte: true},
		"type FETCH": {Type: "FETCH", Accepte: true, SSHKeys: "ssh-rsa AAAA"},
		"type CHECK": {Type: "CHECK", Accepte: true},
	}
	for nom, r := range cas {
		t.Run(nom, func(t *testing.T) {
			if VerdictRefuse(r, true) == "" {
				t.Errorf("%s accepté sur le chemin d'authentification", nom)
			}
		})
	}
}

// TestSeuleUneCombinaisonEstAcceptee.
//
// Le balayage exhaustif des quatre entrées. C'est la garantie qu'aucune
// combinaison ne passe par un chemin qu'on n'aurait pas nommé plus haut.
func TestSeuleUneCombinaisonEstAcceptee(t *testing.T) {
	types := []string{"", "AUTH", "FETCH", "CHECK", "n'importe quoi"}
	acceptees := 0

	for _, recu := range []bool{true, false} {
		for _, accepte := range []bool{true, false} {
			for _, typ := range types {
				r := pamstate.AuthResult{Type: typ, Accepte: accepte}
				if VerdictRefuse(r, recu) != "" {
					continue
				}
				acceptees++
				if !recu || !accepte || typ != "AUTH" {
					t.Errorf("accepté à tort : recu=%v accepte=%v type=%q",
						recu, accepte, typ)
				}
			}
		}
	}

	if acceptees != 1 {
		t.Errorf("%d combinaison(s) acceptée(s) sur %d, attendu exactement 1",
			acceptees, 2*2*len(types))
	}
}
