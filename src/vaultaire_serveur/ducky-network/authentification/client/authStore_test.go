package client

import (
	"reflect"
	"testing"
	"time"

	"vaultaire/core/storage"
)

// Les défis d'authentification en attente.
//
// # Ce que ces tests gardent
//
// Une entrée n'était retirée qu'à la consommation du défi — la trame 02_03. Une
// authentification abandonnée entre 02_02 et 02_03 laissait donc la sienne pour
// toute la durée de vie du processus.
//
// Le nettoyage de fermeture de session ne rattrapait rien : il passait le
// ClientSoftwareID à une fonction qui attend un AuthID. Un commentaire le
// signalait, puis gardait le comportement « pour ne pas le changer ».
//
// Et l'entrée portait le mot de passe EN CLAIR. Un poste qui coupait sa
// connexion au bon moment laissait donc un mot de passe en mémoire, sans limite
// de nombre ni de durée. Un vidage mémoire du core les livrait tous.

func horlogeFigee(t *testing.T) func(time.Duration) {
	t.Helper()
	base := time.Now()
	decalage := time.Duration(0)
	maintenant = func() time.Time { return base.Add(decalage) }
	t.Cleanup(func() { maintenant = time.Now })
	return func(d time.Duration) { decalage += d }
}

func viderStore(t *testing.T) {
	t.Helper()
	authStore.mu.Lock()
	authStore.m = map[string]defiEnAttente{}
	authStore.mu.Unlock()
}

// TestLeDefiNePorteAucunMotDePasse.
//
// LE test de ce fichier. Le champ existait, personne ne le lisait, et il
// suffisait d'une authentification abandonnée pour qu'un mot de passe reste en
// mémoire indéfiniment.
//
// La vérification porte sur le TYPE et non sur une valeur : un champ réintroduit
// plus tard, même laissé vide au début, rouvrirait la porte sans qu'un test de
// valeur s'en aperçoive.
func TestLeDefiNePorteAucunMotDePasse(t *testing.T) {
	typ := reflect.TypeOf(storage.Authentification{})

	for _, interdit := range []string{"Password", "MotDePasse", "Secret", "Pass"} {
		if _, existe := typ.FieldByName(interdit); existe {
			t.Errorf("storage.Authentification porte un champ %q : le serveur garderait "+
				"un secret en mémoire pour chaque authentification en attente, sans usage",
				interdit)
		}
	}
}

// TestDefiConsommeUneSeuleFois : le rejouer ne doit rien rendre.
func TestDefiConsommeUneSeuleFois(t *testing.T) {
	viderStore(t)
	horlogeFigee(t)

	storeAuth(storage.Authentification{
		RandomAuth: []byte("jeton"), AuthID: "A1",
		Username: "alice", ClientSoftwareID: "PC-01",
	})

	jeton, nom := GetRandomAuthByAuthID("A1")
	if string(jeton) != "jeton" || nom != "alice" {
		t.Fatalf("premier appel : jeton=%q nom=%q", jeton, nom)
	}

	jeton, nom = GetRandomAuthByAuthID("A1")
	if jeton != nil || nom != "" {
		t.Errorf("second appel : jeton=%q nom=%q, attendu vide — un défi doit servir une fois", jeton, nom)
	}
}

// TestDefiAbandonneExpire.
//
// Sans échéance, un défi émis puis jamais consommé reste jusqu'à l'arrêt du
// processus. Une machine qui ouvre des authentifications sans les terminer
// ferait croître la carte sans limite.
func TestDefiAbandonneExpire(t *testing.T) {
	viderStore(t)
	horloge := horlogeFigee(t)

	storeAuth(storage.Authentification{
		RandomAuth: []byte("jeton"), AuthID: "A1",
		Username: "alice", ClientSoftwareID: "PC-01",
	})
	if DefisEnAttente() != 1 {
		t.Fatalf("%d défi(s) après dépôt, attendu 1", DefisEnAttente())
	}

	horloge(DureeDeVieDefi + time.Second)

	if jeton, _ := GetRandomAuthByAuthID("A1"); jeton != nil {
		t.Error("un défi expiré est encore accepté")
	}
	if n := DefisEnAttente(); n != 0 {
		t.Errorf("%d défi(s) restant(s) après expiration, attendu 0", n)
	}
}

// TestDefiValideAvantEcheance : l'échéance ne doit pas être trop courte.
//
// Un défi retiré avant que le poste ait pu répondre ferait échouer des
// authentifications légitimes, et le message ne dirait pas pourquoi.
func TestDefiValideAvantEcheance(t *testing.T) {
	viderStore(t)
	horloge := horlogeFigee(t)

	storeAuth(storage.Authentification{
		RandomAuth: []byte("jeton"), AuthID: "A1",
		Username: "alice", ClientSoftwareID: "PC-01",
	})
	horloge(DureeDeVieDefi - time.Second)

	if jeton, _ := GetRandomAuthByAuthID("A1"); jeton == nil {
		t.Error("défi refusé avant son échéance : des connexions légitimes échoueraient")
	}
}

// TestFermetureDeSessionRetireLesDefisDeLaMachine.
//
// C'est ce que la fermeture voulait faire et ne faisait pas : elle passait le
// ClientSoftwareID à une fonction indexée par AuthID, donc ne trouvait jamais
// rien.
func TestFermetureDeSessionRetireLesDefisDeLaMachine(t *testing.T) {
	viderStore(t)
	horlogeFigee(t)

	storeAuth(storage.Authentification{AuthID: "A1", Username: "alice", ClientSoftwareID: "PC-01"})
	storeAuth(storage.Authentification{AuthID: "A2", Username: "bob", ClientSoftwareID: "PC-01"})
	storeAuth(storage.Authentification{AuthID: "A3", Username: "carol", ClientSoftwareID: "PC-02"})

	SupprimerDefisDuClient("PC-01")

	if n := DefisEnAttente(); n != 1 {
		t.Fatalf("%d défi(s) restant(s), attendu 1 — seuls ceux de PC-01 devaient partir", n)
	}
	if _, nom := GetRandomAuthByAuthID("A3"); nom != "carol" {
		t.Error("le défi d'une AUTRE machine a été emporté")
	}
}

// TestSuppressionParIdentifiantVideNeVidePasTout.
//
// Un ClientSoftwareID vide — trame malformée, session sans identité — ne doit
// pas correspondre à toutes les entrées et les effacer d'un coup.
func TestSuppressionParIdentifiantVideNeVidePasTout(t *testing.T) {
	viderStore(t)
	horlogeFigee(t)

	storeAuth(storage.Authentification{AuthID: "A1", Username: "alice", ClientSoftwareID: "PC-01"})
	SupprimerDefisDuClient("")

	if n := DefisEnAttente(); n != 1 {
		t.Errorf("%d défi(s) après suppression avec un identifiant vide, attendu 1", n)
	}
}

// TestLeDepotPurgeLesExpires.
//
// La purge est amortie sur les accès plutôt que périodique. Elle doit donc se
// déclencher au dépôt aussi, sans quoi une machine qui n'authentifie plus
// personne laisserait ses défis en place sans que rien ne les relise.
func TestLeDepotPurgeLesExpires(t *testing.T) {
	viderStore(t)
	horloge := horlogeFigee(t)

	storeAuth(storage.Authentification{AuthID: "vieux", Username: "alice", ClientSoftwareID: "PC-01"})
	horloge(DureeDeVieDefi + time.Second)
	storeAuth(storage.Authentification{AuthID: "neuf", Username: "bob", ClientSoftwareID: "PC-02"})

	if n := DefisEnAttente(); n != 1 {
		t.Errorf("%d défi(s), attendu 1 — le dépôt n'a pas purgé l'expiré", n)
	}
}
