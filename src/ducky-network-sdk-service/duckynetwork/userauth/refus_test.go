package userauth

import (
	"runtime/debug"
	"testing"

	"duckynetworkclient/V1/backoff"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/sessionmgr"
)

// Les formes de 02_07 qu'un poste peut recevoir, d'un core à jour comme d'un
// core antérieur — TO-DO 159.
var formesDeRefus = []struct {
	nom, contenu  string
	compte, motif string
}{
	// Core antérieur à la 2.3 : neuf refus sur onze n'avaient qu'UNE ligne.
	{"ancien, identifiants", "Wrong login Data", "", "Wrong login Data"},
	{"ancien, non authentifie", "You are not authentificate", "", "You are not authentificate"},
	{"ancien, mot de passe expire", "Password expired, change it on the web interface", "",
		"Password expired, change it on the web interface"},
	{"ancien, defi impossible", "Auth Failed please retry", "", "Auth Failed please retry"},
	// Core antérieur : les deux refus bien formés.
	{"ancien, machine interdite", "bob\nyou have not the authorisation for acces to this computeur", "bob",
		"you have not the authorisation for acces to this computeur"},
	// Core antérieur : le refus sans ligne de destination. Le SDK y lit la clé
	// comme destination, le compte comme clé, et il ne reste que le motif.
	{"ancien, sans destination", "Something go wrong contact you administrator", "",
		"Something go wrong contact you administrator"},
	// Core à jour : toujours le compte, puis le motif.
	{"a jour", "alice\nWrong login Data", "alice", "Wrong login Data"},
	{"a jour, compte inconnu", "-\nYou are not authentificate", "", "You are not authentificate"},
	// Bords.
	{"vide", "", "", MotifNonPrecise},
	{"blancs", " \n\t\n", "", MotifNonPrecise},
	{"retours chariot", "alice\r\nWrong login Data\r\n", "alice", "Wrong login Data"},
	{"trois lignes", "alice\nligne un\nligne deux", "alice", "ligne un ligne deux"},
	{"ligne vide en tete", "\nWrong login Data", "", "Wrong login Data"},
}

func TestLireRefusQuelleQueSoitLaForme(t *testing.T) {
	for _, c := range formesDeRefus {
		compte, motif := LireRefus(c.contenu)
		if compte != c.compte || motif != c.motif {
			t.Errorf("%s : LireRefus(%q) = (%q, %q), attendu (%q, %q)",
				c.nom, c.contenu, compte, motif, c.compte, c.motif)
		}
		if motif == "" {
			t.Errorf("%s : le motif est vide — le journal dirait « refusé : » sans rien", c.nom)
		}
	}
}

// sansRegistre remplace l'accès au registre des sessions, qui est global.
func sansRegistre(t *testing.T, statut sessionmgr.SessionStatus, connue bool) *[]string {
	t.Helper()
	avantStatut, avantMarque := statutDe, marquerEnEchec
	marquees := &[]string{}
	statutDe = func(string) (sessionmgr.SessionStatus, bool) { return statut, connue }
	marquerEnEchec = func(id string) { *marquees = append(*marquees, id) }
	t.Cleanup(func() { statutDe, marquerEnEchec = avantStatut, avantMarque })
	return marquees
}

// LE DÉFAUT : une 02_07 à une seule ligne faisait sortir du tableau, et c'est
// la panique qui fermait la connexion.
func TestUnRefusNeFaitPlusPaniquer(t *testing.T) {
	sansRegistre(t, sessionmgr.SessionPending, true)
	for _, c := range formesDeRefus {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s : PANIQUE en lisant le refus : %v\n%s", c.nom, r, debug.Stack())
				}
			}()
			ds := &storage.DuckySession{SessionID: "s"}
			reponse := User_Auth_Manager(storage.Trames_struct_client{
				Message_Order: []string{"02", "07"}, Content: c.contenu,
			}, ds)
			if reponse != "" {
				t.Errorf("%s : un refus ne se répond pas, réponse %q", c.nom, reponse)
			}
			if ds.Refus != c.motif {
				t.Errorf("%s : motif retenu %q, attendu %q", c.nom, ds.Refus, c.motif)
			}
		}()
	}
}

// Le refus FERME la session qu'il refuse : c'est le motif posé sur la session
// qui arrête la boucle de réception (tramesmanager.MessageReader).
func TestLeRefusMarqueLaSessionQuIlRefuse(t *testing.T) {
	for _, cas := range []struct {
		nom    string
		statut sessionmgr.SessionStatus
		connue bool
	}{
		{"en attente", sessionmgr.SessionPending, true},
		{"deja en echec", sessionmgr.SessionFailed, true},
		{"absente du registre", sessionmgr.SessionPending, false},
	} {
		marquees := sansRegistre(t, cas.statut, cas.connue)
		ds := &storage.DuckySession{SessionID: "s-1"}
		if !traiterRefus("alice\nWrong login Data", ds) {
			t.Errorf("%s : la session refusée n'est pas marquée", cas.nom)
		}
		if ds.Refus != "Wrong login Data" {
			t.Errorf("%s : motif %q", cas.nom, ds.Refus)
		}
		if len(*marquees) != 1 || (*marquees)[0] != "s-1" {
			t.Errorf("%s : le registre n'apprend pas l'échec : %v", cas.nom, *marquees)
		}
	}
}

// Un core antérieur émet un 02_07 DANS le tunnel d'une machine, sur une
// demande d'ouverture de session malformée. Fermer ce tunnel pour cela
// couperait la machine du core.
func TestUnRefusNeFermePasUnTunnelAuthentifie(t *testing.T) {
	marquees := sansRegistre(t, sessionmgr.SessionAuthenticated, true)
	ds := &storage.DuckySession{SessionID: "tunnel"}
	if traiterRefus("vaultaire\ninvalid request", ds) {
		t.Error("un tunnel authentifié a été marqué refusé")
	}
	if ds.Refus != "" {
		t.Errorf("le tunnel porte un motif de refus (%q) : la boucle de réception le fermerait", ds.Refus)
	}
	if len(*marquees) != 0 {
		t.Errorf("le tunnel a été passé en échec dans le registre : %v", *marquees)
	}
}

func TestUnRefusSansSessionNePaniquePas(t *testing.T) {
	sansRegistre(t, sessionmgr.SessionPending, true)
	if traiterRefus("Wrong login Data", nil) {
		t.Error("rien à marquer sans session")
	}
}

// Même défaut, autre trame : l'acceptation lisait lines[1] sans vérifier.
func TestUneAcceptationIncompleteNePaniquePas(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIQUE en lisant une 02_04 d'une ligne : %v\n%s", r, debug.Stack())
		}
	}()
	for _, contenu := range []string{"", "alice"} {
		reponse := User_Auth_Manager(storage.Trames_struct_client{
			Message_Order: []string{"02", "04"}, Content: contenu,
		}, &storage.DuckySession{SessionID: "s"})
		if reponse != "" {
			t.Errorf("une acceptation illisible (%q) a déclenché l'inventaire : %q", contenu, reponse)
		}
	}
}

// Après un refus, le délai de reprise continue de grandir ; après une session
// qui a vécu, il repart du plus court.
func TestLeDelaiDeRepriseNeRepartPasDeZeroApresUnRefus(t *testing.T) {
	plafondDuPremier := backoff.DelaiInitial + backoff.DelaiInitial*backoff.DispersionMax/100

	attente := backoff.New()
	refusee := &storage.DuckySession{Refus: "Wrong login Data"}
	var dernier int64
	for i := 0; i < 6; i++ {
		d, refus := DelaiDeReprise(attente, refusee)
		if !refus {
			t.Fatal("la session refusée n'est pas reconnue")
		}
		dernier = int64(d)
	}
	if dernier <= int64(plafondDuPremier) {
		t.Errorf("après six refus le délai vaut %d ns : il est reparti du plus court (%s au plus)",
			dernier, plafondDuPremier)
	}

	// Une session qui n'a pas été refusée remet le compteur à zéro.
	d, refus := DelaiDeReprise(attente, &storage.DuckySession{})
	if refus {
		t.Error("une session ordinaire est prise pour un refus")
	}
	if d > plafondDuPremier {
		t.Errorf("après une session ordinaire le délai vaut %s, attendu %s au plus", d, plafondDuPremier)
	}
	if _, refus := DelaiDeReprise(attente, nil); refus {
		t.Error("une session absente est prise pour un refus")
	}
}
