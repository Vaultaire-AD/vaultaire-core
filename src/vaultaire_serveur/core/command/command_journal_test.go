package command

import (
	"strings"
	"testing"
)

// Le journal des commandes, et son caviardage.
//
// # Ce qui manquait
//
// Rien ne traçait la commande exécutée. Les ACTIONS journalisent leurs
// écritures, mais les lectures sont volontairement muettes : lancer « get -u »
// ou « eyes -g » depuis la console d'administration web ne laissait aucune
// trace, ni de la commande, ni de son auteur.
//
// Pour cette façade en particulier, c'est une lacune : la console exécute des
// commandes arbitraires et se trouve derrière `web_admin`, à travers le réseau.
// Le socket local, lui, suppose déjà un accès root à la machine.
//
// # Ce que ces tests gardent
//
// Le caviardage. Journaliser la ligne telle quelle écrirait des mots de passe en
// clair dans un fichier conservé, recopié, et souvent lisible par plus de monde
// que la base — on aurait remplacé une absence de trace par une fuite.
//
// L'échec de cette fonction est SILENCIEUX : un secret non masqué ne se
// découvre que plus tard, en lisant le journal. D'où des tests qui nomment les
// deux commandes concernées et vérifient les deux sens — ce qui doit être
// masqué, et ce qui ne doit pas l'être.

func TestMotDePasseDeCreationCaviarde(t *testing.T) {
	got := CommandePourJournal("create -u alice paris.fr S3cr3t! 01/01/1990 Alice Martin")

	if strings.Contains(got, "S3cr3t!") {
		t.Fatalf("journal = %q : le mot de passe y figure en clair", got)
	}
	// Le reste doit rester lisible : un journal qui masque tout ne sert plus à
	// rien, et c'est le nom du compte qu'on cherchera.
	for _, attendu := range []string{"create", "-u", "alice", "paris.fr", "01/01/1990"} {
		if !strings.Contains(got, attendu) {
			t.Errorf("journal = %q : %q a été masqué sans raison", got, attendu)
		}
	}
}

// TestMotDePasseDeChangementCaviardeEnEntier.
//
// Le mot de passe occupe TOUS les arguments restants — la commande les rejoint
// pour qu'un mot de passe contenant des espaces ne soit pas tronqué au premier.
// Le caviardage doit donc couvrir la queue entière.
func TestMotDePasseDeChangementCaviardeEnEntier(t *testing.T) {
	got := CommandePourJournal("update -u alice -p mon mot de passe long")

	for _, secret := range []string{"mon", "mot", "passe", "long"} {
		if strings.Contains(got, secret) {
			t.Fatalf("journal = %q : le fragment %q du mot de passe y figure", got, secret)
		}
	}
	if !strings.Contains(got, "update -u alice -p") {
		t.Errorf("journal = %q : la commande n'est plus identifiable", got)
	}
}

// TestLaQueueCaviardeeNeComptePasLesMots.
//
// « *** *** *** » dirait combien de mots compte le mot de passe. C'est une
// indication qu'on n'a aucune raison d'écrire, et qui rétrécit la recherche pour
// qui lira le journal.
func TestLaQueueCaviardeeNeComptePasLesMots(t *testing.T) {
	got := CommandePourJournal("update -u alice -p un mot de passe de six mots")

	if n := strings.Count(got, "***"); n != 1 {
		t.Errorf("journal = %q : %d marqueurs, attendu 1 — le nombre de mots du "+
			"mot de passe est déduisible", got, n)
	}
}

// TestCommandesSansSecretIntactes.
//
// Le caviardage ne doit pas déborder. Masquer un argument utile priverait le
// journal de ce qu'on y cherche, et le défaut ne se verrait qu'au moment d'un
// diagnostic — c'est-à-dire trop tard.
func TestCommandesSansSecretIntactes(t *testing.T) {
	cas := []string{
		"get -u",
		"get -p -u lecture",
		"create -g equipe paris.fr",
		"create -p lecture non --desc \"consultation\"",
		"add -u alice -g equipe",
		"add -u alice -k portable ssh-ed25519 AAAAC3Nz",
		"update -u alice -g equipe", // pas de -p : rien à masquer
		"update -pu lecture read:get:user all",
		"update -debug true",
		"delete -u alice",
		"eyes -g",
	}
	for _, c := range cas {
		t.Run(c, func(t *testing.T) {
			if got := CommandePourJournal(c); got != c {
				t.Errorf("journal = %q, attendu %q inchangé", got, c)
			}
		})
	}
}

// TestCommandeTronqueeNestPasCaviardee.
//
// « update -u alice » sans « -p » n'a pas de mot de passe. Le caviarder quand
// même priverait le journal de ce qui a réellement été tapé de travers — or
// c'est précisément la commande mal formée qu'on voudra relire.
func TestCommandeTronqueeNestPasCaviardee(t *testing.T) {
	for _, c := range []string{"update -u alice", "update -u", "update", "create -u alice paris.fr"} {
		if got := CommandePourJournal(c); got != c {
			t.Errorf("CommandePourJournal(%q) = %q, attendu inchangé", c, got)
		}
	}
}

func TestCommandeVide(t *testing.T) {
	for _, c := range []string{"", "   ", "\t\n"} {
		if got := CommandePourJournal(c); got != "" {
			t.Errorf("CommandePourJournal(%q) = %q, attendue vide", c, got)
		}
	}
}

// TestCaviardageInsensibleALaCasse.
//
// Les commandes sont dispatchées sur une comparaison exacte, mais rien
// n'empêche un script de les écrire autrement, et un caviardage qui ne
// s'appliquerait qu'à la forme minuscule laisserait passer le secret sans que
// personne s'en aperçoive.
func TestCaviardageInsensibleALaCasse(t *testing.T) {
	got := CommandePourJournal("CREATE -U alice paris.fr S3cr3t 01/01/1990")
	if strings.Contains(got, "S3cr3t") {
		t.Errorf("journal = %q : le mot de passe échappe au caviardage en majuscules", got)
	}
}
